//! JWT validator + seat-cap gate.
//!
//! The two public entry points:
//!
//!   * [`validate_jwt`]: RS256 + issuer + algorithm checks; returns a
//!     structured [`ValidationResult`] with an [`ExpiryStatus`] enum so
//!     the caller can implement the 30-day grace policy.
//!   * [`check_seats_available`]: hard cap on **new** sessions.
//!
//! Neither function makes a policy decision on the caller's behalf:
//! enforcement (refuse-new-session, log-warning, surface-banner) lives in
//! the caller. This library only returns the verdict.

use chrono::Utc;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

pub use crate::claims::{LicenseClaims, LicenseFeatures, ISSUER};

/// Grace window after `exp` during which the validator surfaces
/// [`ExpiryStatus::InGrace`] instead of [`ExpiryStatus::HardCutoff`].
///
/// Fixed at 30 days. Changing it changes how every deployed license
/// behaves after `exp`, so treat it as part of the license contract.
pub const EXPIRY_GRACE_DAYS: i64 = 30;

const SECONDS_PER_DAY: i64 = 86_400;

/// Structured verdict returned by [`validate_jwt`].
///
/// Designed so the caller can branch cleanly on whether the token is
/// usable at all, whether to surface the in-grace banner, and whether to
/// refuse new sessions (hard cutoff) without re-parsing the JWT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationResult {
    /// `true` iff the JWT signature + algorithm + issuer all passed.
    /// `false` here means the token is structurally invalid or forged:
    /// `claims` and `expiry_status` will both be `None` / `Invalid`.
    pub valid_signature: bool,
    /// Parsed claims if (and only if) `valid_signature == true`.
    pub claims: Option<LicenseClaims>,
    /// Expiry verdict. See [`ExpiryStatus`] for the three cases.
    pub expiry_status: ExpiryStatus,
    /// Human-readable error if validation failed. Suitable for logging.
    /// Never contains the JWT itself.
    pub error: Option<String>,
}

/// Three-state expiry verdict.
///
/// The caller is expected to:
///   * `Valid`: admit new sessions, no banner.
///   * `InGrace(d)`: admit new sessions, log a warning, surface a
///     banner that includes `d` days into grace (or `EXPIRY_GRACE_DAYS - d`
///     days remaining).
///   * `HardCutoff`: refuse new sessions. Active sessions continue.
///   * `Perpetual`: identical handling to `Valid`. Admit new sessions,
///     no banner. Never reachable from `exp`, only from the signed
///     `perpetual` claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryStatus {
    /// `exp` is in the future. Token fully valid.
    Valid,
    /// `exp` is in the past but within [`EXPIRY_GRACE_DAYS`]. The `i64`
    /// is the number of whole days *into* the grace period (0 = expired
    /// today, `EXPIRY_GRACE_DAYS` = last day of grace).
    InGrace(i64),
    /// `exp + EXPIRY_GRACE_DAYS` is in the past. New sessions must be
    /// refused.
    HardCutoff,
    /// The token carries `perpetual: true`. It NEVER expires, so `exp` is
    /// ignored entirely and this state can never become [`Self::InGrace`]
    /// or [`Self::HardCutoff`]. Callers must treat it exactly like
    /// [`Self::Valid`]: admit new sessions, no banner, no warning.
    ///
    /// This is the perpetual fallback licence. See
    /// [`crate::LicenseClaims::perpetual`] for why it exists.
    Perpetual,
    /// Token signature / structure was invalid; expiry is moot.
    Invalid,
}

/// Seat-admission verdict for **new** sessions.
///
/// `Available { remaining }` returns the number of seats still free *after*
/// the caller seats the incoming session, useful for surfacing
/// "3 seats remaining" banners.
///
/// `AtCap` returns the seat cap so the caller can surface it in the
/// "seats exceeded, contact your admin" error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeatCheck {
    /// New session may be admitted. `remaining` is the count of free
    /// seats *after* this admission. Will be `0` for the last seat.
    Available { remaining: u64 },
    /// Hard cap reached. `seats` is the contracted cap from the JWT.
    AtCap { seats: u32 },
    /// Unlimited-seats license (`claims.seats == 0`). Legacy tokens.
    Unlimited,
}

/// Validate a Bolt license JWT.
///
/// Returns a [`ValidationResult`] regardless of outcome: callers should
/// branch on `valid_signature` and `expiry_status` rather than expecting
/// a `Result`.
///
/// Notes:
///   * Algorithm pinned to RS256 (defends against `alg=none` and HS256
///     key-confusion attacks).
///   * Issuer pinned to [`ISSUER`].
///   * `validate_exp` is **off** internally: expiry is surfaced via
///     [`ExpiryStatus`] so the 30-day grace logic stays in this crate.
///   * A token with `perpetual: true` short-circuits expiry entirely and
///     returns [`ExpiryStatus::Perpetual`]. `exp` is not consulted.
///   * `validate_aud` is off: the `aud` field carries the tier slug, not
///     an audience identifier.
///   * Surrounding whitespace on the token is trimmed (matches CLI
///     behavior; tokens copy-pasted from email survive).
pub fn validate_jwt(token: &str, public_key_pem: &str) -> ValidationResult {
    let decoding_key = match DecodingKey::from_rsa_pem(public_key_pem.as_bytes()) {
        Ok(k) => k,
        Err(e) => {
            return ValidationResult {
                valid_signature: false,
                claims: None,
                expiry_status: ExpiryStatus::Invalid,
                error: Some(format!("public key parse failed: {e}")),
            };
        }
    };

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[ISSUER]);
    // Surface expiry via ExpiryStatus instead of rejecting outright.
    validation.validate_exp = false;
    // `aud` carries tier, not audience.
    validation.validate_aud = false;

    match decode::<LicenseClaims>(token.trim(), &decoding_key, &validation) {
        Ok(data) => {
            let claims = data.claims;
            // A perpetual token ignores `exp` outright: the whole point is
            // that no clock can take the deployment away from the customer.
            let expiry_status = if claims.perpetual {
                ExpiryStatus::Perpetual
            } else {
                compute_expiry_status(claims.exp, Utc::now().timestamp())
            };
            ValidationResult {
                valid_signature: true,
                claims: Some(claims),
                expiry_status,
                error: None,
            }
        }
        Err(e) => ValidationResult {
            valid_signature: false,
            claims: None,
            expiry_status: ExpiryStatus::Invalid,
            error: Some(e.to_string()),
        },
    }
}

/// Compute [`ExpiryStatus`] from an `exp` timestamp and a "now". Split
/// out so unit tests can pin `now` deterministically.
fn compute_expiry_status(exp: i64, now: i64) -> ExpiryStatus {
    if exp > now {
        ExpiryStatus::Valid
    } else {
        let days_past = (now - exp) / SECONDS_PER_DAY;
        if days_past <= EXPIRY_GRACE_DAYS {
            ExpiryStatus::InGrace(days_past)
        } else {
            ExpiryStatus::HardCutoff
        }
    }
}

/// Hard cap on new sessions.
///
/// Returns:
///   * [`SeatCheck::Unlimited`] if `claims.seats == 0` (legacy unbounded
///     tokens).
///   * [`SeatCheck::AtCap`] if `active_session_count >= claims.seats`.
///     Includes the contracted seat count for the user-facing error.
///     Clamps cleanly when `active_session_count > seats` (which can
///     happen briefly during a contract downgrade).
///   * [`SeatCheck::Available { remaining }`] otherwise. `remaining` is
///     `seats - active_session_count - 1` (i.e. after seating the
///     incoming session). For the *last* available seat `remaining = 0`.
///
/// The caller is responsible for guarding *new* admissions only; active
/// sessions are never kicked.
pub fn check_seats_available(claims: &LicenseClaims, active_session_count: u64) -> SeatCheck {
    if claims.seats == 0 {
        return SeatCheck::Unlimited;
    }
    let seats = claims.seats as u64;
    if active_session_count >= seats {
        SeatCheck::AtCap { seats: claims.seats }
    } else {
        // Subtract one for the incoming session being admitted. Saturating
        // sub guards against arithmetic underflow for the last seat.
        let remaining = seats.saturating_sub(active_session_count).saturating_sub(1);
        SeatCheck::Available { remaining }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::LicenseFeatures;

    // ---- Test helpers ---------------------------------------------------

    /// Generate a fresh in-memory RSA keypair (PKCS#8 PEM).
    fn fresh_keypair() -> (String, String) {
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
        use rsa::{RsaPrivateKey, RsaPublicKey};

        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        let pub_key = RsaPublicKey::from(&priv_key);
        let priv_pem = priv_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("priv pem")
            .to_string();
        let pub_pem = pub_key
            .to_public_key_pem(LineEnding::LF)
            .expect("pub pem");
        (priv_pem, pub_pem)
    }

    fn make_claims(exp_offset_secs: i64, seats: u32) -> LicenseClaims {
        let now = Utc::now().timestamp();
        LicenseClaims {
            sub: "bolt-license".to_string(),
            iss: ISSUER.to_string(),
            aud: "enterprise".to_string(),
            exp: now + exp_offset_secs,
            iat: now,
            jti: uuid::Uuid::new_v4().to_string(),
            org: "Acme Corp".to_string(),
            org_id: None,
            admin_email: "admin@acme.test".to_string(),
            seats,
            trial: false,
            features: LicenseFeatures::all(),
            tier: "enterprise".to_string(),
            notes: None,
            perpetual: false,
            // A Bolt-only licence carries no Aeira entitlement block. Spelled
            // out rather than defaulted so that adding a future entitlement
            // field breaks this constructor and forces a decision about what a
            // Bolt token should say about it, instead of silently inheriting
            // whatever `Default` happens to mean that week.
            product: None,
            instance_id: None,
            max_instances: None,
            max_records: None,
            aeira_features: None,
            rate_limit: None,
        }
    }

    /// A perpetual fallback licence with an `exp` the caller chooses, so a
    /// test can prove the flag beats the clock in both directions.
    fn make_perpetual_claims(exp_offset_secs: i64) -> LicenseClaims {
        LicenseClaims {
            perpetual: true,
            ..make_claims(exp_offset_secs, 10)
        }
    }

    fn sign(claims: &LicenseClaims, private_pem: &str) -> String {
        use jsonwebtoken::{encode, EncodingKey, Header};
        let key = EncodingKey::from_rsa_pem(private_pem.as_bytes()).expect("priv key");
        encode(&Header::new(Algorithm::RS256), claims, &key).expect("encode")
    }

    // ---- validate_jwt: expiry semantics --------------------------------

    #[test]
    fn validate_jwt_valid_sig_valid_exp_returns_valid() {
        let (priv_pem, pub_pem) = fresh_keypair();
        let token = sign(&make_claims(86_400, 10), &priv_pem); // exp in 1d
        let r = validate_jwt(&token, &pub_pem);
        assert!(r.valid_signature, "signature must be valid");
        assert_eq!(r.expiry_status, ExpiryStatus::Valid);
        assert!(r.error.is_none());
        let claims = r.claims.expect("claims present");
        assert_eq!(claims.org, "Acme Corp");
        assert_eq!(claims.seats, 10);
    }

    #[test]
    fn validate_jwt_valid_sig_exp_10_days_ago_returns_in_grace_10() {
        let (priv_pem, pub_pem) = fresh_keypair();
        // exp = 10 days ago, exactly. Use 10 days + 1 hour to be safely
        // past the day boundary regardless of test runtime jitter.
        let exp_offset = -(10 * SECONDS_PER_DAY + 3600);
        let token = sign(&make_claims(exp_offset, 10), &priv_pem);
        let r = validate_jwt(&token, &pub_pem);
        assert!(r.valid_signature);
        match r.expiry_status {
            ExpiryStatus::InGrace(days) => assert_eq!(days, 10, "expected 10 days into grace"),
            other => panic!("expected InGrace(10), got {:?}", other),
        }
    }

    #[test]
    fn validate_jwt_valid_sig_exp_40_days_ago_returns_hard_cutoff() {
        let (priv_pem, pub_pem) = fresh_keypair();
        let exp_offset = -(40 * SECONDS_PER_DAY);
        let token = sign(&make_claims(exp_offset, 10), &priv_pem);
        let r = validate_jwt(&token, &pub_pem);
        assert!(r.valid_signature);
        assert_eq!(r.expiry_status, ExpiryStatus::HardCutoff);
    }

    #[test]
    fn validate_jwt_exactly_at_grace_boundary_still_in_grace() {
        // exp = exactly EXPIRY_GRACE_DAYS ago. Boundary should be inclusive
        // (i.e. still in grace, not hard cutoff).
        let (priv_pem, pub_pem) = fresh_keypair();
        // Use full days minus a sliver so floor-div rounds to exactly
        // EXPIRY_GRACE_DAYS even with sub-second jitter.
        let exp_offset = -(EXPIRY_GRACE_DAYS * SECONDS_PER_DAY) + 30;
        let token = sign(&make_claims(exp_offset, 10), &priv_pem);
        let r = validate_jwt(&token, &pub_pem);
        match r.expiry_status {
            ExpiryStatus::InGrace(days) => {
                assert!(
                    days == EXPIRY_GRACE_DAYS - 1 || days == EXPIRY_GRACE_DAYS,
                    "expected last day of grace, got InGrace({days})"
                );
            }
            other => panic!("expected InGrace at boundary, got {:?}", other),
        }
    }

    #[test]
    fn validate_jwt_one_day_past_grace_boundary_is_hard_cutoff() {
        let (priv_pem, pub_pem) = fresh_keypair();
        let exp_offset = -((EXPIRY_GRACE_DAYS + 1) * SECONDS_PER_DAY + 3600);
        let token = sign(&make_claims(exp_offset, 10), &priv_pem);
        let r = validate_jwt(&token, &pub_pem);
        assert_eq!(r.expiry_status, ExpiryStatus::HardCutoff);
    }

    // ---- validate_jwt: signature / structural rejections ---------------

    #[test]
    fn validate_jwt_bad_signature_returns_invalid_signature() {
        let (priv_pem, pub_pem) = fresh_keypair();
        let token = sign(&make_claims(86_400, 10), &priv_pem);
        let mut parts: Vec<String> = token.split('.').map(|s| s.to_string()).collect();
        // Flip the last char of the signature segment.
        let sig = &mut parts[2];
        let last = sig.pop().unwrap_or('A');
        sig.push(if last == 'A' { 'B' } else { 'A' });
        let tampered = parts.join(".");

        let r = validate_jwt(&tampered, &pub_pem);
        assert!(!r.valid_signature);
        assert!(r.claims.is_none());
        assert_eq!(r.expiry_status, ExpiryStatus::Invalid);
        assert!(r.error.is_some());
    }

    #[test]
    fn validate_jwt_wrong_public_key_rejected() {
        let (priv_a, _pub_a) = fresh_keypair();
        let (_priv_b, pub_b) = fresh_keypair();
        let token = sign(&make_claims(86_400, 10), &priv_a);
        let r = validate_jwt(&token, &pub_b);
        assert!(!r.valid_signature);
        assert_eq!(r.expiry_status, ExpiryStatus::Invalid);
    }

    #[test]
    fn validate_jwt_alg_none_rejected() {
        use base64::Engine;
        let (_priv, pub_pem) = fresh_keypair();
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::to_string(&make_claims(86_400, 10))
                .unwrap()
                .as_bytes(),
        );
        let alg_none = format!("{}.{}.", header_b64, payload_b64);
        let r = validate_jwt(&alg_none, &pub_pem);
        assert!(!r.valid_signature, "alg=none must be rejected");
    }

    #[test]
    fn validate_jwt_hs256_under_rs256_rejected() {
        use jsonwebtoken::{encode, EncodingKey, Header};
        let (_priv, pub_pem) = fresh_keypair();
        let claims = make_claims(86_400, 10);
        let hs_key = EncodingKey::from_secret(pub_pem.as_bytes());
        let hs_token = encode(&Header::new(Algorithm::HS256), &claims, &hs_key).expect("hs256");
        let r = validate_jwt(&hs_token, &pub_pem);
        assert!(!r.valid_signature, "HS256 must not validate under RS256");
    }

    #[test]
    fn validate_jwt_wrong_issuer_rejected() {
        let (priv_pem, pub_pem) = fresh_keypair();
        let mut claims = make_claims(86_400, 10);
        claims.iss = "evil.example.com".to_string();
        let token = sign(&claims, &priv_pem);
        let r = validate_jwt(&token, &pub_pem);
        assert!(!r.valid_signature, "wrong issuer must be rejected");
    }

    #[test]
    fn validate_jwt_malformed_token_rejected() {
        let (_priv, pub_pem) = fresh_keypair();
        for malformed in [
            "",
            "not-a-jwt",
            "only.two",
            "four.dots.in.token",
            "header.payload.",
            ".payload.signature",
        ] {
            let r = validate_jwt(malformed, &pub_pem);
            assert!(
                !r.valid_signature,
                "malformed token {:?} must be rejected",
                malformed
            );
            assert_eq!(r.expiry_status, ExpiryStatus::Invalid);
        }
    }

    #[test]
    fn validate_jwt_bad_public_key_pem_rejected() {
        let r = validate_jwt("anything.at.all", "not a pem");
        assert!(!r.valid_signature);
        assert!(r
            .error
            .as_deref()
            .unwrap_or("")
            .contains("public key parse failed"));
    }

    #[test]
    fn validate_jwt_whitespace_around_token_tolerated() {
        let (priv_pem, pub_pem) = fresh_keypair();
        let token = sign(&make_claims(86_400, 10), &priv_pem);
        let padded = format!("\n  {}\t \n", token);
        let r = validate_jwt(&padded, &pub_pem);
        assert!(r.valid_signature, "trimmed token must verify");
    }

    // ---- check_seats_available -----------------------------------------

    #[test]
    fn check_seats_active_lt_seats_returns_available() {
        let c = make_claims(86_400, 10);
        match check_seats_available(&c, 3) {
            SeatCheck::Available { remaining } => {
                // 10 seats, 3 active, admit 1 more → 10 - 3 - 1 = 6 remaining
                assert_eq!(remaining, 6);
            }
            other => panic!("expected Available, got {:?}", other),
        }
    }

    #[test]
    fn check_seats_last_seat_returns_available_remaining_zero() {
        let c = make_claims(86_400, 10);
        match check_seats_available(&c, 9) {
            SeatCheck::Available { remaining } => assert_eq!(remaining, 0),
            other => panic!("expected Available {{ remaining: 0 }}, got {:?}", other),
        }
    }

    #[test]
    fn check_seats_active_eq_seats_returns_at_cap() {
        let c = make_claims(86_400, 10);
        match check_seats_available(&c, 10) {
            SeatCheck::AtCap { seats } => assert_eq!(seats, 10),
            other => panic!("expected AtCap, got {:?}", other),
        }
    }

    #[test]
    fn check_seats_active_gt_seats_clamps_to_at_cap() {
        // After a contract downgrade we can briefly have active > seats.
        // Must still refuse new admissions; never panic.
        let c = make_claims(86_400, 10);
        match check_seats_available(&c, 12) {
            SeatCheck::AtCap { seats } => assert_eq!(seats, 10),
            other => panic!("expected AtCap (clamp), got {:?}", other),
        }
    }

    #[test]
    fn check_seats_zero_seats_returns_unlimited() {
        // Legacy unbounded-seats tokens (`seats: 0`).
        let c = make_claims(86_400, 0);
        assert_eq!(check_seats_available(&c, 999_999), SeatCheck::Unlimited);
        assert_eq!(check_seats_available(&c, 0), SeatCheck::Unlimited);
    }

    // ---- compute_expiry_status (deterministic, pinned now) -------------

    #[test]
    fn compute_expiry_future_exp_is_valid() {
        assert_eq!(compute_expiry_status(1_000_000, 999_999), ExpiryStatus::Valid);
    }

    #[test]
    fn compute_expiry_exp_today_is_in_grace_zero() {
        // exp = now exactly. (now - exp) / 86400 = 0 days into grace.
        assert_eq!(
            compute_expiry_status(1_000_000, 1_000_000),
            ExpiryStatus::InGrace(0)
        );
    }

    #[test]
    fn compute_expiry_30_days_past_is_in_grace_30() {
        let now = 1_000_000;
        let exp = now - 30 * SECONDS_PER_DAY;
        assert_eq!(compute_expiry_status(exp, now), ExpiryStatus::InGrace(30));
    }

    #[test]
    fn compute_expiry_31_days_past_is_hard_cutoff() {
        let now = 1_000_000;
        let exp = now - 31 * SECONDS_PER_DAY;
        assert_eq!(compute_expiry_status(exp, now), ExpiryStatus::HardCutoff);
    }

    // ---- perpetual fallback licence ------------------------------------
    //
    // These pin the CONTRACTUAL guarantee, not an implementation detail:
    // a customer holding a perpetual token can never be cut off, whatever
    // the clock says and whether or not anyone is left to reissue it.

    #[test]
    fn perpetual_token_forty_days_past_exp_is_perpetual_not_hard_cutoff() {
        let (priv_pem, pub_pem) = fresh_keypair();
        // The same offset that makes an ordinary token HardCutoff above.
        let token = sign(&make_perpetual_claims(-40 * SECONDS_PER_DAY), &priv_pem);
        let r = validate_jwt(&token, &pub_pem);
        assert!(r.valid_signature, "signature must be valid");
        assert_eq!(
            r.expiry_status,
            ExpiryStatus::Perpetual,
            "a perpetual licence 40 days past exp must NOT be cut off"
        );
        assert_ne!(r.expiry_status, ExpiryStatus::HardCutoff);
    }

    #[test]
    fn perpetual_token_ten_years_past_exp_is_still_perpetual() {
        let (priv_pem, pub_pem) = fresh_keypair();
        let token = sign(&make_perpetual_claims(-3650 * SECONDS_PER_DAY), &priv_pem);
        let r = validate_jwt(&token, &pub_pem);
        assert_eq!(r.expiry_status, ExpiryStatus::Perpetual);
        assert_eq!(
            r.claims.expect("claims present").perpetual,
            true,
            "the perpetual claim must survive the round trip"
        );
    }

    #[test]
    fn perpetual_token_with_future_exp_reports_perpetual_not_valid() {
        // The caller must be able to tell a perpetual licence from an
        // ordinary in-date one, so the banner and the renewal notice can
        // both stay silent forever rather than firing at `exp`.
        let (priv_pem, pub_pem) = fresh_keypair();
        let token = sign(&make_perpetual_claims(86_400), &priv_pem);
        let r = validate_jwt(&token, &pub_pem);
        assert_eq!(r.expiry_status, ExpiryStatus::Perpetual);
        assert_ne!(r.expiry_status, ExpiryStatus::Valid);
    }

    #[test]
    fn ordinary_token_is_unaffected_by_the_perpetual_path() {
        // Positive control for the two tests above: the SAME helper with
        // the flag off must still reach HardCutoff, so a green perpetual
        // test cannot come from expiry being broken generally.
        let (priv_pem, pub_pem) = fresh_keypair();
        let token = sign(&make_claims(-40 * SECONDS_PER_DAY, 10), &priv_pem);
        let r = validate_jwt(&token, &pub_pem);
        assert_eq!(r.expiry_status, ExpiryStatus::HardCutoff);
    }

    #[test]
    fn token_issued_before_the_field_existed_deserialises_as_not_perpetual() {
        // Token stability: every JWT already in a customer's hands was
        // minted without a `perpetual` claim. Absent on the wire must mean
        // `false`, never a deserialisation failure and never `true`.
        let json = serde_json::json!({
            "sub": "bolt-license",
            "iss": ISSUER,
            "aud": "enterprise",
            "exp": 1_000_000_i64,
            "iat": 900_000_i64,
            "jti": "11111111-1111-4111-8111-111111111111",
            "org": "Legacy Corp",
            "admin_email": "admin@legacy.test",
            "seats": 10,
            "trial": false,
            "tier": "enterprise"
        });
        let claims: LicenseClaims =
            serde_json::from_value(json).expect("a pre-existing token must still deserialise");
        assert_eq!(
            claims.perpetual, false,
            "an absent perpetual claim must never grant a perpetual licence"
        );
    }

    #[test]
    fn compute_expiry_status_is_never_asked_about_perpetual_tokens() {
        // compute_expiry_status has no knowledge of the flag by design:
        // the short circuit lives in validate_jwt. This pins that the
        // clock function itself is unchanged, so the only way to reach
        // Perpetual is a signed claim.
        let now = 1_000_000;
        let exp = now - 31 * SECONDS_PER_DAY;
        assert_eq!(compute_expiry_status(exp, now), ExpiryStatus::HardCutoff);
    }
}
