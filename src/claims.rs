//! License JWT claims.
//!
//! The field names are part of the token format. Tokens already issued must
//! keep validating, so optional fields use `#[serde(default)]` and missing
//! fields fall back to safe values (no features, 0 seats, and so on).

use serde::{Deserialize, Serialize};

/// Issuer string carried by every Bolt license token and pinned at
/// validation time.
pub const ISSUER: &str = "bolt.sparcle.app";

/// Per-feature flags. All default to `false`.
///
/// Kept as named fields (rather than a set of strings) so a typo in the
/// caller is a compile error.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct LicenseFeatures {
    #[serde(default)]
    pub agent: bool,
    #[serde(default)]
    pub mcp: bool,
    #[serde(default)]
    pub plugins: bool,
    #[serde(default)]
    pub skills: bool,
    #[serde(default)]
    pub directory: bool,
    #[serde(default)]
    pub analytics: bool,
    #[serde(default)]
    pub audit_export: bool,
    #[serde(default)]
    pub advanced_sso: bool,
    #[serde(default)]
    pub custom_branding: bool,
    #[serde(default)]
    pub priority_support: bool,
}

impl LicenseFeatures {
    /// Demo / trial profile: product features on, operations features off.
    pub fn demo() -> Self {
        Self {
            agent: true,
            mcp: true,
            plugins: true,
            skills: true,
            directory: true,
            analytics: true,
            audit_export: false,
            advanced_sso: false,
            custom_branding: false,
            priority_support: false,
        }
    }

    /// Every feature on.
    pub fn all() -> Self {
        Self {
            agent: true,
            mcp: true,
            plugins: true,
            skills: true,
            directory: true,
            analytics: true,
            audit_export: true,
            advanced_sso: true,
            custom_branding: true,
            priority_support: true,
        }
    }
}

/// JWT payload of a Bolt license.
///
/// Field names are part of the token format: renaming one would break every
/// token already issued. New fields must be added behind `#[serde(default)]`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LicenseClaims {
    /// Always `"bolt-license"`.
    pub sub: String,
    /// Always [`ISSUER`]. Pinned at validation time.
    pub iss: String,
    /// Carries the tier slug (`"demo"`, `"trial"`, `"team"`, `"enterprise"`).
    /// Audience validation is off in the validator, so this field is
    /// informational only.
    pub aud: String,
    /// Expiry timestamp (Unix seconds). A past `exp` is reported as
    /// [`crate::ExpiryStatus::InGrace`] or `HardCutoff` rather than rejected,
    /// so the caller can apply the grace period.
    pub exp: i64,
    /// Issued-at timestamp (Unix seconds).
    pub iat: i64,
    /// Unique license identifier (UUID v4).
    pub jti: String,
    /// Licensed organisation display name.
    pub org: String,
    /// Optional organisation identifier. Omitted from the wire when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    /// Admin contact email for the license.
    pub admin_email: String,
    /// Seat cap. `0` means unlimited. Any other value is a hard cap, see
    /// [`crate::check_seats_available`].
    #[serde(default)]
    pub seats: u32,
    /// Trial flag. Informational, kept for older tokens.
    #[serde(default)]
    pub trial: bool,
    /// Enabled feature flags.
    #[serde(default)]
    pub features: LicenseFeatures,
    /// Tier display string (mirrors `aud`).
    pub tier: String,
    /// Optional free-text notes. Omitted from the wire when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Perpetual license.
    ///
    /// When `true` the token never expires: the validator returns
    /// [`crate::ExpiryStatus::Perpetual`] whatever `exp` says, so the
    /// deployment can never reach [`crate::ExpiryStatus::HardCutoff`].
    ///
    /// The flag is inside the signed payload, so only the license issuer can
    /// set it. Absent on the wire means `false`, so older tokens are
    /// unaffected.
    #[serde(default)]
    pub perpetual: bool,

    // -- Aeira entitlement block ------------------------------------------
    //
    // Read by Aeira's own validator. Every field is an `Option` that is
    // skipped when `None`, so a token that does not use them has exactly the
    // same wire format as one issued before these fields existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    /// Instance fingerprint this token is bound to. `None` = portable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_instances: Option<u32>,
    /// Total record ceiling. `None` = unlimited. `Some(0)` means read-only,
    /// so zero is meaningful, not absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_records: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aeira_features: Option<AeiraFeatures>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitClaim>,
}

/// Aeira capability flags. The field names and JSON shape must match Aeira's
/// reader exactly: a rename on either side silently reads as `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AeiraFeatures {
    #[serde(default)]
    pub kafka_enabled: bool,
    #[serde(default)]
    pub region_acl_enabled: bool,
    #[serde(default)]
    pub quotas_enabled: bool,
    #[serde(default)]
    pub namespace_isolation: bool,
}

/// Aeira rate-limit ceiling. `qps == 0` means limiting is disabled, so zero
/// is a real setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitClaim {
    pub qps: u32,
    pub burst: u32,
}
