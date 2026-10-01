//! # bolt-license-verify
//!
//! Checks a Bolt license token. This crate only VERIFIES. It holds no key and
//! has no code that can sign or issue a license.
//!
//! A Bolt license is a JWT signed with RS256. The caller supplies the public
//! key (PEM). This crate gives back plain verdicts and makes no policy
//! decision itself:
//!
//!   * [`validate_jwt`] checks the signature, the algorithm and the issuer,
//!     then returns a [`ValidationResult`] whose [`ExpiryStatus`] says
//!     whether the token is valid, inside the grace period, past it, or
//!     perpetual. Expiry is reported, not enforced, so the caller decides
//!     what to do.
//!
//!   * [`check_seats_available`] compares the seat cap in the token with the
//!     number of active sessions the caller passes in, and returns a
//!     [`SeatCheck`].
//!
//! ## Rules this crate encodes
//!
//! | Concern        | Behavior                                                   |
//! |----------------|------------------------------------------------------------|
//! | Seats          | `AtCap` when `active >= seats`. `seats == 0` is unlimited. |
//! | Expiry         | [`EXPIRY_GRACE_DAYS`] of grace after `exp`.                |
//! | After grace    | `HardCutoff`. The caller refuses NEW sessions only.        |
//! | Perpetual      | `perpetual: true` never expires. No grace, no cutoff.      |
//! | Algorithm      | RS256 only. `alg=none` and HS256 are rejected.             |

use serde::{Deserialize, Serialize};

pub mod claims;
pub mod validator;

pub use claims::{AeiraFeatures, LicenseClaims, LicenseFeatures, RateLimitClaim};
pub use validator::{
    check_seats_available, validate_jwt, ExpiryStatus, SeatCheck, ValidationResult,
    EXPIRY_GRACE_DAYS, ISSUER,
};

/// Crate version, for diagnostic logging.
pub const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Re-export of `serde_json` so callers do not need a direct dependency just
/// to build ad-hoc diagnostic JSON.
#[doc(hidden)]
pub use serde_json;

/// Marker type so downstream crates can name this crate in type position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoltLicense;
