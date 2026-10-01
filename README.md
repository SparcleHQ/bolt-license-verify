# bolt-license-verify

This crate checks Bolt license tokens. It only checks. It cannot create a
license, and it holds no key.

Bolt uses it to read the license of a self-hosted Bolt server. It is public so
that people who work on Bolt can build it without access to Sparcle's private
license tools.

## What it does

A Bolt license is a JWT signed with RS256. You pass in the token and the public
key (PEM). The crate tells you:

- whether the signature, the algorithm and the issuer are correct,
- what the license says (organisation, tier, seats, features),
- whether it is valid, in the 30 day grace period, past it, or perpetual,
- whether there is a free seat for one more session.

It does not decide what to do with the answer. That is up to your code.

## Example

```rust
use bolt_license_verify::{check_seats_available, validate_jwt, ExpiryStatus, SeatCheck};

fn check(token: &str, public_key_pem: &str, active_sessions: u64) {
    let result = validate_jwt(token, public_key_pem);
    if !result.valid_signature {
        eprintln!("license rejected: {:?}", result.error);
        return;
    }
    let claims = result.claims.expect("claims are present when the signature is valid");

    match result.expiry_status {
        ExpiryStatus::Valid | ExpiryStatus::Perpetual => {}
        ExpiryStatus::InGrace(days) => eprintln!("license expired {days} days ago"),
        ExpiryStatus::HardCutoff => eprintln!("license is past its grace period"),
        ExpiryStatus::Invalid => unreachable!(),
    }

    match check_seats_available(&claims, active_sessions) {
        SeatCheck::Available { remaining } => println!("ok, {remaining} seats left after this one"),
        SeatCheck::AtCap { seats } => println!("all {seats} seats are in use"),
        SeatCheck::Unlimited => println!("no seat limit"),
    }
}
```

## Rules

- Only RS256 is accepted. Tokens with `alg=none` or HS256 are rejected.
- The issuer must be `bolt.sparcle.app`.
- `exp` is not enforced by the crate. A past `exp` is reported as `InGrace`
  for 30 days, then `HardCutoff`.
- A token with `perpetual: true` never expires.
- `seats: 0` means no seat limit.

## Is it safe that this is public?

Yes. Checking a signature needs only the public key, and that is meant to be
shared. Making a valid license needs the private key, which is not in this
crate and never was. Knowing how the check works does not help anyone make a
token that passes it.

## Tests

```sh
cargo test
```

The tests make a fresh key pair in memory each time they run. No key is stored
in this repository.

## Security issues

Please report security problems to security@sparcle.app, not in a public issue.
See https://sparcle.app/trust/vulnerability-disclosure.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
