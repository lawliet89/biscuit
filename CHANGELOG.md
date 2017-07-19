# Changelog

## Version 0.0.7 (2017-07-19)

There are no breaking changes in this release.

Added a convenience `validate_times` function to `jwe::Compact` and `jws::Compact` that allows
quick temporal validation if their payloads are `ClaimSet`s.

## Version 0.0.6 (2017-07-05)

This release adds no new features and breaks no API. It simply bumps `ring` to 0.11.

## Version 0.0.5 (2017-07-05)

This release adds no new features and breaks no API. It simply bumps Chrono and Ring to their newest version.

## Version 0.0.4 (2017-05-15)

Update dependency to `ring` 0.9.4 so that different versions of `ring` can no longer be used in a Rust build.

There are no new features or API change.

## Version 0.0.3 (2017-04-23)

Minor bug fix release. Fixed incorrect ECDSA signature verification.

Thanks to @hobofan.

## Version 0.0.2 (2017-04-23)

This is a major breaking release. Not all algorithms, verification, and features are
supported yet.

### New Features

- JSON Web Encryption support (JWE)
- JSON Web Key (JWK)
- Replaced `rustc_serialize` with `serde`
- Support custom headers for JWS
- Added a `biscuit::Empty` convenice empty struct that users can plug into type parameters when they do
not need them, such as the type parameter of custom headers.
- Added `SingleOrMultiple` and `StringOrUri` enums to better represent the types of values that the JOSE
RFCs allow.

### Breaking Changes

- `biscuit::JWT` is no longer a struct. It is now a type alias for `jws::Compact`, which according
to the RFC, is the compact serialization of a JSON Web Signature (JWS).
- Moved `biscuit::Algorithm` to `biscuit::jwa::SignatureAlgorithm` to better reflect its use.
- Various internal traits that should be implementation detail and opaque to users of `biscuit` have been
changed, added, or removed.

## Version 0.0.1 (2017-03-17)

This is an initial release after forking from Version 1.1.6 of [`Keats/rust-jwt`](https://github.com/Keats/rust-jwt).

- Added RSA signing and verification
- Added ECDSA verification (signing support is pending addition of support in `ring`)
