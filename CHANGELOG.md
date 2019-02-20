# Changelog

## 0.2.0 (Unreleased)

- Minimum Rust 1.31 is needed for editions support on dependencies

## Version 0.1.0 (2018-10-29)

### Breaking Change

- Minimum Rust 1.27.2 supported. Older versions might build, but this might not be supported.
- Ring 0.13.2 minimum required. This breaks with other libraries using any other versions

### Features

- Add ECDSA support (https://github.com/lawliet89/biscuit/pull/95)
- Additional claims validation (https://github.com/lawliet89/biscuit/pull/99)
- RSA signature validation with only the exponent and modulus (https://github.com/lawliet89/biscuit/pull/100)

## Version 0.0.8 (2018-02-14)

There are breaking changes in this release:

- `ring` was upgraded to 0.12. Until [#619](https://github.com/briansmith/ring/pull/619) lands,
this crate will now be incompatible with all other crates that uses a different version of `ring`.
- `jwa::rng` is no longer public
- [#84](https://github.com/lawliet89/biscuit/pull/84) All AES GCM encryption now requires a user
provided nonce. See [this example](https://lawliet89.github.io/biscuit/biscuit/type.JWE.html).
- `SignatureAlgorithm::verify` now returns `Result<(), Error>` instead of `Result<bool, Error>`.
- Bumped various dependencies, although they should not break any user facing code: `lazy_static`,
`data-encoding`.

Other non-breaking changes include:

- New helper
[function](https://lawliet89.github.io/biscuit/biscuit/jwk/struct.JWKSet.html#method.find) in `JWKSet` to find key by Key ID
- [New helper functions](https://github.com/lawliet89/biscuit/pull/88) in `jws::Compact` to retrieve
parts without signature verification.

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
