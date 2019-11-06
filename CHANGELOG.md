# Changelog

## 0.4.0 (2019-06-11)

There are no new feature except for some breaking changes to correct.

## Breaking Changes

### `Octet` Misspelling

All misspelling of `octect` have been corrected to `octet`. The following
types have been renamed and the old misspelt version is no longer available.

To migrate, you can simply do a case sensitive replace of `Octect` with `Octet` and
`octect` with `octet` in your code.

The following types have been renamed:

- `jwk::KeyType::Octect` 🡒 `jwk::KeyType::Octet`
- `jwk::KeyType::OctectKeyPair` 🡒 `jwk::KeyType::OctetKeyPair`
- `jwk::OctectKeyType` 🡒 `jwk::OctetKeyType`
- `jwk::OctectKeyType::Octect` 🡒 `jwk::OctetKeyType::Octet`
- `jwk::AlgorithmParameters::OctectKey` 🡒 `jwk::AlgorithmParameters::OctetKey`

The following functions have been renamed:

- `jwk::JWK::new_octect_key` 🡒 `jwk::JWK::new_octet_key`
- `jwk::JWK::octect_key` 🡒 `jwk::JWK::octet_key`
- `jwk::AlgorithmParameters::octect_key` 🡒 `jwk::AlgorithmParameters::octet_key`

### Clippy `trivially_copy_pass_by_ref` lint

This release also fixes the
[Clippy `trivially_copy_pass_by_ref` lint](https://rust-lang.github.io/rust-clippy/master/index.html#trivially_copy_pass_by_ref)
by modifying function arguments that would have taken a reference of a 1 byte value that
implements `Copy` to take the value of itself. This mainly affects all struct methods
of the following types

There should be no need to modify your code for this because the types are `Copy`.

- `jwa::SignatureAlgorithm`
- `jwa::KeyManagementAlgorithm`
- `jwa::ContentEncryptionAlgorithm`
- `jwk::KeyType`

## 0.3.1 (2019-07-30)

There are no new features except for ring dependency changes.

- biscuit now depends on ring 0.16.5
- Changed internal usage of ring's AEAD APIs
- Removed `Compact::to_string`. `Compact` now implements `Display` which has a blanket
  implementation of `std::string::ToString`. Use that instead. This should not break any
  users because `std::string::ToString` is used by the `std` prelude.

## 0.3.0 (2019-07-19)

There are no new features or API changes except for ring dependency changes.

### Breaking Changes

- Minimum supported Rust version is now 1.36 due to Ring's usage of newer Rust features
- biscuit now depends on ring 0.16

## 0.2.0 (2019-03-11)

- Minimum Rust 1.31 is needed for editions support on dependencies
- biscuit now depends on ring 0.14

## Version 0.1.1 (2019-03-18)

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
