# biscuit

[![Build Status](https://travis-ci.org/lawliet89/biscuit.svg)](https://travis-ci.org/lawliet89/biscuit)
[![Crates.io](https://img.shields.io/crates/v/biscuit.svg)](https://crates.io/crates/biscuit)
[![Repository](https://img.shields.io/github/tag/lawliet89/biscuit.svg)](https://github.com/lawliet89/biscuit)
[![Documentation](https://docs.rs/biscuit/badge.svg)](https://docs.rs/biscuit)
[![dependency status](https://deps.rs/repo/github/lawliet89/biscuit/status.svg)](https://deps.rs/repo/github/lawliet89/biscuit)

- Documentation:  [stable](https://docs.rs/biscuit/)
- Changelog: [Link](https://github.com/lawliet89/biscuit/blob/master/CHANGELOG.md)

A library to work with Javascript Object Signing and Encryption(JOSE),
including JSON Web Tokens (JWT), JSON Web Signature (JWS) and JSON Web Encryption (JWE)

This was based off [`Keats/rust-jwt`](https://github.com/Keats/rust-jwt).

## Installation

Add the following to Cargo.toml:

```toml
biscuit = "0.6.0-beta1"
```

To use the latest `master` branch, for example:

```toml
biscuit = { git = "https://github.com/lawliet89/biscuit", branch = "master" }
```

## Supported Features

The crate, does not support all, and probably will never support all of
the features described in the various RFCs, including some algorithms and verification.

See the [documentation](https://github.com/lawliet89/biscuit/blob/master/doc/supported.md) for more information.
