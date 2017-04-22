# biscuit

[![Build Status](https://travis-ci.org/lawliet89/biscuit.svg)](https://travis-ci.org/lawliet89/biscuit)
[![Crates.io](https://img.shields.io/crates/v/biscuit.svg)](https://crates.io/crates/biscuit)
[![Repository](https://img.shields.io/github/tag/lawliet89/biscuit.svg)](https://github.com/lawliet89/biscuit)
[![Documentation](https://docs.rs/biscuit/badge.svg)](https://docs.rs/biscuit)

- Documentation:  [stable](https://docs.rs/biscuit/) | [master branch](https://lawliet89.github.io/biscuit)
- Changelog: [Link](https://github.com/lawliet89/biscuit/blob/master/CHANGELOG.md)

A library based off [`Keats/rust-jwt`](https://github.com/Keats/rust-jwt) that allows you create, parse, and
verify JWT (JSON Web Tokens).

## Installation

Add the following to Cargo.toml:

```toml
biscuit = "0.0.2"
```

To use the latest `master` branch, for example:

```toml
biscuit = { git = "https://github.com/lawliet89/biscuit", branch = "master" }
```

## Supported Features

The crate, does not support all, and probably will never support all of
the features described in the various RFCs, including some algorithms and verification.

See the [documentation](https://github.com/lawliet89/biscuit/blob/master/doc/supported.md) for more information.
