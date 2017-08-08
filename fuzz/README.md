# fuzz

## Running the fuzz tests

The fuzz tests can be run using `cargo fuzz` in nightly.

```
cargo install cargo-fuzz -f
cargo fuzz list
cargo +nightly fuzz run fuzz_parser
```
