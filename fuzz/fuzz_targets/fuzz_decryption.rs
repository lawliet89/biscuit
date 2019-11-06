#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate biscuit;
extern crate serde_json;

use biscuit::{Empty, JWE};
use biscuit::jwk::JWK;
use biscuit::jwa::{KeyManagementAlgorithm, ContentEncryptionAlgorithm};

fuzz_target!(|data: &[u8]| {
    let key: JWK<Empty> = JWK::new_octet_key(&vec![0; 256 / 8], Default::default());

    let token = std::str::from_utf8(data);
    if token.is_err() {
        return;
    }
    let token = token.unwrap();

    let token: JWE<serde_json::Value, biscuit::Empty, biscuit::Empty> = JWE::new_encrypted(&token);

    let _ = token.into_decrypted(
        &key,
        KeyManagementAlgorithm::A256GCMKW,
        ContentEncryptionAlgorithm::A256GCM,
    );
});
