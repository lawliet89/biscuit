use ring::signature;
use untrusted;

macro_rules! not_err {
    ($e:expr) => (match $e {
        Ok(e) => e,
        Err(e) => panic!("{} failed with {}", stringify!($e), e),
    })
}

pub fn read_private_key() -> signature::RSAKeyPair {
    not_err!(signature::RSAKeyPair::from_der(untrusted::Input::from(include_bytes!("../test/fixtures/private_key.\
                                                                                    der"))))
}

pub fn read_public_key() -> Vec<u8> {
    include_bytes!("../test/fixtures/public_key.der").iter().map(|b| b.clone()).collect()
}

pub fn read_signature_payload() -> &'static [u8] {
    include_bytes!("../test/fixtures/signature_payload.txt")
}
