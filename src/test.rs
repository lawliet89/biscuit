use ring::signature;
use untrusted;

macro_rules! not_err {
    ($e:expr) => (match $e {
        Ok(e) => e,
        Err(e) => panic!("{} failed with {}", stringify!($e), e),
    })
}

pub fn read_rsa_private_key() -> signature::RSAKeyPair {
    not_err!(signature::RSAKeyPair::from_der(untrusted::Input::from(include_bytes!("../test/fixtures/rsa_private_key.\
                                                                                    der"))))
}

pub fn read_rsa_public_key() -> Vec<u8> {
    include_bytes!("../test/fixtures/rsa_public_key.der").to_vec()
}


pub fn read_ecdsa_public_key() -> signature::RSAKeyPair {
    not_err!(signature::RSAKeyPair::from_der(untrusted::Input::from(include_bytes!("../test/fixtures/ecdsa_private_key.\
                                                                                    der"))))
}
