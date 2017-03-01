macro_rules! not_err {
    ($e:expr) => (match $e {
        Ok(e) => e,
        Err(e) => panic!("{} failed with {}", stringify!($e), e),
    })
}

pub fn read_private_key() -> &'static [u8] {
    include_bytes!("../test/fixtures/private_key.der")
}

pub fn read_signature_payload() -> &'static [u8] {
    include_bytes!("../test/fixtures/signature_payload.txt")
}
