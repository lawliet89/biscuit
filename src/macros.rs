macro_rules! unexpected_key_type_error {
    ($expected: path, $actual: expr) => {
        Error::WrongKeyType { actual: $actual.to_string(), expected: $expected.to_string() }
    }
}
