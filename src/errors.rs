use ring;
use std::{string, fmt, error};
use serde_json;
use rustc_serialize::base64;

#[derive(Debug)]
/// All the errors we can encounter while signing/verifying tokens
/// and a couple of custom one for when the token we are trying
/// to verify is invalid
pub enum Error {
    GenericError(String),
    JsonError(serde_json::error::Error),
    DecodeBase64(base64::FromBase64Error),
    Utf8(string::FromUtf8Error),

    InvalidToken,
    InvalidSignature,
    WrongAlgorithmHeader,
    UnspecifiedCryptographicError,
}

macro_rules! impl_from_error {
    ($f: ty, $e: expr) => {
        impl From<$f> for Error {
            fn from(f: $f) -> Error { $e(f) }
        }
    }
}

impl_from_error!(String, Error::GenericError);
impl_from_error!(serde_json::error::Error, Error::JsonError);
impl_from_error!(base64::FromBase64Error, Error::DecodeBase64);
impl_from_error!(string::FromUtf8Error, Error::Utf8);

impl From<ring::error::Unspecified> for Error {
    fn from(_: ring::error::Unspecified) -> Self {
        Error::UnspecifiedCryptographicError
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::GenericError(ref err) => err,
            Error::JsonError(ref err) => err.description(),
            Error::DecodeBase64(ref err) => err.description(),
            Error::Utf8(ref err) => err.description(),
            Error::InvalidToken => "Invalid Token",
            Error::InvalidSignature => "Invalid Signature",
            Error::WrongAlgorithmHeader => "Wrong Algorithm Header",
            Error::UnspecifiedCryptographicError => "An Unspecified Cryptographic Error",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        Some(match *self {
            Error::JsonError(ref err) => err as &error::Error,
            Error::DecodeBase64(ref err) => err as &error::Error,
            Error::Utf8(ref err) => err as &error::Error,
            ref e => e as &error::Error,
        })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::GenericError(ref err) => fmt::Display::fmt(err, f),
            Error::JsonError(ref err) => fmt::Display::fmt(err, f),
            Error::DecodeBase64(ref err) => fmt::Display::fmt(err, f),
            Error::Utf8(ref err) => fmt::Display::fmt(err, f),
            Error::InvalidToken => write!(f, "{}", error::Error::description(self)),
            Error::InvalidSignature => write!(f, "{}", error::Error::description(self)),
            Error::WrongAlgorithmHeader => write!(f, "{}", error::Error::description(self)),
            Error::UnspecifiedCryptographicError => write!(f, "{}", error::Error::description(self)),
        }
    }
}
