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
    ValidationError(ValidationError),
    JsonError(serde_json::error::Error),
    DecodeBase64(base64::FromBase64Error),
    Utf8(string::FromUtf8Error),

    UnspecifiedCryptographicError,
    UnsupportedOperation,
}

#[derive(Debug)]
pub enum ValidationError {
    InvalidToken,
    InvalidSignature,
    WrongAlgorithmHeader,
    MissingRequired(String),
    TemporalError(String),
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
impl_from_error!(ValidationError, Error::ValidationError);

impl From<ring::error::Unspecified> for Error {
    fn from(_: ring::error::Unspecified) -> Self {
        Error::UnspecifiedCryptographicError
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        use Error::*;

        match *self {
            GenericError(ref err) => err,
            JsonError(ref err) => err.description(),
            DecodeBase64(ref err) => err.description(),
            Utf8(ref err) => err.description(),
            ValidationError(ref err) => err.description(),
            UnspecifiedCryptographicError => "An Unspecified Cryptographic Error",
            UnsupportedOperation => "This operation is not supported"
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        use Error::*;

        Some(match *self {
            JsonError(ref err) => err as &error::Error,
            DecodeBase64(ref err) => err as &error::Error,
            Utf8(ref err) => err as &error::Error,
            ValidationError(ref err) => err as &error::Error,
            ref e => e as &error::Error,
        })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            GenericError(ref err) => fmt::Display::fmt(err, f),
            JsonError(ref err) => fmt::Display::fmt(err, f),
            DecodeBase64(ref err) => fmt::Display::fmt(err, f),
            Utf8(ref err) => fmt::Display::fmt(err, f),
            ValidationError(ref err) => fmt::Display::fmt(err, f),
            UnspecifiedCryptographicError => write!(f, "{}", error::Error::description(self)),
            UnsupportedOperation => write!(f, "{}", error::Error::description(self)),
        }
    }
}

impl error::Error for ValidationError {
    fn description(&self) -> &str {
        use ValidationError::*;

        match *self {
            InvalidToken => "Invalid Token",
            InvalidSignature => "Invalid Signature",
            WrongAlgorithmHeader => "Wrong Algorithm Header",
            MissingRequired(_) => "Missing required field",
            TemporalError(_) => "Temporal validation failed",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        Some(self as &error::Error)
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ValidationError::*;
        use std::error::Error;

        match *self {
            MissingRequired(ref field) => write!(f, "{} is required but is missing", field),
            TemporalError(ref err) => write!(f, "{}: {}", self.description(), err),
            _ => write!(f, "{}", error::Error::description(self)),
        }

    }
}
