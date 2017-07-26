//! Errors returned will be converted to one of the structs in this module.
use std::{str, string, fmt, error, io};
use data_encoding;
use ring;
use serde_json;
use url::ParseError;

#[derive(Debug)]
/// All the errors we can encounter while signing/verifying tokens
/// and a couple of custom one for when the token we are trying
/// to verify is invalid
pub enum Error {
    /// A generic error which is described by the contained string
    GenericError(String),
    /// Error returned from failed token validation
    ValidationError(ValidationError),
    /// Error during the serialization or deserialization of tokens
    JsonError(serde_json::error::Error),
    /// Error during base64 encoding or decoding
    DecodeBase64(data_encoding::decode::Error),
    /// Error when decoding bytes to UTF8 string
    Utf8(str::Utf8Error),
    /// Errors related to IO
    IOError(io::Error),
    /// Errors related to URI parsing
    UriParseError(ParseError),

    /// Wrong key type was provided for the cryptographic operation
    WrongKeyType {
        /// Expected type of key
        expected: String,
        /// Actual type of key
        actual: String,
    },

    /// Wrong variant of `EncryptionOptions` was provided for the encryption operation
    WrongEncryptionOptions {
        /// Expected variant of options
        expected: String,
        /// Actual variant of options
        actual: String,
    },

    /// An unknown cryptographic error
    UnspecifiedCryptographicError,
    /// An unsupported or invalid operation
    UnsupportedOperation,
}

#[derive(Debug)]
/// Errors from validating tokens
pub enum ValidationError {
    /// Token is invalid in structure or form
    InvalidToken,
    /// Token has an invalid signature
    InvalidSignature,
    /// Token provided was signed or encrypted with an unexpected algorithm
    WrongAlgorithmHeader,

    /// A field required is missing from the token
    MissingRequired(String),
    /// The token has invalid temporal field values
    TemporalError(String),
    /// The number of compact parts is incorrect
    PartsLengthError {
        /// Expected number of parts
        expected: usize,
        /// Actual number of parts
        actual: usize,
    },
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
impl_from_error!(data_encoding::decode::Error, Error::DecodeBase64);
impl_from_error!(str::Utf8Error, Error::Utf8);
impl_from_error!(ValidationError, Error::ValidationError);
impl_from_error!(io::Error, Error::IOError);
impl_from_error!(ParseError, Error::UriParseError);


impl From<ring::error::Unspecified> for Error {
    fn from(_: ring::error::Unspecified) -> Self {
        Error::UnspecifiedCryptographicError
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(e: string::FromUtf8Error) -> Self {
        Error::Utf8(e.utf8_error())
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
            IOError(ref e) => e.description(),
            UriParseError(ref e) => e.description(),
            WrongKeyType { .. } => "The wrong type of key was provided for the cryptographic operation",
            WrongEncryptionOptions { .. } => {
                "Wrong variant of `EncryptionOptions` was provided for the encryption operation"
            }
            UnspecifiedCryptographicError => "An Unspecified Cryptographic Error",
            UnsupportedOperation => "This operation is not supported",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        use Error::*;

        Some(match *self {
            JsonError(ref err) => err,
            DecodeBase64(ref err) => err,
            Utf8(ref err) => err,
            ValidationError(ref err) => err,
            IOError(ref e) => e,
            UriParseError(ref e) => e,
            ref e => e,
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
            IOError(ref err) => fmt::Display::fmt(err, f),
            UriParseError(ref err) => fmt::Display::fmt(err, f),
            WrongKeyType {
                ref actual,
                ref expected,
            } => {
                write!(
                    f,
                    "{} was expected for this cryptographic operation but {} was provided",
                    expected,
                    actual
                )
            }
            WrongEncryptionOptions {
                ref actual,
                ref expected,
            } => {
                write!(
                    f,
                    "{} was expected for this cryptographic operation but {} was provided",
                    expected,
                    actual
                )
            }
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
            WrongAlgorithmHeader => "Token provided was signed or encrypted with an unexpected algorithm",
            PartsLengthError { .. } => "Unexpected number of parts in compact JSON representation",
            MissingRequired(_) => "Missing required field",
            TemporalError(_) => "Temporal validation failed",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        Some(self)
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ValidationError::*;
        use std::error::Error;

        match *self {
            MissingRequired(ref field) => write!(f, "{} is required but is missing", field),
            TemporalError(ref err) => write!(f, "{}: {}", self.description(), err),
            PartsLengthError { expected, actual } => {
                write!(
                    f,
                    "Expected {} parts in Compact JSON representation but got {}",
                    expected,
                    actual
                )
            }
            _ => write!(f, "{}", error::Error::description(self)),
        }

    }
}
