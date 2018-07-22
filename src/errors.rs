//! Errors returned will be converted to one of the structs in this module.
use std::{error, fmt, io, str, string};
use data_encoding;
use ring;
use serde_json;
use url::ParseError;
use chrono::Duration;
use SingleOrMultiple;
use StringOrUri;

#[derive(Debug)]
/// All the errors we can encounter while signing/verifying tokens
/// and a couple of custom one for when the token we are trying
/// to verify is invalid
pub enum Error {
    /// A generic error which is described by the contained string
    GenericError(String),
    /// Error returned from failed token decoding
    DecodeError(DecodeError),
    /// Error returned from failed token validation
    ValidationError(ValidationError),
    /// Error during the serialization or deserialization of tokens
    JsonError(serde_json::error::Error),
    /// Error during base64 encoding or decoding
    DecodeBase64(data_encoding::DecodeError),
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
/// Errors from decoding tokens
pub enum DecodeError {
    /// Token is invalid in structure or form
    InvalidToken,
    /// The number of compact parts is incorrect
    PartsLengthError {
        /// Expected number of parts
        expected: usize,
        /// Actual number of parts
        actual: usize,
    },

}

#[derive(Debug, Eq, PartialEq, Clone)]
/// Errors from validating tokens
pub enum ValidationError {
    /// Token has an invalid signature (RFC7523 3.9)
    InvalidSignature,
    /// Token provided was signed or encrypted with an unexpected algorithm
    WrongAlgorithmHeader,
    /// A field required is missing from the token
    /// The parameter shows the name of the missing claim
    MissingRequiredClaims(Vec<String>),
    /// The token's expiry has passed (exp check failled, RFC7523 3.4)
    /// The parameter show how long the token has expired
    Expired(Duration),
    /// The token is not yet valid (nbf check failed, RFC7523 3.5)
    /// The parameter show how much longer the token will start to be valid
    NotYetValid(Duration),
    /// The token has been created too far in the past (iat check failed, RFC7523 3.6)
    /// This is different from Expired because the token may not be expired yet, but the
    /// acceptor of the token may impose more strict requirement for the age of the token for
    /// some more sensitive operations.
    /// The parameter show how much older the token is than required
    TooOld(Duration),
    /// The token does not have or has the wrong issuer (iss check failed, RFC7523 3.1)
    InvalidIssuer(StringOrUri),
    /// The token does not have or has the wrong audience (aud check failed, RFC7523 3.3
    InvalidAudience(SingleOrMultiple<StringOrUri>)
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
impl_from_error!(data_encoding::DecodeError, Error::DecodeBase64);
impl_from_error!(str::Utf8Error, Error::Utf8);
impl_from_error!(ValidationError, Error::ValidationError);
impl_from_error!(DecodeError, Error::DecodeError);
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
            DecodeError(ref err) => err.description(),
            IOError(ref err) => err.description(),
            UriParseError(ref err) => err.description(),
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
            DecodeError(ref err) => err,
            ValidationError(ref err) => err,
            IOError(ref err) => err,
            UriParseError(ref err) => err,
            ref err => err,
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
            DecodeError(ref err) => fmt::Display::fmt(err, f),
            ValidationError(ref err) => fmt::Display::fmt(err, f),
            IOError(ref err) => fmt::Display::fmt(err, f),
            UriParseError(ref err) => fmt::Display::fmt(err, f),
            WrongKeyType {
                ref actual,
                ref expected,
            } => write!(
                f,
                "{} was expected for this cryptographic operation but {} was provided",
                expected, actual
            ),
            WrongEncryptionOptions {
                ref actual,
                ref expected,
            } => write!(
                f,
                "{} was expected for this cryptographic operation but {} was provided",
                expected, actual
            ),
            UnspecifiedCryptographicError => write!(f, "{}", error::Error::description(self)),
            UnsupportedOperation => write!(f, "{}", error::Error::description(self)),
        }
    }
}

impl error::Error for ValidationError {
    fn description(&self) -> &str {
        use ValidationError::*;

        match *self {
            InvalidSignature => "Invalid Signature",
            WrongAlgorithmHeader => "Token provided was signed or encrypted with an unexpected algorithm",
            MissingRequiredClaims(_) => "Missing required claim",
            Expired(_) => "Token expired",
            NotYetValid(_) => "Token not yet valid",
            TooOld(_) => "Token is too old",
            InvalidIssuer(_) => "Issuer is invalid",
            InvalidAudience(_) => "Audience of token is invalid"
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        Some(self)
    }
}

impl error::Error for DecodeError {
    fn description(&self) -> &str {
        use self::DecodeError::*;

        match *self {
            InvalidToken => "Invalid Token",
            PartsLengthError { .. } => "Unexpected number of parts in compact JSON representation",
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ValidationError::*;
        use std::error::Error;

        match *self {
            MissingRequiredClaims(ref fields) => write!(f, "The following claims are required, but missing: {:?}", fields),
            Expired(ago) => write!(f, "Token expired {} seconds ago", ago.num_seconds()),
            NotYetValid(nyv_for) => write!(f, "Token will be valid in {} seconds", nyv_for.num_seconds()),
            TooOld(duration) => write!(f, "Token has been considered too old for {} seconds", duration.num_seconds()),
            InvalidIssuer(ref iss) => write!(f, "Issuer of token is invalid: {:?}", iss),
            InvalidAudience(ref aud) => write!(f, "Audience of token is invalid: {:?}", aud),

            InvalidSignature | WrongAlgorithmHeader => write!(f, "{}", self.description())
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::DecodeError::*;
        use std::error::Error;

        match *self {
            InvalidToken => write!(f, "{}", self.description()),
            PartsLengthError { expected, actual } => write!(
                f,
                "Expected {} parts in Compact JSON representation but got {}",
                expected, actual
            )
        }
    }
}
