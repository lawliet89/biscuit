//! Errors returned will be converted to one of the structs in this module.
use crate::SingleOrMultiple;
use crate::StringOrUri;
use chrono::Duration;
use data_encoding;
use ring;
use serde_json;
use std::{error, fmt, io, str, string};
use url::ParseError;

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
    /// Key was rejected by Ring
    KeyRejected(ring::error::KeyRejected),

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
    InvalidAudience(SingleOrMultiple<StringOrUri>),
    /// The token doesn't contains the Kid claim in the header
    KidMissing,
    /// The by the Kid specified key, wasn't found in the KeySet
    KeyNotFound,
    /// The algorithm of the JWK is not supported for validating JWTs
    UnsupportedKeyAlgorithm,
}

macro_rules! impl_from_error {
    ($f:ty, $e:expr) => {
        impl From<$f> for Error {
            fn from(f: $f) -> Error {
                $e(f)
            }
        }
    };
}

impl_from_error!(String, Error::GenericError);
impl_from_error!(serde_json::error::Error, Error::JsonError);
impl_from_error!(data_encoding::DecodeError, Error::DecodeBase64);
impl_from_error!(str::Utf8Error, Error::Utf8);
impl_from_error!(ValidationError, Error::ValidationError);
impl_from_error!(DecodeError, Error::DecodeError);
impl_from_error!(io::Error, Error::IOError);
impl_from_error!(ParseError, Error::UriParseError);
impl_from_error!(ring::error::KeyRejected, Error::KeyRejected);

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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::Error::*;

        match *self {
            GenericError(ref err) => fmt::Display::fmt(err, f),
            JsonError(ref err) => fmt::Display::fmt(err, f),
            DecodeBase64(ref err) => fmt::Display::fmt(err, f),
            Utf8(ref err) => fmt::Display::fmt(err, f),
            DecodeError(ref err) => fmt::Display::fmt(err, f),
            ValidationError(ref err) => fmt::Display::fmt(err, f),
            IOError(ref err) => fmt::Display::fmt(err, f),
            UriParseError(ref err) => fmt::Display::fmt(err, f),
            KeyRejected(ref err) => fmt::Display::fmt(err, f),
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
            UnspecifiedCryptographicError => write!(f, "An unspecified cryptographic error"),
            UnsupportedOperation => write!(f, "This operation is not supported"),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use crate::Error::*;

        match *self {
            JsonError(ref err) => Some(err),
            DecodeBase64(ref err) => Some(err),
            Utf8(ref err) => Some(err),
            DecodeError(ref err) => Some(err),
            ValidationError(ref err) => Some(err),
            IOError(ref err) => Some(err),
            UriParseError(ref err) => Some(err),
            _ => None,
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use self::DecodeError::*;

        match *self {
            InvalidToken => write!(f, "Invalid token"),
            PartsLengthError { expected, actual } => write!(
                f,
                "Expected {} parts in Compact JSON representation but got {}",
                expected, actual
            ),
        }
    }
}

impl error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::ValidationError::*;

        match *self {
            MissingRequiredClaims(ref fields) => write!(
                f,
                "The following claims are required, but missing: {:?}",
                fields
            ),
            Expired(ago) => write!(f, "Token expired {} seconds ago", ago.num_seconds()),
            NotYetValid(nyv_for) => write!(
                f,
                "Token will be valid in {} seconds",
                nyv_for.num_seconds()
            ),
            TooOld(duration) => write!(
                f,
                "Token has been considered too old for {} seconds",
                duration.num_seconds()
            ),
            InvalidIssuer(ref iss) => write!(f, "Issuer of token is invalid: {:?}", iss),
            InvalidAudience(ref aud) => write!(f, "Audience of token is invalid: {:?}", aud),
            InvalidSignature => write!(f, "Invalid signature"),
            WrongAlgorithmHeader => write!(
                f,
                "Token provided was signed or encrypted with an unexpected algorithm"
            ),
            KidMissing => write!(f, "Header is missing kid"),
            KeyNotFound => write!(f, "Key not found in JWKS"),
            UnsupportedKeyAlgorithm => write!(f, "Algorithm of JWK not supported"),
        }
    }
}

impl error::Error for ValidationError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}
