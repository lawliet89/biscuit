//! Errors returned will be converted to one of the structs in this module.
use chrono::Duration;
use data_encoding;
use ring;
use serde_json;
use std::{io, str, string};
use url::ParseError;
use SingleOrMultiple;
use StringOrUri;

#[derive(Fail, Debug)]
/// All the errors we can encounter while signing/verifying tokens
/// and a couple of custom one for when the token we are trying
/// to verify is invalid
pub enum Error {
    /// A generic error which is described by the contained string
    #[fail(display = "An unknown error has occured: {}", _0)]
    GenericError(String),
    /// Error returned from failed token decoding
    #[fail(display = "{}", _0)]
    DecodeError(#[fail(cause)] DecodeError),
    /// Error returned from failed token validation
    #[fail(display = "{}", _0)]
    ValidationError(#[fail(cause)] ValidationError),
    /// Error during the serialization or deserialization of tokens
    #[fail(display = "{}", _0)]
    JsonError(#[fail(cause)] serde_json::error::Error),
    /// Error during base64 encoding or decoding
    #[fail(display = "{}", _0)]
    DecodeBase64(#[fail(cause)] data_encoding::DecodeError),
    /// Error when decoding bytes to UTF8 string
    #[fail(display = "{}", _0)]
    Utf8(#[fail(cause)] str::Utf8Error),
    /// Errors related to IO
    #[fail(display = "{}", _0)]
    IOError(#[fail(cause)] io::Error),
    /// Errors related to URI parsing
    #[fail(display = "{}", _0)]
    UriParseError(#[fail(cause)] ParseError),

    /// Wrong key type was provided for the cryptographic operation
    #[fail(
        display = "{} was expected for this cryptographic operation but {} was provided",
        expected,
        actual
    )]
    WrongKeyType {
        /// Expected type of key
        expected: String,
        /// Actual type of key
        actual: String,
    },

    /// Wrong variant of `EncryptionOptions` was provided for the encryption operation
    #[fail(
        display = "{} was expected for this cryptographic operation but {} was provided",
        expected,
        actual
    )]
    WrongEncryptionOptions {
        /// Expected variant of options
        expected: String,
        /// Actual variant of options
        actual: String,
    },

    /// An unknown cryptographic error
    #[fail(display = "An Unspecified Cryptographic Error")]
    UnspecifiedCryptographicError,
    /// An unsupported or invalid operation
    #[fail(display = "This operation is not supported")]
    UnsupportedOperation,
}

#[derive(Fail, Debug, Eq, PartialEq, Clone)]
/// Errors from decoding tokens
pub enum DecodeError {
    /// Token is invalid in structure or form
    #[fail(display = "Token is invalid or malformed")]
    InvalidToken,
    /// The number of compact parts is incorrect
    #[fail(
        display = "Expected {} parts but got {} parts compact JSON representation",
        expected,
        actual
    )]
    PartsLengthError {
        /// Expected number of parts
        expected: usize,
        /// Actual number of parts
        actual: usize,
    },
}

#[derive(Fail, Debug, Eq, PartialEq, Clone)]
/// Errors from validating tokens
pub enum ValidationError {
    /// Token has an invalid signature (RFC7523 3.9)
    #[fail(display = "Token has an invalid signature")]
    InvalidSignature,
    /// Token provided was signed or encrypted with an unexpected algorithm
    #[fail(display = "Token provided was signed or encrypted with an unexpected algorithm")]
    WrongAlgorithmHeader,
    /// A field required is missing from the token
    /// The parameter shows the name of the missing claim
    #[fail(display = "Token is missing required claims: {:?}", _0)]
    MissingRequiredClaims(Vec<String>),
    /// The token's expiry has passed (exp check failled, RFC7523 3.4)
    /// The parameter show how long the token has expired
    #[fail(display = "Token expired {} ago", _0)]
    Expired(Duration),
    /// The token is not yet valid (nbf check failed, RFC7523 3.5)
    /// The parameter show how much longer the token will start to be valid
    #[fail(display = "Token will be valid in {}", _0)]
    NotYetValid(Duration),
    /// The token has been created too far in the past (iat check failed, RFC7523 3.6)
    /// This is different from Expired because the token may not be expired yet, but the
    /// acceptor of the token may impose more strict requirement for the age of the token for
    /// some more sensitive operations.
    /// The parameter show how much older the token is than required
    #[fail(display = "Token has been considered too old for {}", _0)]
    TooOld(Duration),
    /// The token does not have or has the wrong issuer (iss check failed, RFC7523 3.1)
    #[fail(display = "Issuer of token is invalid: {}", _0)]
    InvalidIssuer(StringOrUri),
    /// The token does not have or has the wrong audience (aud check failed, RFC7523 3.3
    #[fail(display = "Audience of token is invalid: {}", _0)]
    InvalidAudience(SingleOrMultiple<StringOrUri>),
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
