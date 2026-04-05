//! Errors returned will be converted to one of the structs in this module.
use crate::SingleOrMultiple;
use chrono::Duration;
use std::{error, fmt, io, str, string};

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
    /// The token's expiry has passed (exp check failed, RFC7523 3.4)
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
    InvalidIssuer(String),
    /// The token does not have or has the wrong audience (aud check failed, RFC7523 3.3
    InvalidAudience(SingleOrMultiple<String>),
    /// The token doesn't contains the Kid claim in the header
    KidMissing,
    /// The by the Kid specified key, wasn't found in the KeySet
    KeyNotFound,
    /// The algorithm of the JWK is not supported for validating JWTs
    UnsupportedKeyAlgorithm,
    /// An algorithm is needed for verification but was not provided
    MissingAlgorithm,
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
            MissingAlgorithm => write!(
                f,
                "An algorithm is needed for verification but was not provided"
            ),
        }
    }
}

impl error::Error for ValidationError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SingleOrMultiple;
    use chrono::Duration;
    use std::error::Error as StdError;

    // --- Display tests for Error variants ---

    #[test]
    fn display_generic_error() {
        let error = Error::GenericError("test error message".to_string());
        assert_eq!("test error message", error.to_string());
    }

    #[test]
    fn display_wrong_key_type() {
        let error = Error::WrongKeyType {
            expected: "RSA".to_string(),
            actual: "EC".to_string(),
        };
        assert_eq!(
            "RSA was expected for this cryptographic operation but EC was provided",
            error.to_string()
        );
    }

    #[test]
    fn display_wrong_encryption_options() {
        let error = Error::WrongEncryptionOptions {
            expected: "AES_GCM".to_string(),
            actual: "AES_CBC".to_string(),
        };
        assert_eq!(
            "AES_GCM was expected for this cryptographic operation but AES_CBC was provided",
            error.to_string()
        );
    }

    #[test]
    fn display_unspecified_cryptographic_error() {
        let error = Error::UnspecifiedCryptographicError;
        assert_eq!("An unspecified cryptographic error", error.to_string());
    }

    #[test]
    fn display_unsupported_operation() {
        let error = Error::UnsupportedOperation;
        assert_eq!("This operation is not supported", error.to_string());
    }

    // --- Display tests for DecodeError ---

    #[test]
    fn display_decode_error_invalid_token() {
        let error = DecodeError::InvalidToken;
        assert_eq!("Invalid token", error.to_string());
    }

    #[test]
    fn display_decode_error_parts_length_error() {
        let error = DecodeError::PartsLengthError {
            expected: 3,
            actual: 2,
        };
        assert_eq!(
            "Expected 3 parts in Compact JSON representation but got 2",
            error.to_string()
        );
    }

    // --- Display tests for ValidationError ---

    #[test]
    fn display_validation_error_invalid_signature() {
        let error = ValidationError::InvalidSignature;
        assert_eq!("Invalid signature", error.to_string());
    }

    #[test]
    fn display_validation_error_wrong_algorithm_header() {
        let error = ValidationError::WrongAlgorithmHeader;
        assert_eq!(
            "Token provided was signed or encrypted with an unexpected algorithm",
            error.to_string()
        );
    }

    #[test]
    fn display_validation_error_missing_required_claims() {
        let error = ValidationError::MissingRequiredClaims(vec![
            "exp".to_string(),
            "iat".to_string(),
        ]);
        let msg = error.to_string();
        assert!(msg.contains("exp"));
        assert!(msg.contains("iat"));
    }

    #[test]
    fn display_validation_error_expired() {
        let error = ValidationError::Expired(Duration::seconds(30));
        assert_eq!("Token expired 30 seconds ago", error.to_string());
    }

    #[test]
    fn display_validation_error_not_yet_valid() {
        let error = ValidationError::NotYetValid(Duration::seconds(60));
        assert_eq!("Token will be valid in 60 seconds", error.to_string());
    }

    #[test]
    fn display_validation_error_too_old() {
        let error = ValidationError::TooOld(Duration::seconds(15));
        assert_eq!(
            "Token has been considered too old for 15 seconds",
            error.to_string()
        );
    }

    #[test]
    fn display_validation_error_invalid_issuer() {
        let error = ValidationError::InvalidIssuer("bad_issuer".to_string());
        assert!(error.to_string().contains("bad_issuer"));
    }

    #[test]
    fn display_validation_error_invalid_audience() {
        let error =
            ValidationError::InvalidAudience(SingleOrMultiple::Single("aud".to_string()));
        assert!(error.to_string().contains("aud"));
    }

    #[test]
    fn display_validation_error_kid_missing() {
        let error = ValidationError::KidMissing;
        assert_eq!("Header is missing kid", error.to_string());
    }

    #[test]
    fn display_validation_error_key_not_found() {
        let error = ValidationError::KeyNotFound;
        assert_eq!("Key not found in JWKS", error.to_string());
    }

    #[test]
    fn display_validation_error_unsupported_key_algorithm() {
        let error = ValidationError::UnsupportedKeyAlgorithm;
        assert_eq!("Algorithm of JWK not supported", error.to_string());
    }

    #[test]
    fn display_validation_error_missing_algorithm() {
        let error = ValidationError::MissingAlgorithm;
        assert_eq!(
            "An algorithm is needed for verification but was not provided",
            error.to_string()
        );
    }

    // --- Error wrapping delegates Display to inner type ---

    #[test]
    fn error_wraps_decode_error_for_display() {
        let error: Error = DecodeError::InvalidToken.into();
        assert_eq!("Invalid token", error.to_string());
    }

    #[test]
    fn error_wraps_validation_error_for_display() {
        let error: Error = ValidationError::InvalidSignature.into();
        assert_eq!("Invalid signature", error.to_string());
    }

    // --- From conversion tests ---

    #[test]
    fn from_string_to_error() {
        let error: Error = "test message".to_string().into();
        assert!(matches!(error, Error::GenericError(ref msg) if msg == "test message"));
    }

    #[test]
    fn from_validation_error_to_error() {
        let error: Error = ValidationError::InvalidSignature.into();
        assert!(matches!(
            error,
            Error::ValidationError(ValidationError::InvalidSignature)
        ));
    }

    #[test]
    fn from_decode_error_to_error() {
        let error: Error = DecodeError::InvalidToken.into();
        assert!(matches!(error, Error::DecodeError(DecodeError::InvalidToken)));
    }

    #[test]
    fn from_io_error_to_error() {
        let io_error = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let error: Error = io_error.into();
        assert!(matches!(error, Error::IOError(_)));
    }

    #[test]
    fn from_unspecified_cryptographic_error() {
        let error: Error = ring::error::Unspecified.into();
        assert!(matches!(error, Error::UnspecifiedCryptographicError));
    }

    #[test]
    fn from_utf8_error() {
        let invalid_utf8 = vec![0xFF, 0xFE];
        let utf8_error = str::from_utf8(&invalid_utf8).unwrap_err();
        let error: Error = utf8_error.into();
        assert!(matches!(error, Error::Utf8(_)));
    }

    #[test]
    fn from_string_from_utf8_error() {
        let invalid_utf8 = vec![0xFF, 0xFE];
        let utf8_error = String::from_utf8(invalid_utf8).unwrap_err();
        let error: Error = utf8_error.into();
        assert!(matches!(error, Error::Utf8(_)));
    }

    #[test]
    fn from_json_error_to_error() {
        let json_error =
            serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let error: Error = json_error.into();
        assert!(matches!(error, Error::JsonError(_)));
    }

    #[test]
    fn from_base64_decode_error_to_error() {
        let base64_error = data_encoding::BASE64URL_NOPAD.decode(b"!@#$%^").unwrap_err();
        let error: Error = base64_error.into();
        assert!(matches!(error, Error::DecodeBase64(_)));
    }

    // --- std::error::Error::source() tests ---

    #[test]
    fn error_source_for_json_error_is_some() {
        let json_error =
            serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let error: Error = json_error.into();
        assert!(error.source().is_some());
    }

    #[test]
    fn error_source_for_io_error_is_some() {
        let io_error = io::Error::new(io::ErrorKind::NotFound, "not found");
        let error: Error = io_error.into();
        assert!(error.source().is_some());
    }

    #[test]
    fn error_source_for_decode_error_is_some() {
        let error: Error = DecodeError::InvalidToken.into();
        assert!(error.source().is_some());
    }

    #[test]
    fn error_source_for_validation_error_is_some() {
        let error: Error = ValidationError::InvalidSignature.into();
        assert!(error.source().is_some());
    }

    #[test]
    fn error_source_for_generic_error_is_none() {
        let error = Error::GenericError("test".to_string());
        assert!(error.source().is_none());
    }

    #[test]
    fn error_source_for_wrong_key_type_is_none() {
        let error = Error::WrongKeyType {
            expected: "RSA".to_string(),
            actual: "EC".to_string(),
        };
        assert!(error.source().is_none());
    }

    #[test]
    fn error_source_for_unspecified_is_none() {
        let error = Error::UnspecifiedCryptographicError;
        assert!(error.source().is_none());
    }

    #[test]
    fn decode_error_source_is_none() {
        let error = DecodeError::InvalidToken;
        assert!(error.source().is_none());
    }

    #[test]
    fn validation_error_source_is_none() {
        let error = ValidationError::InvalidSignature;
        assert!(error.source().is_none());
    }

    // --- ValidationError derived trait tests ---

    #[test]
    fn validation_error_equality() {
        assert_eq!(ValidationError::InvalidSignature, ValidationError::InvalidSignature);
        assert_ne!(ValidationError::InvalidSignature, ValidationError::WrongAlgorithmHeader);
    }

    #[test]
    fn validation_error_clone() {
        let error = ValidationError::MissingRequiredClaims(vec!["exp".to_string()]);
        let cloned = error.clone();
        assert_eq!(error, cloned);
    }
}
