//! Related to the JWS RFC, including JWT signing and headers
use std::default::Default;
use std::sync::Arc;

use ring::{digest, hmac, rand, signature};
use ring::constant_time::verify_slices_are_equal;
use untrusted;

use CompactJson;
use CompactPart;
use errors::{Error, ValidationError};

/// Compact representation of a JWS
///
/// This representation contains a payload (type `T`) (e.g. a claims set) and is (optionally) signed. This is the
/// most common form of tokens used.
///
/// Serialization/deserialization is handled by serde. Before you transport the token, make sure you
/// turn it into the encoded form first.
///
/// # Examples
/// ## Encoding and decoding with HS256
///
/// ```
/// extern crate biscuit;
/// extern crate serde;
/// #[macro_use]
/// extern crate serde_derive;
/// extern crate serde_json;
///
/// use std::str::FromStr;
/// use biscuit::*;
/// use biscuit::jws::*;
///
/// # fn main() {
///
/// // Define our own private claims
/// #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
/// struct PrivateClaims {
///     company: String,
///     department: String,
/// }
///
/// let expected_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
///                         eyJpc3MiOiJodHRwczovL3d3dy5hY21lLmNv\
///                         bS8iLCJzdWIiOiJKb2huIERvZSIsImF1ZCI6I\
///                         mh0dHM6Ly9hY21lLWN1c3RvbWVyLmNvbS8iLC\
///                         JuYmYiOjEyMzQsImNvbXBhbnkiOiJBQ01FIiwi\
///                         ZGVwYXJ0bWVudCI6IlRvaWxldCBDbG\
///                         VhbmluZyJ9.dnx1OmRZSFxjCD1ivy4lveTT-sxay5Fq6vY6jnJvqeI";
///
/// let expected_claims = ClaimsSet::<PrivateClaims> {
///     registered: RegisteredClaims {
///         issuer: Some(FromStr::from_str("https://www.acme.com").unwrap()),
///         subject: Some(FromStr::from_str("John Doe").unwrap()),
///         audience:
///             Some(SingleOrMultiple::Single(FromStr::from_str("htts://acme-customer.com").unwrap())),
///         not_before: Some(1234.into()),
///         ..Default::default()
///     },
///     private: PrivateClaims {
///         department: "Toilet Cleaning".to_string(),
///         company: "ACME".to_string(),
///     },
/// };
///
/// let expected_jwt = Compact::new_decoded(Header {
///                                         algorithm: Algorithm::HS256,
///                                         ..Default::default()
///                                     },
///                                     expected_claims.clone());
///
/// let token = expected_jwt
///     .into_encoded(Secret::Bytes("secret".to_string().into_bytes())).unwrap();
/// let token = serde_json::to_string(&token).unwrap();
/// assert_eq!(format!("\"{}\"", expected_token), token);
/// // Now, send `token` to your clients
///
/// // ... some time later, we get token back!
///
/// let token = serde_json::from_str::<Compact<ClaimsSet<PrivateClaims>>>(&token).unwrap();
/// let token = token.into_decoded(Secret::Bytes("secret".to_string().into_bytes()),
///     Algorithm::HS256).unwrap();
/// assert_eq!(*token.payload().unwrap(), expected_claims);
/// # }
/// ```
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Compact<T: CompactJson> {
    /// Decoded form of the JWS.
    /// This variant cannot be serialized or deserialized and will return an error.
    #[serde(skip_serializing)]
    #[serde(skip_deserializing)]
    Decoded {
        /// Embedded header
        header: Header,
        /// Payload, usually a claims set
        payload: T,
    },
    /// Encoded and (optionally) signed JWT. Use this form to send to your clients
    Encoded(String),
}

/// Used in decode: takes the result of a rsplit and ensure we only get 2 parts
/// Errors if we don't
macro_rules! expect_two {
    ($iter:expr) => {{
        let mut i = $iter; // evaluate the expr
        match (i.next(), i.next(), i.next()) {
            (Some(first), Some(second), None) => Ok((first, second)),
            _ => Err(Error::ValidationError(ValidationError::InvalidToken))
        }
    }}
}

impl<T: CompactJson> Compact<T> {
    /// New decoded JWT
    pub fn new_decoded(header: Header, payload: T) -> Self {
        Compact::Decoded {
            header: header,
            payload: payload,
        }
    }

    /// New encoded JWT
    pub fn new_encoded(token: &str) -> Self {
        Compact::Encoded(token.to_string())
    }

    /// Consumes self and convert into encoded form. If the token is already encoded,
    /// this is a no-op.
    // TODO: Is the no-op dangerous? What if the secret between the previous encode and this time is different?
    pub fn into_encoded(self, secret: Secret) -> Result<Self, Error> {
        match self {
            Compact::Encoded(_) => Ok(self),
            Compact::Decoded { .. } => self.encode(secret),
        }
    }

    /// Encode the JWT passed and sign the payload using the algorithm from the header and the secret
    /// The secret is dependent on the signing algorithm
    pub fn encode(&self, secret: Secret) -> Result<Self, Error> {
        match *self {
            Compact::Decoded { ref header, ref payload } => {
                let encoded_header = header.to_base64()?;
                let encoded_claims = payload.to_base64()?;
                let payload = [&*encoded_header, encoded_claims.as_ref()].join(".");
                let signature = header.algorithm
                    .sign(payload.as_bytes(), secret)?
                    .to_base64()?;

                Ok(Compact::Encoded([payload, signature].join(".")))
            }
            Compact::Encoded(_) => Err(Error::UnsupportedOperation),
        }
    }


    /// Consumes self and convert into decoded form, verifying the signature, if any.
    /// If the token is already decoded, this is a no-op.AsMut
    // TODO: Is the no-op dangerous? What if the secret between the previous decode and this time is different?
    pub fn into_decoded(self, secret: Secret, algorithm: Algorithm) -> Result<Self, Error> {
        match self {
            Compact::Encoded(_) => self.decode(secret, algorithm),
            Compact::Decoded { .. } => Ok(self),
        }
    }

    /// Decode a token into the JWT struct and verify its signature
    /// If the token or its signature is invalid, it will return an error
    pub fn decode(&self, secret: Secret, algorithm: Algorithm) -> Result<Self, Error> {
        match *self {
            Compact::Decoded { .. } => Err(Error::UnsupportedOperation),
            Compact::Encoded(ref token) => {
                // Check that there are only two parts
                let (signature, payload) = expect_two!(token.rsplitn(2, '.'))?;
                let signature: Vec<u8> = CompactPart::from_base64(signature.as_bytes())?;

                if !algorithm.verify(signature.as_ref(), payload.as_ref(), secret)? {
                    Err(ValidationError::InvalidSignature)?;
                }

                let (claims, header) = expect_two!(payload.rsplitn(2, '.'))?;

                let header = Header::from_base64(header)?;
                if header.algorithm != algorithm {
                    Err(ValidationError::WrongAlgorithmHeader)?;
                }
                let decoded_claims: T = T::from_base64(claims)?;

                Ok(Self::new_decoded(header, decoded_claims))
            }
        }
    }

    /// Convenience method to extract the encoded string from an encoded compact JWS
    pub fn encoded(&self) -> Result<&str, Error> {
        match *self {
            Compact::Decoded { .. } => Err(Error::UnsupportedOperation),
            Compact::Encoded(ref encoded) => Ok(encoded),
        }
    }

    /// Convenience method to extract the claims set from a decoded compact JWS
    pub fn payload(&self) -> Result<&T, Error> {
        match *self {
            Compact::Decoded { ref payload, .. } => Ok(payload),
            Compact::Encoded(_) => Err(Error::UnsupportedOperation),
        }
    }

    /// Convenience method to extract the header from a decoded compact JWS
    pub fn header(&self) -> Result<&Header, Error> {
        match *self {
            Compact::Decoded { ref header, .. } => Ok(header),
            Compact::Encoded(_) => Err(Error::UnsupportedOperation),
        }
    }
}

impl<T> Clone for Compact<T>
    where T: CompactJson + Clone
{
    fn clone(&self) -> Self {
        match *self {
            Compact::Decoded { ref header, ref payload } => {
                Compact::Decoded {
                    header: (*header).clone(),
                    payload: (*payload).clone(),
                }
            }
            Compact::Encoded(ref encoded) => Compact::Encoded((*encoded).clone()),
        }
    }
}

/// The secrets used to sign and/or encrypt tokens
pub enum Secret {
    /// Used with the `None` algorithm variant.
    None,
    /// Bytes used for HMAC secret. Can be constructed from a string literal
    ///
    /// # Examples
    /// ```
    /// use biscuit::jws::Secret;
    ///
    /// let secret = Secret::bytes_from_str("secret");
    /// ```
    Bytes(Vec<u8>),
    /// An RSA Key pair constructed from a DER-encoded private key
    ///
    /// To generate a private key, use
    ///
    /// ```sh
    /// openssl genpkey -algorithm RSA \
    ///                 -pkeyopt rsa_keygen_bits:2048 \
    ///                 -outform der \
    ///                 -out private_key.der
    /// ```
    ///
    /// Often, keys generated for use in OpenSSL-based software are
    /// encoded in PEM format, which is not supported by *ring*. PEM-encoded
    /// keys that are in `RSAPrivateKey` format can be decoded into the using
    /// an OpenSSL command like this:
    ///
    /// ```sh
    /// openssl rsa -in private_key.pem -outform DER -out private_key.der
    /// ```
    ///
    /// # Examples
    /// ```
    /// use biscuit::jws::Secret;
    ///
    /// let secret = Secret::rsa_keypair_from_file("test/fixtures/rsa_private_key.der");
    /// ```
    RSAKeyPair(Arc<signature::RSAKeyPair>),
    /// Bytes of a DER encoded RSA Public Key
    ///
    /// To generate the public key from your DER-encoded private key
    ///
    /// ```sh
    /// openssl rsa -in private_key.der \
    ///             -inform DER
    ///             -RSAPublicKey_out \
    ///             -outform DER \
    ///             -out public_key.der
    /// ```
    ///
    /// To convert a PEM formatted public key
    ///
    /// ```sh
    /// openssl rsa -RSAPublicKey_in \
    ///             -in public_key.pem \
    ///             -inform PEM \
    ///             -outform DER \
    ///             -RSAPublicKey_out \
    ///             -out public_key.der
    /// ```
    ///
    /// # Examples
    /// ```
    /// use biscuit::jws::Secret;
    ///
    /// let secret = Secret::public_key_from_file("test/fixtures/rsa_public_key.der");
    PublicKey(Vec<u8>),
}

impl Secret {
    fn read_bytes(path: &str) -> Result<Vec<u8>, Error> {
        use std::io::prelude::*;
        use std::fs::File;

        let mut file = File::open(path)?;
        let metadata = file.metadata()?;
        let mut bytes: Vec<u8> = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    /// Convenience function to create a secret bytes array from a string
    /// See example in the [`Secret::Bytes`] variant documentation for usage.
    pub fn bytes_from_str(secret: &str) -> Self {
        Secret::Bytes(secret.to_string().into_bytes())
    }

    /// Convenience function to get the RSA Keypair from a DER encoded RSA private key.
    /// See example in the [`Secret::RSAKeyPair`] variant documentation for usage.
    pub fn rsa_keypair_from_file(path: &str) -> Result<Self, Error> {
        let der = Self::read_bytes(path)?;
        let key_pair = signature::RSAKeyPair::from_der(untrusted::Input::from(der.as_slice()))?;
        Ok(Secret::RSAKeyPair(Arc::new(key_pair)))
    }

    /// Convenience function to create a Public key from a DER encoded RSA or ECDSA public key
    /// See examples in the [`Secret::PublicKey`] variant documentation for usage.
    pub fn public_key_from_file(path: &str) -> Result<Self, Error> {
        let der = Self::read_bytes(path)?;
        Ok(Secret::PublicKey(der.iter().map(|b| b.clone()).collect()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// A basic JWT header part, the alg defaults to HS256 and typ is automatically
/// set to `JWT`. All the other fields are optional.
/// The fields are defined by [RFC7519#5](https://tools.ietf.org/html/rfc7519#section-5) and additionally in
/// [RFC7515#4.1](https://tools.ietf.org/html/rfc7515#section-4.1).
// TODO: Implement verification for registered headers and support custom headers
pub struct Header {
    /// Algorithms, as defined in [RFC 7518](https://tools.ietf.org/html/rfc7518), used to sign or encrypt the JWT
    /// Serialized to `alg`.
    /// Defined in [RFC7515#4.1.1](https://tools.ietf.org/html/rfc7515#section-4.1.1).
    #[serde(rename = "alg")]
    pub algorithm: Algorithm,

    /// Media type of the JWT. Serialized to `typ`.
    /// Defined in [RFC7519#5.1](https://tools.ietf.org/html/rfc7519#section-5.1) and additionally
    /// [RFC7515#4.1.9](https://tools.ietf.org/html/rfc7515#section-4.1.9).
    #[serde(rename = "typ", skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,

    /// Content Type. Typically used to indicate the presence of a nested JWT which is signed or encrypted.
    /// Serialized to `cty`.
    /// Defined in [RFC7519#5.2](https://tools.ietf.org/html/rfc7519#section-5.2) and additionally
    /// [RFC7515#4.1.10](https://tools.ietf.org/html/rfc7515#section-4.1.10).
    #[serde(rename = "cty", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,

    /// The JSON Web Key Set URL. This is currently not implemented (correctly).
    /// Serialized to `jku`.
    /// Defined in [RFC7515#4.1.2](https://tools.ietf.org/html/rfc7515#section-4.1.2).
    #[serde(rename = "jku", skip_serializing_if = "Option::is_none")]
    pub web_key_url: Option<String>,

    /// The JSON Web Key. This is currently not implemented (correctly).
    /// Serialized to `jwk`.
    /// Defined in [RFC7515#4.1.3](https://tools.ietf.org/html/rfc7515#section-4.1.3).
    #[serde(rename = "jwk", skip_serializing_if = "Option::is_none")]
    pub web_key: Option<String>,

    /// The Key ID. This is currently not implemented (correctly).
    /// Serialized to `kid`.
    /// Defined in [RFC7515#4.1.3](https://tools.ietf.org/html/rfc7515#section-4.1.3).
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    /// X.509 Public key cerfificate URL. This is currently not implemented (correctly).
    /// Serialized to `x5u`.
    /// Defined in [RFC7515#4.1.5](https://tools.ietf.org/html/rfc7515#section-4.1.5).
    #[serde(rename = "x5u", skip_serializing_if = "Option::is_none")]
    pub x509_url: Option<String>,

    /// X.509 public key certificate chain. This is currently not implemented (correctly).
    /// Serialized to `x5c`.
    /// Defined in [RFC7515#4.1.6](https://tools.ietf.org/html/rfc7515#section-4.1.6).
    #[serde(rename = "x5c", skip_serializing_if = "Option::is_none")]
    pub x509_chain: Option<Vec<String>>,

    /// X.509 Certificate thumbprint. This is currently not implemented (correctly).
    /// Also not implemented, is the SHA-256 thumbprint variant of this header.
    /// Serialized to `x5t`.
    /// Defined in [RFC7515#4.1.7](https://tools.ietf.org/html/rfc7515#section-4.1.7).
    // TODO: How to make sure the headers are mutually exclusive?
    #[serde(rename = "x5t", skip_serializing_if = "Option::is_none")]
    pub x509_fingerprint: Option<String>,

    /// List of critical extended headers.
    /// This is currently not implemented (correctly).
    /// Also, private headers are not supported at the moment.
    /// Serialized to `crit`.
    /// Defined in [RFC7515#4.1.11](https://tools.ietf.org/html/rfc7515#section-4.1.11).
    #[serde(rename = "crit", skip_serializing_if = "Option::is_none")]
    pub critical: Option<Vec<String>>,
}

impl Default for Header {
    fn default() -> Header {
        Header {
            algorithm: Algorithm::default(),
            media_type: Some("JWT".to_string()),
            content_type: None,
            web_key_url: None,
            web_key: None,
            key_id: None,
            x509_url: None,
            x509_chain: None,
            x509_fingerprint: None,
            critical: None,
        }
    }
}

impl CompactJson for Header {}

#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
/// The algorithms supported for signatures and encryption, defined by [RFC 7518](https://tools.ietf.org/html/rfc7518).
/// Currently, only signing is supported.
// TODO: Add support for `none`
pub enum Algorithm {
    /// No encryption/signature is included for the JWT.
    /// During verification, the signature _MUST BE_ empty or verification  will fail.
    #[serde(rename = "none")]
    None,
    /// HMAC using SHA-256
    HS256,
    /// HMAC using SHA-384
    HS384,
    /// HMAC using SHA-512
    HS512,
    /// RSASSA-PKCS1-v1_5 using SHA-256
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512
    RS512,
    /// ECDSA using P-256 and SHA-256
    ES256,
    /// ECDSA using P-384 and SHA-384
    ES384,
    /// ECDSA using P-521 and SHA-512 --
    /// This variant is [unsupported](https://github.com/briansmith/ring/issues/268) and will probably never be.
    ES512,
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
    /// The size of the salt value is the same size as the hash function output.
    PS256,
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    /// The size of the salt value is the same size as the hash function output.
    PS384,
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    /// The size of the salt value is the same size as the hash function output.
    PS512,
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::HS256
    }
}

impl Algorithm {
    /// Take some bytes and sign it according to the algorithm and secret provided.
    pub fn sign(&self, data: &[u8], secret: Secret) -> Result<Vec<u8>, Error> {
        use self::Algorithm::*;

        match *self {
            None => Self::sign_none(secret),
            HS256 | HS384 | HS512 => Self::sign_hmac(data, secret, self),
            RS256 | RS384 | RS512 | PS256 | PS384 | PS512 => Self::sign_rsa(data, secret, self),
            ES256 | ES384 | ES512 => Self::sign_ecdsa(data, secret, self),
        }
    }

    /// Verify signature based on the algorithm and secret provided.
    pub fn verify(&self, expected_signature: &[u8], data: &[u8], secret: Secret) -> Result<bool, Error> {
        use self::Algorithm::*;

        match *self {
            None => Self::verify_none(expected_signature, secret),
            HS256 | HS384 | HS512 => Self::verify_hmac(expected_signature, data, secret, self),
            RS256 | RS384 | RS512 | PS256 | PS384 | PS512 | ES256 | ES384 | ES512 => {
                Self::verify_public_key(expected_signature, data, secret, self)
            }
        }

    }

    fn sign_none(secret: Secret) -> Result<Vec<u8>, Error> {
        match secret {
            Secret::None => {}
            _ => Err("Invalid secret type. `None` should be provided".to_string())?,
        };
        Ok(vec![])
    }

    fn sign_hmac(data: &[u8], secret: Secret, algorithm: &Algorithm) -> Result<Vec<u8>, Error> {
        let secret = match secret {
            Secret::Bytes(secret) => secret,
            _ => Err("Invalid secret type. A byte array is required".to_string())?,
        };

        let digest = match *algorithm {
            Algorithm::HS256 => &digest::SHA256,
            Algorithm::HS384 => &digest::SHA384,
            Algorithm::HS512 => &digest::SHA512,
            _ => unreachable!("Should not happen"),
        };
        let key = hmac::SigningKey::new(digest, &secret);
        Ok(hmac::sign(&key, data).as_ref().to_vec())
    }

    fn sign_rsa(data: &[u8], secret: Secret, algorithm: &Algorithm) -> Result<Vec<u8>, Error> {
        let key_pair = match secret {
            Secret::RSAKeyPair(key_pair) => key_pair,
            _ => Err("Invalid secret type. A RSAKeyPair is required".to_string())?,
        };
        let mut signing_state = signature::RSASigningState::new(key_pair)?;
        let rng = rand::SystemRandom::new();
        let mut signature = vec![0; signing_state.key_pair().public_modulus_len()];
        let padding_algorithm: &signature::RSAEncoding = match *algorithm {
            Algorithm::RS256 => &signature::RSA_PKCS1_SHA256,
            Algorithm::RS384 => &signature::RSA_PKCS1_SHA384,
            Algorithm::RS512 => &signature::RSA_PKCS1_SHA512,
            Algorithm::PS256 => &signature::RSA_PSS_SHA256,
            Algorithm::PS384 => &signature::RSA_PSS_SHA384,
            Algorithm::PS512 => &signature::RSA_PSS_SHA512,
            _ => unreachable!("Should not happen"),
        };
        signing_state.sign(padding_algorithm, &rng, data, &mut signature)?;
        Ok(signature)
    }

    fn sign_ecdsa(_data: &[u8], _secret: Secret, _algorithm: &Algorithm) -> Result<Vec<u8>, Error> {
        // Not supported at the moment by ring
        // Tracking issues:
        //  - P-256: https://github.com/briansmith/ring/issues/207
        //  - P-384: https://github.com/briansmith/ring/issues/209
        //  - P-521: Probably never: https://github.com/briansmith/ring/issues/268
        Err(Error::UnsupportedOperation)
    }

    fn verify_none(expected_signature: &[u8], secret: Secret) -> Result<bool, Error> {
        match secret {
            Secret::None => {}
            _ => Err("Invalid secret type. `None` should be provided".to_string())?,
        };
        Ok(expected_signature.is_empty())
    }

    fn verify_hmac(expected_signature: &[u8],
                   data: &[u8],
                   secret: Secret,
                   algorithm: &Algorithm)
                   -> Result<bool, Error> {
        let actual_signature = Self::sign_hmac(data, secret, algorithm)?;
        Ok(verify_slices_are_equal(expected_signature.as_ref(), actual_signature.as_ref()).is_ok())
    }

    fn verify_public_key(expected_signature: &[u8],
                         data: &[u8],
                         secret: Secret,
                         algorithm: &Algorithm)
                         -> Result<bool, Error> {
        let public_key = match secret {
            Secret::PublicKey(public_key) => public_key,
            _ => Err("Invalid secret type. A PublicKey is required".to_string())?,
        };
        let public_key_der = untrusted::Input::from(public_key.as_slice());

        let verification_algorithm: &signature::VerificationAlgorithm = match *algorithm {
            Algorithm::RS256 => &signature::RSA_PKCS1_2048_8192_SHA256,
            Algorithm::RS384 => &signature::RSA_PKCS1_2048_8192_SHA384,
            Algorithm::RS512 => &signature::RSA_PKCS1_2048_8192_SHA512,
            Algorithm::PS256 => &signature::RSA_PSS_2048_8192_SHA256,
            Algorithm::PS384 => &signature::RSA_PSS_2048_8192_SHA384,
            Algorithm::PS512 => &signature::RSA_PSS_2048_8192_SHA512,
            Algorithm::ES256 => &signature::ECDSA_P256_SHA256_ASN1,
            Algorithm::ES384 => &signature::ECDSA_P384_SHA384_ASN1,
            Algorithm::ES512 => Err(Error::UnsupportedOperation)?,
            _ => unreachable!("Should not happen"),
        };

        let message = untrusted::Input::from(data);
        let expected_signature = untrusted::Input::from(expected_signature);
        match signature::verify(verification_algorithm,
                                public_key_der,
                                message,
                                expected_signature) {
            Ok(()) => Ok(true),
            Err(e) => {
                println!("{}", e);
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::{self, FromStr};

    use serde_json;

    use {ClaimsSet, RegisteredClaims, SingleOrMultiple, CompactPart, CompactJson};
    use super::{Secret, Algorithm, Header, Compact};

    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    struct PrivateClaims {
        company: String,
        department: String,
    }

    impl CompactJson for PrivateClaims {}

    #[test]
    #[should_panic(expected = "the enum variant Compact::Decoded cannot be serialized")]
    fn decoded_compact_jws_cannot_be_serialized() {
        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com/"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str("htts://acme-customer.com/")))),
                not_before: Some(1234.into()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let biscuit = Compact::new_decoded(Header { algorithm: Algorithm::None, ..Default::default() },
                                           expected_claims.clone());
        serde_json::to_string(&biscuit).unwrap();
    }

    #[test]
    #[should_panic(expected = "data did not match any variant of untagged enum Compact")]
    fn decoded_compact_jws_cannot_be_deserialized() {
        let json = r#"{"header":{"alg":"none","typ":"JWT"},
                       "payload":{"iss":"https://www.acme.com/","sub":"John Doe",
                                     "aud":"htts://acme-customer.com","nbf":1234,
                                     "company":"ACME","department":"Toilet Cleaning"}}"#;
        serde_json::from_str::<Compact<PrivateClaims>>(json).unwrap();
    }

    #[test]
    fn compact_jws_round_trip_none() {
        let expected_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.\
                              eyJpc3MiOiJodHRwczovL3d3dy5hY21lLmNvbS8iLCJzdWIiOiJKb2huIERvZSIsImF1ZCI6Imh0dHM6Ly9\
                              hY21lLWN1c3RvbWVyLmNvbS8iLCJuYmYiOjEyMzQsImNvbXBhbnkiOiJBQ01FIiwiZGVwYXJ0bWVudCI6Il\
                              RvaWxldCBDbGVhbmluZyJ9.";

        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str("htts://acme-customer.com")))),
                not_before: Some(1234.into()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let expected_jwt = Compact::new_decoded(Header { algorithm: Algorithm::None, ..Default::default() },
                                                expected_claims.clone());
        let token = not_err!(expected_jwt.into_encoded(Secret::None));
        assert_eq!(expected_token, not_err!(token.encoded()));

        let biscuit = not_err!(token.into_decoded(Secret::None, Algorithm::None));
        let actual_claims = not_err!(biscuit.payload());
        assert_eq!(expected_claims, *actual_claims);
    }

    #[test]
    fn compact_jws_round_trip_hs256() {
        let expected_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                              eyJpc3MiOiJodHRwczovL3d3dy5hY21lLmNvbS8iLCJzdWIiOiJKb2huIERvZSIsImF1ZCI6Imh0dHM6Ly9hY21lL\
                              WN1c3RvbWVyLmNvbS8iLCJuYmYiOjEyMzQsImNvbXBhbnkiOiJBQ01FIiwiZGVwYXJ0bWVudCI6IlRvaWxldCBDbG\
                              VhbmluZyJ9.dnx1OmRZSFxjCD1ivy4lveTT-sxay5Fq6vY6jnJvqeI";

        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str("htts://acme-customer.com")))),
                not_before: Some(1234.into()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let expected_jwt = Compact::new_decoded(Header { algorithm: Algorithm::HS256, ..Default::default() },
                                                expected_claims.clone());
        let token = not_err!(expected_jwt.into_encoded(Secret::Bytes("secret".to_string().into_bytes())));
        assert_eq!(expected_token, not_err!(token.encoded()));

        let biscuit = not_err!(token.into_decoded(Secret::Bytes("secret".to_string().into_bytes()),
                                                  Algorithm::HS256));
        assert_eq!(expected_claims, *not_err!(biscuit.payload()));
    }

    #[test]
    fn compact_jws_round_trip_rs256() {
        let expected_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.\
                              eyJpc3MiOiJodHRwczovL3d3dy5hY21lLmNvbS8iLCJzdWIiOiJKb2huIERvZSIsImF1ZCI6Imh0dHM6Ly9hY21lL\
                              WN1c3RvbWVyLmNvbS8iLCJuYmYiOjEyMzQsImNvbXBhbnkiOiJBQ01FIiwiZGVwYXJ0bWVudCI6IlRvaWxldCBDbG\
                              VhbmluZyJ9.THHNGg4AIq2RT30zecAD41is6j1ffGRn6GdK6cpl08esHufG5neJOMTO1fONVykOFgCaJw9jLP7GCd\
                              YumsMKU3434QAQyvLCPklHQWE7VcSFSdsf7skcvuvwPtkMWCGrzFK7seVv9OiJzjNzoeyS2d8io7wviFqkpcXwOVZ\
                              W4ArP5katX4nIoXlwWfcK82E6MacSIL2uq_ha6yL2z7trq3dSszSnUevlWKq-9FIFk11XwToMTmGubkWyGk-k-dfH\
                              AXwnS1hADXkwSAemWoCG98v6zFtTZHOOAPnB09acEKVtVRFKZQa3V2IpdsHtRoPJU5pFgCXi8VRebHJm99yTXw";

        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str("htts://acme-customer.com")))),
                not_before: Some(1234.into()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };
        let private_key = Secret::rsa_keypair_from_file("test/fixtures/rsa_private_key.der").unwrap();

        let expected_jwt = Compact::new_decoded(Header { algorithm: Algorithm::RS256, ..Default::default() },
                                                expected_claims.clone());
        let token = not_err!(expected_jwt.into_encoded(private_key));
        assert_eq!(expected_token, not_err!(token.encoded()));

        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let biscuit = not_err!(token.into_decoded(public_key, Algorithm::RS256));
        assert_eq!(expected_claims, *not_err!(biscuit.payload()));
    }

    #[test]
    fn compact_jws_encode_with_additional_header_fields() {
        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str("htts://acme-customer.com")))),
                not_before: Some(1234.into()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let mut header = Header::default();
        header.key_id = Some("kid".to_string());

        let expected_jwt = Compact::new_decoded(header.clone(), expected_claims);
        let token = not_err!(expected_jwt.into_encoded(Secret::Bytes("secret".to_string().into_bytes())));
        let biscuit = not_err!(token.into_decoded(Secret::Bytes("secret".to_string().into_bytes()),
                                                  Algorithm::HS256));
        assert_eq!(header, *not_err!(biscuit.header()));
    }

    #[test]
    #[should_panic(expected = "InvalidToken")]
    fn compact_jws_decode_token_missing_parts() {
        let token = Compact::<PrivateClaims>::new_encoded("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        let claims = token.decode(Secret::Bytes("secret".to_string().into_bytes()),
                                  Algorithm::HS256);
        claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn compact_jws_decode_token_invalid_signature_hs256() {
        let token = Compact::<PrivateClaims>::new_encoded("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                                                       eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.\
                                                       pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI");
        let claims = token.decode(Secret::Bytes("secret".to_string().into_bytes()),
                                  Algorithm::HS256);
        claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn compact_jws_decode_token_invalid_signature_rs256() {
        let token = Compact::<PrivateClaims>::new_encoded("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                                                       eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.\
                                                       pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI");
        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let claims = token.decode(public_key, Algorithm::RS256);
        claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn compact_jws_decode_token_wrong_algorithm() {
        let token = Compact::<PrivateClaims>::new_encoded("eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.\
                                                       eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.\
                                                       pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI");
        let claims = token.decode(Secret::Bytes("secret".to_string().into_bytes()),
                                  Algorithm::HS256);
        claims.unwrap();
    }

    #[test]
    fn header_serialization_round_trip_no_optional() {
        let expected = Header::default();
        let expected_json = r#"{"alg":"HS256","typ":"JWT"}"#;

        let encoded = not_err!(serde_json::to_string(&expected));
        assert_eq!(expected_json, encoded);

        let decoded: Header = not_err!(serde_json::from_str(&encoded));
        assert_eq!(decoded, expected);
    }

    #[test]
    fn header_serialization_round_trip_with_optional() {
        let mut expected = Header::default();
        expected.key_id = Some("kid".to_string());

        let expected_json = r#"{"alg":"HS256","typ":"JWT","kid":"kid"}"#;

        let encoded = not_err!(serde_json::to_string(&expected));
        assert_eq!(expected_json, encoded);

        let decoded: Header = not_err!(serde_json::from_str(&encoded));
        assert_eq!(decoded, expected);
    }

    #[test]
    fn sign_and_verify_none() {
        let expected_signature: Vec<u8> = vec![];
        let actual_signature = not_err!(Algorithm::None.sign("payload".to_string().as_bytes(), Secret::None));
        assert_eq!(expected_signature, actual_signature);

        let valid = not_err!(Algorithm::None.verify(vec![].as_slice(),
                                                    "payload".to_string().as_bytes(),
                                                    Secret::None));
        assert!(valid);
    }

    #[test]
    fn sign_and_verify_hs256() {
        let expected_base64 = "uC_LeRrOxXhZuYm0MKgmSIzi5Hn9-SMmvQoug3WkK6Q";
        let expected_bytes: Vec<u8> = not_err!(CompactPart::from_base64(expected_base64));

        let actual_signature = not_err!(Algorithm::HS256.sign("payload".to_string().as_bytes(),
                                                              Secret::bytes_from_str("secret")));
        assert_eq!(not_err!(actual_signature.to_base64()), expected_base64);

        let valid = not_err!(Algorithm::HS256.verify(expected_bytes.as_slice(),
                                                     "payload".to_string().as_bytes(),
                                                     Secret::bytes_from_str("secret")));
        assert!(valid);
    }

    /// To generate the signature, use
    ///
    /// ```sh
    /// echo -n "payload" | openssl dgst -sha256 -sign test/fixtures/rsa_private_key.pem | base64
    /// ```
    ///
    /// The base64 encoding from this command will be in `STANDARD` form and not URL_SAFE.
    #[test]
    fn sign_and_verify_rs256() {
        let private_key = Secret::rsa_keypair_from_file("test/fixtures/rsa_private_key.der").unwrap();
        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();
        // This is standard base64
        let expected_signature = "JIHqiBfUknrFPDLT0gxyoufD06S43ZqWN_PzQqHZqQ-met7kZmkSTYB_rUyotLMxlKkuXdnvKmWm\
                                  dwGAHWEwDvb5392pCmAAtmUIl6LormxJptWYb2PoF5jmtX_lwV8y4RYIh54Ai51162VARQCKAsxL\
                                  uH772MEChkcpjd31NWzaePWoi_IIk11iqy6uFWmbLLwzD_Vbpl2C6aHR3vQjkXZi05gA3zksjYAh\
                                  j-m7GgBt0UFOE56A4USjhQwpb4g3NEamgp51_kZ2ULi4Aoo_KJC6ynIm_pR6rEzBgwZjlCUnE-6o\
                                  5RPQZ8Oau03UDVH2EwZe-Q91LaWRvkKjGg5Tcw";
        let expected_signature_bytes: Vec<u8> = not_err!(CompactPart::from_base64(expected_signature));

        let actual_signature = not_err!(Algorithm::RS256.sign(payload_bytes, private_key));
        assert_eq!(not_err!(actual_signature.to_base64()), expected_signature);

        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let valid = not_err!(Algorithm::RS256.verify(expected_signature_bytes.as_slice(),
                                                     payload_bytes,
                                                     public_key));
        assert!(valid);
    }

    /// This signature is non-deterministic.
    #[test]
    fn sign_and_verify_ps256_round_trip() {
        let private_key = Secret::rsa_keypair_from_file("test/fixtures/rsa_private_key.der").unwrap();
        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();

        let actual_signature = not_err!(Algorithm::PS256.sign(payload_bytes, private_key));

        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let valid = not_err!(Algorithm::PS256.verify(actual_signature.as_slice(), payload_bytes, public_key));
        assert!(valid);
    }

    /// To generate a (non-deterministic) signature:
    ///
    /// ```sh
    /// echo -n "payload" | openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 \
    ///    -sign test/fixtures/rsa_private_key.pem | base64
    /// ```
    ///
    /// The base64 encoding from this command will be in `STANDARD` form and not URL_SAFE.
    #[test]
    fn verify_ps256() {
        use data_encoding::base64;

        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();
        let signature = "TiMXtt3Wmv/a/tbLWuJPDlFYMfuKsD7U5lbBUn2mBu8DLMLj1EplEZNmkB8w65BgUijnu9hxmhwv\
                         ET2k7RrsYamEst6BHZf20hIK1yE/YWaktbVmAZwUDdIpXYaZn8ukTsMT06CDrVk6RXF0EPMaSL33\
                         tFNPZpz4/3pYQdxco/n6DpaR5206wsur/8H0FwoyiFKanhqLb1SgZqyc+SXRPepjKc28wzBnfWl4\
                         mmlZcJ2xk8O2/t1Y1/m/4G7drBwOItNl7EadbMVCetYnc9EILv39hjcL9JvaA9q0M2RB75DIu8SF\
                         9Kr/l+wzUJjWAHthgqSBpe15jLkpO8tvqR89fw==";
        let signature_bytes: Vec<u8> = not_err!(base64::decode(signature.as_bytes()));
        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let valid = not_err!(Algorithm::PS256.verify(signature_bytes.as_slice(), payload_bytes, public_key));
        assert!(valid);
    }

    #[test]
    #[should_panic(expected = "UnsupportedOperation")]
    fn sign_ecdsa() {
        let private_key = Secret::Bytes("secret".to_string().into_bytes()); // irrelevant
        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();

        Algorithm::ES256.sign(payload_bytes, private_key).unwrap();
    }

    /// Test case from https://github.com/briansmith/ring/blob/c5b8113/src/ec/suite_b/ecdsa_verify_tests.txt#L248
    #[test]
    fn verify_es256() {
        use data_encoding::hex;

        let payload = "sample".to_string();
        let payload_bytes = payload.as_bytes();
        let public_key = "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E9562\
                          8BC64F2F1B20C2D7E9F5177A3C294D4462299";
        let public_key = Secret::PublicKey(not_err!(hex::decode(public_key.as_bytes())));
        let signature = "3046022100EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716022100F7CB1C942D657C\
                         41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8";
        let signature_bytes: Vec<u8> = not_err!(hex::decode(signature.as_bytes()));
        let valid = not_err!(Algorithm::ES256.verify(signature_bytes.as_slice(), payload_bytes, public_key));
        assert!(valid);
    }

    /// Test case from https://github.com/briansmith/ring/blob/c5b8113/src/ec/suite_b/ecdsa_verify_tests.txt#L283
    #[test]
    fn verify_es384() {
        use data_encoding::hex;

        let payload = "sample".to_string();
        let payload_bytes = payload.as_bytes();
        let public_key = "04EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A25451548\
                          0BC138015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD25\
                          33264720";
        let public_key = Secret::PublicKey(not_err!(hex::decode(public_key.as_bytes())));
        let signature = "306602310094EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36\
                         DD1E80FABE4602310099EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E\
                         679E7B82C71A38628AC8";
        let signature_bytes: Vec<u8> = not_err!(hex::decode(signature.as_bytes()));
        let valid = not_err!(Algorithm::ES384.verify(signature_bytes.as_slice(), payload_bytes, public_key));
        assert!(valid);
    }

    #[test]
    #[should_panic(expected = "UnsupportedOperation")]
    fn verify_es512() {
        let payload: Vec<u8> = vec![];
        let signature: Vec<u8> = vec![];
        let public_key = Secret::PublicKey(vec![]);
        Algorithm::ES512.verify(signature.as_slice(), payload.as_slice(), public_key).unwrap();
    }

    #[test]
    fn invalid_none() {
        let invalid_signature = "broken".to_string();
        let signature_bytes = invalid_signature.as_bytes();
        let valid = not_err!(Algorithm::None.verify(signature_bytes,
                                                    "payload".to_string().as_bytes(),
                                                    Secret::None));
        assert!(!valid);
    }

    #[test]
    fn invalid_hs256() {
        let invalid_signature = "broken".to_string();
        let signature_bytes = invalid_signature.as_bytes();
        let valid = not_err!(Algorithm::HS256.verify(signature_bytes,
                                                     "payload".to_string().as_bytes(),
                                                     Secret::Bytes("secret".to_string().into_bytes())));
        assert!(!valid);
    }

    #[test]
    fn invalid_rs256() {
        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let invalid_signature = "broken".to_string();
        let signature_bytes = invalid_signature.as_bytes();
        let valid = not_err!(Algorithm::RS256.verify(signature_bytes,
                                                     "payload".to_string().as_bytes(),
                                                     public_key));
        assert!(!valid);
    }

    #[test]
    fn invalid_ps256() {
        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let invalid_signature = "broken".to_string();
        let signature_bytes = invalid_signature.as_bytes();
        let valid = not_err!(Algorithm::PS256.verify(signature_bytes,
                                                     "payload".to_string().as_bytes(),
                                                     public_key));
        assert!(!valid);
    }

    #[test]
    fn invalid_es256() {
        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let invalid_signature = "broken".to_string();
        let signature_bytes = invalid_signature.as_bytes();
        let valid = not_err!(Algorithm::ES256.verify(signature_bytes,
                                                     "payload".to_string().as_bytes(),
                                                     public_key));
        assert!(!valid);
    }
}
