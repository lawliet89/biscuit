//! JSON Web Signatures, including JWT signing and headers
//!
//! Defined in [RFC 7515](https://tools.ietf.org/html/rfc7515)
use std::sync::Arc;
use std::str;

use ring::signature;
use serde::{self, Serialize, Deserialize};
use serde_json;
use untrusted;

use {CompactJson, CompactPart, Empty};
use errors::{Error, ValidationError};
use jwa::SignatureAlgorithm;
use serde_custom;

/// Compact representation of a JWS
///
/// This representation contains a payload (type `T`) (e.g. a claims set) and is (optionally) signed. This is the
/// most common form of tokens used. The JWS can contain additional header fields provided by type `H`.
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
/// use biscuit::jwa::*;
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
/// let signing_secret = Secret::Bytes("secret".to_string().into_bytes());
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
/// let expected_jwt = jws::Compact::new_decoded(From::from(
///                                                 RegisteredHeader {
///                                                 algorithm: SignatureAlgorithm::HS256,
///                                                 ..Default::default()
///                                             }),
///                                             expected_claims.clone());
///
/// let token = expected_jwt
///     .into_encoded(&signing_secret).unwrap();
/// let token = serde_json::to_string(&token).unwrap();
/// assert_eq!(format!("\"{}\"", expected_token), token);
/// // Now, send `token` to your clients
///
/// // ... some time later, we get token back!
///
/// let token = serde_json::from_str::<jws::Compact<ClaimsSet<PrivateClaims>, Empty>>(&token).unwrap();
/// let token = token.into_decoded(&signing_secret,
///     SignatureAlgorithm::HS256).unwrap();
/// assert_eq!(*token.payload().unwrap(), expected_claims);
/// # }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Compact<T: CompactPart, H: Serialize + Deserialize + 'static> {
    /// Decoded form of the JWS.
    /// This variant cannot be serialized or deserialized and will return an error.
    #[serde(skip_serializing)]
    #[serde(skip_deserializing)]
    Decoded {
        /// Embedded header
        header: Header<H>,
        /// Payload, usually a claims set
        payload: T,
    },
    /// Encoded and (optionally) signed JWT. Use this form to send to your clients
    Encoded(::Compact),
}

impl<T: CompactPart, H: Serialize + Deserialize + 'static> Compact<T, H> {
    /// New decoded JWT
    pub fn new_decoded(header: Header<H>, payload: T) -> Self {
        Compact::Decoded {
            header: header,
            payload: payload,
        }
    }

    /// New encoded JWT
    pub fn new_encoded(token: &str) -> Self {
        Compact::Encoded(::Compact::decode(token))
    }

    /// Consumes self and convert into encoded form. If the token is already encoded,
    /// this is a no-op.
    // TODO: Is the no-op dangerous? What if the secret between the previous encode and this time is different?
    pub fn into_encoded(self, secret: &Secret) -> Result<Self, Error> {
        match self {
            Compact::Encoded(_) => Ok(self),
            Compact::Decoded { .. } => self.encode(secret),
        }
    }

    /// Encode the JWT passed and sign the payload using the algorithm from the header and the secret
    /// The secret is dependent on the signing algorithm
    pub fn encode(&self, secret: &Secret) -> Result<Self, Error> {
        match *self {
            Compact::Decoded {
                ref header,
                ref payload,
            } => {
                let mut compact = ::Compact::with_capacity(3);
                compact.push(header)?;
                compact.push(payload)?;
                let encoded_payload = compact.encode();
                let signature = header
                    .registered
                    .algorithm
                    .sign(encoded_payload.as_bytes(), secret)?;
                compact.push(&signature)?;
                Ok(Compact::Encoded(compact))
            }
            Compact::Encoded(_) => Err(Error::UnsupportedOperation),
        }
    }

    /// Consumes self and convert into decoded form, verifying the signature, if any.
    /// If the token is already decoded, this is a no-op
    // TODO: Is the no-op dangerous? What if the secret between the previous decode and this time is different?
    pub fn into_decoded(self, secret: &Secret, algorithm: SignatureAlgorithm) -> Result<Self, Error> {
        match self {
            Compact::Encoded(_) => self.decode(secret, algorithm),
            Compact::Decoded { .. } => Ok(self),
        }
    }

    /// Decode a token into the JWT struct and verify its signature
    /// If the token or its signature is invalid, it will return an error
    pub fn decode(&self, secret: &Secret, algorithm: SignatureAlgorithm) -> Result<Self, Error> {
        match *self {
            Compact::Decoded { .. } => Err(Error::UnsupportedOperation),
            Compact::Encoded(ref encoded) => {
                if encoded.len() != 3 {
                    Err(ValidationError::PartsLengthError {
                            actual: encoded.len(),
                            expected: 3,
                        })?
                }

                let signature: Vec<u8> = encoded.part(2)?;
                let payload = &encoded.parts[0..2].join(".").to_string();

                if !algorithm
                        .verify(signature.as_ref(), payload.as_ref(), secret)? {
                    Err(ValidationError::InvalidSignature)?;
                }

                let header: Header<H> = encoded.part(0)?;
                if header.registered.algorithm != algorithm {
                    Err(ValidationError::WrongAlgorithmHeader)?;
                }
                let decoded_claims: T = encoded.part(1)?;

                Ok(Self::new_decoded(header, decoded_claims))
            }
        }
    }

    /// Convenience method to get a reference to the encoded string from an encoded compact JWS
    pub fn encoded(&self) -> Result<&::Compact, Error> {
        match *self {
            Compact::Decoded { .. } => Err(Error::UnsupportedOperation),
            Compact::Encoded(ref encoded) => Ok(encoded),
        }
    }

    /// Convenience method to get a mutable reference to the encoded string from an encoded compact JWS
    pub fn encoded_mut(&mut self) -> Result<&mut ::Compact, Error> {
        match *self {
            Compact::Decoded { .. } => Err(Error::UnsupportedOperation),
            Compact::Encoded(ref mut encoded) => Ok(encoded),
        }
    }

    /// Convenience method to get a reference to the claims set from a decoded compact JWS
    pub fn payload(&self) -> Result<&T, Error> {
        match *self {
            Compact::Decoded { ref payload, .. } => Ok(payload),
            Compact::Encoded(_) => Err(Error::UnsupportedOperation),
        }
    }

    /// Convenience method to get a reference to the claims set from a decoded compact JWS
    pub fn payload_mut(&mut self) -> Result<&mut T, Error> {
        match *self {
            Compact::Decoded { ref mut payload, .. } => Ok(payload),
            Compact::Encoded(_) => Err(Error::UnsupportedOperation),
        }
    }

    /// Convenience method to get a reference to the header from a decoded compact JWS
    pub fn header(&self) -> Result<&Header<H>, Error> {
        match *self {
            Compact::Decoded { ref header, .. } => Ok(header),
            Compact::Encoded(_) => Err(Error::UnsupportedOperation),
        }
    }

    /// Convenience method to get a reference to the header from a decoded compact JWS
    pub fn header_mut(&mut self) -> Result<&mut Header<H>, Error> {
        match *self {
            Compact::Decoded { ref mut header, .. } => Ok(header),
            Compact::Encoded(_) => Err(Error::UnsupportedOperation),
        }
    }

    /// Consumes self, and move the payload and header out and return them as a tuple
    ///
    /// # Panics
    /// Panics if the JWS is not decoded
    pub fn unwrap_decoded(self) -> Result<(Header<H>, T), Error> {
        match self {
            Compact::Decoded { header, payload } => Ok((header, payload)),
            Compact::Encoded(_) => panic!("JWS is encoded"),
        }
    }

    /// Consumes self, and move the encoded Compact out and return it
    ///
    /// # Panics
    /// Panics if the JWS is not encoded
    pub fn unwrap_encoded(self) -> Result<::Compact, Error> {
        match self {
            Compact::Decoded { .. } => panic!("JWS is decoded"),
            Compact::Encoded(encoded) => Ok(encoded),
        }
    }
}

/// Implementation for embedded inside a JWE.
// FIXME: Maybe use a separate trait instead?
impl<T: CompactPart, H: Serialize + Deserialize + 'static> CompactPart for Compact<T, H> {
    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let encoded = self.encoded()?;
        Ok(encoded.to_string().into_bytes())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let string = str::from_utf8(bytes)?;
        Ok(Self::new_encoded(string))
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
        Ok(Secret::PublicKey(der.to_vec()))
    }
}

/// JWS Header, consisting of the registered fields and other custom fields
#[derive(Debug, Eq, PartialEq, Clone, Default)]
pub struct Header<T: Serialize + Deserialize> {
    /// Registered header fields
    pub registered: RegisteredHeader,
    /// Private header fields
    pub private: T,
}

impl_flatten_serde_generic!(Header<T>, serde_custom::flatten::DuplicateKeysBehaviour::RaiseError,
                            registered, private);

impl<T: Serialize + Deserialize + 'static> CompactJson for Header<T> {}

impl Header<Empty> {
    /// Convenience function to create a header with only registered headers
    pub fn from_registered_header(registered: RegisteredHeader) -> Self {
        Self {
            registered: registered,
            ..Default::default()
        }
    }
}

impl From<RegisteredHeader> for Header<Empty> {
    fn from(registered: RegisteredHeader) -> Self {
        Self::from_registered_header(registered)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Registered JWS header fields.
/// The alg defaults to HS256 and typ is automatically
/// set to `JWT`. All the other fields are optional.
/// The fields are defined by [RFC7519#5](https://tools.ietf.org/html/rfc7519#section-5) and additionally in
/// [RFC7515#4.1](https://tools.ietf.org/html/rfc7515#section-4.1).
// TODO: Implement verification for registered headers and support custom headers
pub struct RegisteredHeader {
    /// Algorithms, as defined in [RFC 7518](https://tools.ietf.org/html/rfc7518), used to sign or encrypt the JWT
    /// Serialized to `alg`.
    /// Defined in [RFC7515#4.1.1](https://tools.ietf.org/html/rfc7515#section-4.1.1).
    #[serde(rename = "alg")]
    pub algorithm: SignatureAlgorithm,

    /// Media type of the complete JWS. Serialized to `typ`.
    /// Defined in [RFC7519#5.1](https://tools.ietf.org/html/rfc7519#section-5.1) and additionally
    /// [RFC7515#4.1.9](https://tools.ietf.org/html/rfc7515#section-4.1.9).
    /// The "typ" value "JOSE" can be used by applications to indicate that
    /// this object is a JWS or JWE using the JWS Compact Serialization or
    /// the JWE Compact Serialization.  The "typ" value "JOSE+JSON" can be
    /// used by applications to indicate that this object is a JWS or JWE
    /// using the JWS JSON Serialization or the JWE JSON Serialization.
    /// Other type values can also be used by applications.
    #[serde(rename = "typ", skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,

    /// Content Type of the secured payload.
    /// Typically used to indicate the presence of a nested JOSE object which is signed or encrypted.
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
    /// Serialized to `crit`.
    /// Defined in [RFC7515#4.1.11](https://tools.ietf.org/html/rfc7515#section-4.1.11).
    #[serde(rename = "crit", skip_serializing_if = "Option::is_none")]
    pub critical: Option<Vec<String>>,
}

impl Default for RegisteredHeader {
    fn default() -> RegisteredHeader {
        RegisteredHeader {
            algorithm: SignatureAlgorithm::default(),
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

#[cfg(test)]
mod tests {
    use std::str::{self, FromStr};

    use serde_json;

    use {Empty, ClaimsSet, RegisteredClaims, SingleOrMultiple, CompactJson};
    use super::{Secret, SignatureAlgorithm, Header, RegisteredHeader, Compact};

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

        let biscuit = Compact::new_decoded(From::from(RegisteredHeader {
                                                          algorithm: SignatureAlgorithm::None,
                                                          ..Default::default()
                                                      }),
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
        serde_json::from_str::<Compact<PrivateClaims, Empty>>(json).unwrap();
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

        let expected_jwt = Compact::new_decoded(From::from(RegisteredHeader {
                                                               algorithm: SignatureAlgorithm::None,
                                                               ..Default::default()
                                                           }),
                                                expected_claims.clone());
        let token = not_err!(expected_jwt.into_encoded(&Secret::None));
        assert_eq!(expected_token, not_err!(token.encoded()).to_string());

        let biscuit = not_err!(token.into_decoded(&Secret::None, SignatureAlgorithm::None));
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

        let expected_jwt = Compact::new_decoded(From::from(RegisteredHeader {
                                                               algorithm: SignatureAlgorithm::HS256,
                                                               ..Default::default()
                                                           }),
                                                expected_claims.clone());
        let token = not_err!(expected_jwt.into_encoded(&Secret::Bytes("secret".to_string().into_bytes())));
        assert_eq!(expected_token, not_err!(token.encoded()).to_string());

        let biscuit = not_err!(token.into_decoded(&Secret::Bytes("secret".to_string().into_bytes()),
                                                  SignatureAlgorithm::HS256));
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

        let expected_jwt = Compact::new_decoded(From::from(RegisteredHeader {
                                                               algorithm: SignatureAlgorithm::RS256,
                                                               ..Default::default()
                                                           }),
                                                expected_claims.clone());
        let token = not_err!(expected_jwt.into_encoded(&private_key));
        assert_eq!(expected_token, not_err!(token.encoded()).to_string());

        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let biscuit = not_err!(token.into_decoded(&public_key, SignatureAlgorithm::RS256));
        assert_eq!(expected_claims, *not_err!(biscuit.payload()));
    }

    #[test]
    fn compact_jws_encode_with_additional_header_fields() {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        struct CustomHeader {
            something: String,
        }

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

        let header = Header {
            registered: Default::default(),
            private: CustomHeader { something: "foobar".to_string() },
        };

        let expected_jwt = Compact::new_decoded(header.clone(), expected_claims);
        let token = not_err!(expected_jwt.into_encoded(&Secret::Bytes("secret".to_string().into_bytes())));
        let biscuit = not_err!(token.into_decoded(&Secret::Bytes("secret".to_string().into_bytes()),
                                                  SignatureAlgorithm::HS256));
        assert_eq!(header, *not_err!(biscuit.header()));
    }

    #[test]
    #[should_panic(expected = "PartsLengthError { expected: 3, actual: 1 }")]
    fn compact_jws_decode_token_missing_parts() {
        let token = Compact::<PrivateClaims, Empty>::new_encoded("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        let claims = token.decode(&Secret::Bytes("secret".to_string().into_bytes()),
                                  SignatureAlgorithm::HS256);
        claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn compact_jws_decode_token_invalid_signature_hs256() {
        let token = Compact::<PrivateClaims, Empty>::new_encoded("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                                                                    eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.\
                                                                    pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI");
        let claims = token.decode(&Secret::Bytes("secret".to_string().into_bytes()),
                                  SignatureAlgorithm::HS256);
        claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn compact_jws_decode_token_invalid_signature_rs256() {
        let token = Compact::<PrivateClaims, Empty>::new_encoded("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                                                       eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.\
                                                       pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI");
        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let claims = token.decode(&public_key, SignatureAlgorithm::RS256);
        claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn compact_jws_decode_token_wrong_algorithm() {
        let token = Compact::<PrivateClaims, Empty>::new_encoded("eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.\
                                                       eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.\
                                                       pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI");
        let claims = token.decode(&Secret::Bytes("secret".to_string().into_bytes()),
                                  SignatureAlgorithm::HS256);
        claims.unwrap();
    }

    #[test]
    fn compact_jws_round_trip_hs256_for_bytes_payload() {
        let expected_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IlJhbmRvbSBieXRlcyJ9.\
                              eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcG\
                              xlLmNvbS9pc19yb290Ijp0cnVlfQ.E5ahoj_gMO8WZzSUhquWuBkPLGZm18zaLbyHUQA7TIs";
        let payload: Vec<u8> =
            vec![123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101,
                                    120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104,
                                    116, 116, 112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47,
                                    105, 115, 95, 114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125];

        let expected_jwt = Compact::new_decoded(From::from(RegisteredHeader {
                                                               algorithm: SignatureAlgorithm::HS256,
                                                               content_type: Some("Random bytes".to_string()),
                                                               ..Default::default()
                                                           }),
                                                payload.clone());
        let token = not_err!(expected_jwt.into_encoded(&Secret::Bytes("secret".to_string().into_bytes())));
        assert_eq!(expected_token, not_err!(token.encoded()).to_string());

        let biscuit = not_err!(token.into_decoded(&Secret::Bytes("secret".to_string().into_bytes()),
                                                  SignatureAlgorithm::HS256));
        assert_eq!(payload, *not_err!(biscuit.payload()));
    }

    #[test]
    fn header_serialization_round_trip_no_optional() {
        let expected = RegisteredHeader::default();
        let expected_json = r#"{"alg":"HS256","typ":"JWT"}"#;

        let encoded = not_err!(serde_json::to_string(&expected));
        assert_eq!(expected_json, encoded);

        let decoded: RegisteredHeader = not_err!(serde_json::from_str(&encoded));
        assert_eq!(decoded, expected);
    }

    #[test]
    fn header_serialization_round_trip_with_optional() {
        let mut expected = RegisteredHeader::default();
        expected.key_id = Some("kid".to_string());

        let expected_json = r#"{"alg":"HS256","typ":"JWT","kid":"kid"}"#;

        let encoded = not_err!(serde_json::to_string(&expected));
        assert_eq!(expected_json, encoded);

        let decoded: RegisteredHeader = not_err!(serde_json::from_str(&encoded));
        assert_eq!(decoded, expected);
    }
}
