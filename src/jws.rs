//! JSON Web Signatures, including JWT signing and headers
//!
//! Defined in [RFC 7515](https://tools.ietf.org/html/rfc7515). For most common use,
//! you will want to look at the  [`Compact`](enum.Compact.html) enum.
use std::str;
use std::sync::Arc;

use num::BigUint;
use ring::signature;
use serde::de::DeserializeOwned;
use serde::{self, Deserialize, Serialize};

use crate::errors::{DecodeError, Error, ValidationError};
use crate::jwa::{Algorithm, SignatureAlgorithm};
use crate::jwk;
use crate::jwk::{AlgorithmParameters, JWKSet};
use crate::{CompactJson, CompactPart, Empty};

/// Compact representation of a JWS
///
/// This representation contains a payload (type `T`) (e.g. a claims set) and is (optionally) signed. This is the
/// most common form of tokens used. The JWS can contain additional header fields provided by type `H`.
///
/// Serialization/deserialization is handled by serde. Before you transport the token, make sure you
/// turn it into the encoded form first.
///
/// # Examples
/// ## Signing and verifying a JWT with HS256
/// See an example in the [`biscuit::JWT`](../type.JWT.html) type alias.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Compact<T, H> {
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
    Encoded(crate::Compact),
}

impl<T, H> Compact<T, H>
where
    T: CompactPart,
    H: Serialize + DeserializeOwned,
{
    /// New decoded JWT
    pub fn new_decoded(header: Header<H>, payload: T) -> Self {
        Compact::Decoded { header, payload }
    }

    /// New encoded JWT
    pub fn new_encoded(token: &str) -> Self {
        Compact::Encoded(crate::Compact::decode(token))
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
                let mut compact = crate::Compact::with_capacity(3);
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
    pub fn into_decoded(
        self,
        secret: &Secret,
        algorithm: SignatureAlgorithm,
    ) -> Result<Self, Error> {
        match self {
            Compact::Encoded(_) => self.decode(secret, algorithm),
            Compact::Decoded { .. } => Ok(self),
        }
    }

    /// Decode a token into the JWT struct and verify its signature using the concrete Secret
    /// If the token or its signature is invalid, it will return an error
    pub fn decode(&self, secret: &Secret, algorithm: SignatureAlgorithm) -> Result<Self, Error> {
        match *self {
            Compact::Decoded { .. } => Err(Error::UnsupportedOperation),
            Compact::Encoded(ref encoded) => {
                if encoded.len() != 3 {
                    Err(DecodeError::PartsLengthError {
                        actual: encoded.len(),
                        expected: 3,
                    })?
                }

                let signature: Vec<u8> = encoded.part(2)?;
                let payload = &encoded.parts[0..2].join(".");

                algorithm
                    .verify(signature.as_ref(), payload.as_ref(), secret)
                    .map_err(|_| ValidationError::InvalidSignature)?;

                let header: Header<H> = encoded.part(0)?;
                if header.registered.algorithm != algorithm {
                    Err(ValidationError::WrongAlgorithmHeader)?;
                }
                let decoded_claims: T = encoded.part(1)?;

                Ok(Self::new_decoded(header, decoded_claims))
            }
        }
    }

    /// Decode a token into the JWT struct and verify its signature using a JWKS
    ///
    /// If the JWK does not contain an optional algorithm parameter, you will have to specify
    /// the expected algorithm or an error will be returned.
    ///
    /// If the JWK specifies an algorithm and you provide an expected algorithm,
    /// both will be checked for equality. If they do not match, an error will be returned.
    ///
    /// If the token or its signature is invalid, it will return an error
    pub fn decode_with_jwks<J>(
        &self,
        jwks: &JWKSet<J>,
        expected_algorithm: Option<SignatureAlgorithm>,
    ) -> Result<Self, Error> {
        match *self {
            Compact::Decoded { .. } => Err(Error::UnsupportedOperation),
            Compact::Encoded(ref encoded) => {
                if encoded.len() != 3 {
                    Err(DecodeError::PartsLengthError {
                        actual: encoded.len(),
                        expected: 3,
                    })?
                }

                let signature: Vec<u8> = encoded.part(2)?;
                let payload = &encoded.parts[0..2].join(".");

                let header: Header<H> = encoded.part(0)?;
                let key_id = header
                    .registered
                    .key_id
                    .as_ref()
                    .ok_or(ValidationError::KidMissing)?;
                let jwk = jwks.find(key_id).ok_or(ValidationError::KeyNotFound)?;

                let algorithm = match jwk.common.algorithm {
                    Some(jwk_alg) => {
                        let algorithm = match jwk_alg {
                            Algorithm::Signature(algorithm) => algorithm,
                            _ => Err(ValidationError::UnsupportedKeyAlgorithm)?,
                        };

                        if header.registered.algorithm != algorithm {
                            Err(ValidationError::WrongAlgorithmHeader)?;
                        }

                        if let Some(expected_algorithm) = expected_algorithm {
                            if expected_algorithm != algorithm {
                                Err(ValidationError::WrongAlgorithmHeader)?;
                            }
                        }

                        algorithm
                    }
                    None => match expected_algorithm {
                        Some(expected_algorithm) => {
                            if expected_algorithm != header.registered.algorithm {
                                Err(ValidationError::WrongAlgorithmHeader)?;
                            }
                            expected_algorithm
                        }
                        None => Err(ValidationError::MissingAlgorithm)?,
                    },
                };

                let secret = match &jwk.algorithm {
                    AlgorithmParameters::RSA(rsa) => rsa.jws_public_key_secret(),
                    AlgorithmParameters::OctetKey(oct) => Secret::Bytes(oct.value.clone()),
                    _ => Err(ValidationError::UnsupportedKeyAlgorithm)?,
                };

                algorithm
                    .verify(signature.as_ref(), payload.as_ref(), &secret)
                    .map_err(|_| ValidationError::InvalidSignature)?;

                let decoded_claims: T = encoded.part(1)?;

                Ok(Self::new_decoded(header, decoded_claims))
            }
        }
    }

    /// Convenience method to get a reference to the encoded string from an encoded compact JWS
    pub fn encoded(&self) -> Result<&crate::Compact, Error> {
        match *self {
            Compact::Decoded { .. } => Err(Error::UnsupportedOperation),
            Compact::Encoded(ref encoded) => Ok(encoded),
        }
    }

    /// Convenience method to get a mutable reference to the encoded string from an encoded compact JWS
    pub fn encoded_mut(&mut self) -> Result<&mut crate::Compact, Error> {
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
            Compact::Decoded {
                ref mut payload, ..
            } => Ok(payload),
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
    pub fn unwrap_decoded(self) -> (Header<H>, T) {
        match self {
            Compact::Decoded { header, payload } => (header, payload),
            Compact::Encoded(_) => panic!("JWS is encoded"),
        }
    }

    /// Consumes self, and move the encoded Compact out and return it
    ///
    /// # Panics
    /// Panics if the JWS is not encoded
    pub fn unwrap_encoded(self) -> crate::Compact {
        match self {
            Compact::Decoded { .. } => panic!("JWS is decoded"),
            Compact::Encoded(encoded) => encoded,
        }
    }

    /// Without decoding and verifying the JWS, retrieve a copy of the header.
    ///
    /// ## Warning
    /// Use this at your own risk. It is not advisable to trust unverified content.
    pub fn unverified_header(&self) -> Result<Header<H>, Error> {
        match *self {
            Compact::Decoded { .. } => Err(Error::UnsupportedOperation),
            Compact::Encoded(ref compact) => compact.part(0),
        }
    }

    /// Without decoding and verifying the JWS, retrieve a copy of the payload.
    ///
    /// ## Warning
    /// Use this at your own risk. It is not advisable to trust unverified content.
    pub fn unverified_payload(&self) -> Result<T, Error> {
        match *self {
            Compact::Decoded { .. } => Err(Error::UnsupportedOperation),
            Compact::Encoded(ref compact) => compact.part(1),
        }
    }

    /// Get a copy of the signature
    pub fn signature(&self) -> Result<Vec<u8>, Error> {
        match *self {
            Compact::Decoded { .. } => Err(Error::UnsupportedOperation),
            Compact::Encoded(ref compact) => compact.part(2),
        }
    }
}

/// Convenience implementation for a Compact that contains a `ClaimsSet`
impl<'a, P, H> Compact<crate::ClaimsSet<'a, P>, H>
where
    crate::ClaimsSet<'a, P>: CompactPart,
    H: Serialize + DeserializeOwned,
{
    /// Validate the temporal claims in the decoded token
    ///
    /// If `None` is provided for options, the defaults will apply.
    ///
    /// By default, no temporal claims (namely `iat`, `exp`, `nbf`)
    /// are required, and they will pass validation if they are missing.
    pub fn validate(&self, options: crate::ValidationOptions) -> Result<(), Error> {
        self.payload()?.registered.validate(options)?;
        Ok(())
    }
}

/// Implementation for embedded inside a JWE.
// FIXME: Maybe use a separate trait instead?
impl<T: CompactPart, H: Serialize + DeserializeOwned> CompactPart for Compact<T, H> {
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
    RsaKeyPair(Arc<signature::RsaKeyPair>),
    /// An ECDSA Key pair constructed from a PKCS8 DER encoded private key
    ///
    /// To generate a private key, use
    ///
    /// ```sh
    /// openssl ecparam -genkey -name prime256v1 | \
    /// openssl pkcs8 -topk8 -nocrypt -outform DER > ecdsa_private_key.p8
    /// ```
    ///
    /// # Examples
    /// ```
    /// use biscuit::jws::Secret;
    ///
    /// let secret = Secret::ecdsa_keypair_from_file(biscuit::jwa::SignatureAlgorithm::ES256, "test/fixtures/ecdsa_private_key.p8");
    /// ```
    EcdsaKeyPair(Arc<signature::EcdsaKeyPair>),
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
    /// Use the modulus (`n`) and exponent (`e`) of an RSA key directly
    ///
    /// These parameters can be obtained from a JWK directly using
    /// [`jwk::RSAKeyParameters::jws_public_key_secret`]
    RSAModulusExponent {
        /// RSA modulus
        n: BigUint,
        /// RSA exponent
        e: BigUint,
    },
}

impl Secret {
    fn read_bytes(path: &str) -> Result<Vec<u8>, Error> {
        use std::fs::File;
        use std::io::prelude::*;

        let mut file = File::open(path)?;
        let metadata = file.metadata()?;
        let mut bytes: Vec<u8> = Vec::with_capacity(metadata.len() as usize);
        let _ = file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    /// Convenience function to create a secret bytes array from a string
    /// See example in the [`Secret::Bytes`] variant documentation for usage.
    pub fn bytes_from_str(secret: &str) -> Self {
        Secret::Bytes(secret.to_string().into_bytes())
    }

    /// Convenience function to get the RSA Keypair from a DER encoded RSA private key.
    /// See example in the [`Secret::RsaKeyPair`] variant documentation for usage.
    pub fn rsa_keypair_from_file(path: &str) -> Result<Self, Error> {
        let der = Self::read_bytes(path)?;
        let key_pair = signature::RsaKeyPair::from_der(der.as_slice())?;
        Ok(Secret::RsaKeyPair(Arc::new(key_pair)))
    }

    /// Convenience function to get the ECDSA Keypair from a PKCS8-DER encoded EC private key.
    pub fn ecdsa_keypair_from_file(
        algorithm: SignatureAlgorithm,
        path: &str,
    ) -> Result<Self, Error> {
        let der = Self::read_bytes(path)?;
        let ring_algorithm = match algorithm {
            SignatureAlgorithm::ES256 => &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            SignatureAlgorithm::ES384 => &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            _ => return Err(Error::UnsupportedOperation),
        };
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(ring_algorithm, der.as_slice())?;
        Ok(Secret::EcdsaKeyPair(Arc::new(key_pair)))
    }

    /// Convenience function to create a Public key from a DER encoded RSA or ECDSA public key
    /// See examples in the [`Secret::PublicKey`] variant documentation for usage.
    pub fn public_key_from_file(path: &str) -> Result<Self, Error> {
        let der = Self::read_bytes(path)?;
        Ok(Secret::PublicKey(der.to_vec()))
    }
}

impl From<jwk::RSAKeyParameters> for Secret {
    fn from(rsa: jwk::RSAKeyParameters) -> Self {
        rsa.jws_public_key_secret()
    }
}

/// JWS Header, consisting of the registered fields and other custom fields
#[derive(Debug, Eq, PartialEq, Clone, Default, Serialize, Deserialize)]
pub struct Header<T> {
    /// Registered header fields
    #[serde(flatten)]
    pub registered: RegisteredHeader,
    /// Private header fields
    #[serde(flatten)]
    pub private: T,
}

impl<T: Serialize + DeserializeOwned> CompactJson for Header<T> {}

impl Header<Empty> {
    /// Convenience function to create a header with only registered headers
    pub fn from_registered_header(registered: RegisteredHeader) -> Self {
        Self {
            registered,
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

    use serde::{Deserialize, Serialize};

    use super::{Compact, Header, RegisteredHeader, Secret, SignatureAlgorithm};
    use crate::jwk::JWKSet;
    use crate::{ClaimsSet, CompactJson, Empty, RegisteredClaims, SingleOrMultiple};

    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    struct PrivateClaims {
        company: String,
        department: String,
    }

    impl CompactJson for PrivateClaims {}

    // HS256 key - "secret"
    static HS256_PAYLOAD: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
        eyJpc3MiOiJodHRwczovL3d3dy5hY21lLmNvbS8iLCJzdWIiOiJKb2huIERvZSIsImF1ZCI6Imh0dHBzOi8vYWNtZ\
        S1jdXN0b21lci5jb20vIiwibmJmIjoxMjM0LCJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2x\
        lYW5pbmcifQ.VFCl2un1Kc17odzOe2Ehf4DVrWddu3U4Ux3GFpOZHtc";

    #[test]
    #[should_panic(expected = "the enum variant Compact::Decoded cannot be serialized")]
    fn decoded_compact_jws_cannot_be_serialized() {
        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com/"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str(
                    "https://acme-customer.com/"
                )))),
                not_before: Some(1234.into()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let biscuit = Compact::new_decoded(
            From::from(RegisteredHeader {
                algorithm: SignatureAlgorithm::None,
                ..Default::default()
            }),
            expected_claims,
        );
        let _ = serde_json::to_string(&biscuit).unwrap();
    }

    #[test]
    #[should_panic(expected = "data did not match any variant of untagged enum Compact")]
    fn decoded_compact_jws_cannot_be_deserialized() {
        let json = r#"{"header":{"alg":"none","typ":"JWT"},
                       "payload":{"iss":"https://www.acme.com/","sub":"John Doe",
                                     "aud":"https://acme-customer.com/","nbf":1234,
                                     "company":"ACME","department":"Toilet Cleaning"}}"#;
        let _ = serde_json::from_str::<Compact<PrivateClaims, Empty>>(json).unwrap();
    }

    #[test]
    fn compact_jws_round_trip_none() {
        let expected_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.\
            eyJpc3MiOiJodHRwczovL3d3dy5hY21lLmNvbS8iLCJzdWIiOiJKb2huIERvZSIsImF1ZCI6Imh0dHBzOi8vY\
            WNtZS1jdXN0b21lci5jb20vIiwibmJmIjoxMjM0LCJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2l\
            sZXQgQ2xlYW5pbmcifQ.";

        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com/"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str(
                    "https://acme-customer.com/"
                )))),
                not_before: Some(1234.into()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let expected_jwt = Compact::new_decoded(
            From::from(RegisteredHeader {
                algorithm: SignatureAlgorithm::None,
                ..Default::default()
            }),
            expected_claims.clone(),
        );
        let token = not_err!(expected_jwt.into_encoded(&Secret::None));
        assert_eq!(expected_token, not_err!(token.encoded()).to_string());

        let biscuit = not_err!(token.into_decoded(&Secret::None, SignatureAlgorithm::None));
        let actual_claims = not_err!(biscuit.payload());
        assert_eq!(expected_claims, *actual_claims);
    }

    #[test]
    fn compact_jws_round_trip_hs256() {
        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com/"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str(
                    "https://acme-customer.com/"
                )))),
                not_before: Some(1234.into()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let expected_jwt = Compact::new_decoded(
            From::from(RegisteredHeader {
                algorithm: SignatureAlgorithm::HS256,
                ..Default::default()
            }),
            expected_claims.clone(),
        );
        let token =
            not_err!(expected_jwt.into_encoded(&Secret::Bytes("secret".to_string().into_bytes())));
        assert_eq!(HS256_PAYLOAD, not_err!(token.encoded()).to_string());

        let biscuit = not_err!(token.into_decoded(
            &Secret::Bytes("secret".to_string().into_bytes()),
            SignatureAlgorithm::HS256
        ));
        assert_eq!(expected_claims, *not_err!(biscuit.payload()));
    }

    #[test]
    fn compact_jws_round_trip_rs256() {
        let expected_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.\
                              eyJpc3MiOiJodHRwczovL3d3dy5hY21lLmNvbS8iLCJzdWIiOiJKb2huIERvZSIsImF1Z\
                              CI6Imh0dHBzOi8vYWNtZS1jdXN0b21lci5jb20vIiwibmJmIjoxMjM0LCJjb21wYW55Ij\
                              oiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
                              Gat3NBUTaCyvroil66U0nId4-l6VqbtJYIsM9wRbWo45oYoN-NxYIyl8M-9AlEPseg-4SIuo-A-jccJOWGeWWwy-E\
                              en_92wg18II58luHz7vAyclw1maJBKHmuj8f2wE_Ky8ir3iTpTGkJQ3IUU9SuU9Fkvajm4jgWUtRPpjHm_IqyxV8N\
                              kHNyN0p5CqeuRC8sZkOSFkm9b0WnWYRVls1QOjBnN9w9zW9wg9DGwj10pqg8hQ5sy-C3J-9q1zJgGDXInkhPLjitO\
                              9wzWg4yfVt-CJNiHsJT7RY_EN2VmbG8UOjHp8xUPpfqUKyoQttKaQkJHdjP_b47LO4ZKI4UivlA";

        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com/"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str(
                    "https://acme-customer.com/"
                )))),
                not_before: Some(1234.into()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };
        let private_key =
            Secret::rsa_keypair_from_file("test/fixtures/rsa_private_key.der").unwrap();

        let expected_jwt = Compact::new_decoded(
            From::from(RegisteredHeader {
                algorithm: SignatureAlgorithm::RS256,
                ..Default::default()
            }),
            expected_claims.clone(),
        );
        let token = not_err!(expected_jwt.into_encoded(&private_key));
        assert_eq!(expected_token, not_err!(token.encoded()).to_string());

        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let biscuit = not_err!(token.into_decoded(&public_key, SignatureAlgorithm::RS256));
        assert_eq!(expected_claims, *not_err!(biscuit.payload()));
    }

    #[test]
    fn compact_jws_verify_es256() {
        use data_encoding::HEXUPPER;

        // This is a ECDSA Public key in `SubjectPublicKey` form.
        // Conversion is not available in `ring` yet.
        // See https://github.com/lawliet89/biscuit/issues/71#issuecomment-296445140 for a
        // way to retrieve it from `SubjectPublicKeyInfo`.
        let public_key =
            "043727F96AAD416887DD75CC2E333C3D8E06DCDF968B6024579449A2B802EFC891F638C75\
             1CF687E6FF9A280E11B7036585E60CA32BB469C3E57998A289E0860A6";
        let jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.\
                   eyJ0b2tlbl90eXBlIjoic2VydmljZSIsImlhdCI6MTQ5MjkzODU4OH0.\
                   do_XppIOFthPWlTXL95CIBfgRdyAxbcIsUfM0YxMjCjqvp4ehHFA3I-JasABKzC8CAy4ndhCHsZdpAtK\
                   kqZMEA";
        let signing_secret = Secret::PublicKey(not_err!(HEXUPPER.decode(public_key.as_bytes())));

        let token = Compact::<ClaimsSet<serde_json::Value>, Empty>::new_encoded(jwt);
        let _ = not_err!(token.into_decoded(&signing_secret, SignatureAlgorithm::ES256));
    }

    #[test]
    fn compact_jws_encode_with_additional_header_fields() {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        struct CustomHeader {
            something: String,
        }

        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com/"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str(
                    "https://acme-customer.com/"
                )))),
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
            private: CustomHeader {
                something: "foobar".to_string(),
            },
        };

        let expected_jwt = Compact::new_decoded(header.clone(), expected_claims);
        let token =
            not_err!(expected_jwt.into_encoded(&Secret::Bytes("secret".to_string().into_bytes())));
        let biscuit = not_err!(token.into_decoded(
            &Secret::Bytes("secret".to_string().into_bytes()),
            SignatureAlgorithm::HS256
        ));
        assert_eq!(header, *not_err!(biscuit.header()));
    }

    #[test]
    #[should_panic(expected = "PartsLengthError { expected: 3, actual: 1 }")]
    fn compact_jws_decode_token_missing_parts() {
        let token =
            Compact::<PrivateClaims, Empty>::new_encoded("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        let claims = token.decode(
            &Secret::Bytes("secret".to_string().into_bytes()),
            SignatureAlgorithm::HS256,
        );
        let _ = claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn compact_jws_decode_token_invalid_signature_hs256() {
        let token = Compact::<PrivateClaims, Empty>::new_encoded(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
             eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.\
             pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI",
        );
        let claims = token.decode(
            &Secret::Bytes("secret".to_string().into_bytes()),
            SignatureAlgorithm::HS256,
        );
        let _ = claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn compact_jws_decode_token_invalid_signature_rs256() {
        let token = Compact::<PrivateClaims, Empty>::new_encoded(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
             eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.\
             pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI",
        );
        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let claims = token.decode(&public_key, SignatureAlgorithm::RS256);
        let _ = claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn compact_jws_decode_token_wrong_algorithm() {
        let token = Compact::<PrivateClaims, Empty>::new_encoded(
            "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.\
             eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.\
             pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI",
        );
        let claims = token.decode(
            &Secret::Bytes("secret".to_string().into_bytes()),
            SignatureAlgorithm::HS256,
        );
        let _ = claims.unwrap();
    }

    #[test]
    fn compact_jws_round_trip_hs256_for_bytes_payload() {
        let expected_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IlJhbmRvbSBieXRlcyJ9.\
             eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcG\
             xlLmNvbS9pc19yb290Ijp0cnVlfQ.E5ahoj_gMO8WZzSUhquWuBkPLGZm18zaLbyHUQA7TIs";
        let payload: Vec<u8> = vec![
            123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120,
            112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116,
            112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95,
            114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125,
        ];

        let expected_jwt = Compact::new_decoded(
            From::from(RegisteredHeader {
                algorithm: SignatureAlgorithm::HS256,
                content_type: Some("Random bytes".to_string()),
                ..Default::default()
            }),
            payload.clone(),
        );
        let token =
            not_err!(expected_jwt.into_encoded(&Secret::Bytes("secret".to_string().into_bytes())));
        assert_eq!(expected_token, not_err!(token.encoded()).to_string());

        let biscuit = not_err!(token.into_decoded(
            &Secret::Bytes("secret".to_string().into_bytes()),
            SignatureAlgorithm::HS256
        ));
        assert_eq!(payload, *not_err!(biscuit.payload()));
    }

    #[test]
    fn compact_jws_decode_with_jwks_shared_secret() {
        let token = Compact::<PrivateClaims, Empty>::new_encoded(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
            &r#"{
            "keys": [
                        {
                            "kty": "oct",
                            "use": "sig",
                            "kid": "key0",
                            "k": "-clnNQnBupZt23N8McUcZytLhan9OmjlJXmqS7daoeY",
                            "alg": "HS256"
                        }
            ]
        }"#,
        )
        .unwrap();

        let _ = token.decode_with_jwks(&jwks, None).expect("to succeed");
    }

    /// JWK has algorithm and user provided a matching expected algorithm
    #[test]
    fn compact_jws_decode_with_jwks_shared_secret_matching_alg() {
        let token = Compact::<PrivateClaims, Empty>::new_encoded(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
            &r#"{
            "keys": [
                        {
                            "kty": "oct",
                            "use": "sig",
                            "kid": "key0",
                            "k": "-clnNQnBupZt23N8McUcZytLhan9OmjlJXmqS7daoeY",
                            "alg": "HS256"
                        }
            ]
        }"#,
        )
        .unwrap();

        let _ = token
            .decode_with_jwks(&jwks, Some(SignatureAlgorithm::HS256))
            .expect("to succeed");
    }

    /// JWK has algorithm and user provided a non-matching expected algorithm
    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn compact_jws_decode_with_jwks_shared_secret_mismatched_alg() {
        let token = Compact::<PrivateClaims, Empty>::new_encoded(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
            &r#"{
            "keys": [
                        {
                            "kty": "oct",
                            "use": "sig",
                            "kid": "key0",
                            "k": "-clnNQnBupZt23N8McUcZytLhan9OmjlJXmqS7daoeY",
                            "alg": "HS256"
                        }
            ]
        }"#,
        )
        .unwrap();

        let _ = token
            .decode_with_jwks(&jwks, Some(SignatureAlgorithm::RS256))
            .unwrap();
    }

    /// JWK has no algorithm and user provided a header matching expected algorithm
    #[test]
    fn compact_jws_decode_with_jwks_without_alg() {
        let token = Compact::<PrivateClaims, Empty>::new_encoded(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
            &r#"{
            "keys": [
                        {
                            "kty": "oct",
                            "use": "sig",
                            "kid": "key0",
                            "k": "-clnNQnBupZt23N8McUcZytLhan9OmjlJXmqS7daoeY"
                        }
            ]
        }"#,
        )
        .unwrap();

        let _ = token
            .decode_with_jwks(&jwks, Some(SignatureAlgorithm::HS256))
            .expect("to succeed");
    }

    /// JWK has no algorithm and user provided a header not-matching expected algorithm
    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn compact_jws_decode_with_jwks_without_alg_non_matching() {
        let token = Compact::<PrivateClaims, Empty>::new_encoded(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
            &r#"{
            "keys": [
                        {
                            "kty": "oct",
                            "use": "sig",
                            "kid": "key0",
                            "k": "-clnNQnBupZt23N8McUcZytLhan9OmjlJXmqS7daoeY"
                        }
            ]
        }"#,
        )
        .unwrap();

        let _ = token
            .decode_with_jwks(&jwks, Some(SignatureAlgorithm::RS256))
            .unwrap();
    }

    /// JWK has no algorithm and user did not provide any expected algorithm
    #[test]
    #[should_panic(expected = "MissingAlgorithm")]
    fn compact_jws_decode_with_jwks_missing_alg() {
        let token = Compact::<PrivateClaims, Empty>::new_encoded(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
            &r#"{
            "keys": [
                        {
                            "kty": "oct",
                            "use": "sig",
                            "kid": "key0",
                            "k": "-clnNQnBupZt23N8McUcZytLhan9OmjlJXmqS7daoeY"
                        }
            ]
        }"#,
        )
        .unwrap();

        let _ = token.decode_with_jwks(&jwks, None).unwrap();
    }

    #[test]
    fn compact_jws_decode_with_jwks_rsa() {
        let token = Compact::<PrivateClaims, Empty>::new_encoded(
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             MImpi6zezEy0PE5uHU7hM1I0VaNPQx4EAYjEnq2v4gyypmfgKqzrSntSACHZvPsLHDN\
             Ui8PGBM13NcF5IxhybHRM_LVMlMK2rlmQQR7NYueV1psfdSh6fGcYoDxuiZnzybpSxP\
             5Fy8wGe-BgoL5EIPzzhfQBZagzliztLt8RarXHbXnK_KxN1GE5_q5V_ZvjpNr3FExuC\
             cKSvjhlkWR__CmTpv4FWZDkWXJgABLSd0Fe1soUNXMNaqzeTH-xSIYMv06Jckfky6Ds\
             OKcqWyA5QGNScRkSh4fu4jkIiPlituJhFi3hYgIfGTGQMDt2TsiaUCZdfyLhipGwHzmMijeHiQ",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
            &r#"{
            "keys": [
                        {
                            "kty": "RSA",
                            "e": "AQAB",
                            "use": "sig",
                            "kid": "key0",
                            "alg": "RS256",
                            "n": "rx7xQsC4XuzCW1YZwm3JUftsScV3v82VmuuIcmUOBGyLpeChfHwwr61UZOVL6yiFSIoGlS1KbVkyZ5xf8FCQGdRuAYvx2sH4E0D9gOdjAauXIx7ADbG5wfTHqiyYcWezovzdXZb4F7HCaBkaKhtg8FTkTozQz5m6stzcFatcSUZpNM6lCSGoi0kFfucEAV2cNoWUaW1WnYyGB2sxupSIako9updQIHfAqiDSbawO8uBymNjiQJS3evImjLcJajAYzrmK1biSu5uJuw3RReYef3QUvLY9o2T6LV3QiIWi3MeBktjhwAvCKzcOeU34py946AJm6USXkwit_hlFx5DzgQ"
                        }
            ]
        }"#,
        )
        .unwrap();

        let _ = token.decode_with_jwks(&jwks, None).expect("to succeed");
    }

    #[test]
    #[should_panic(expected = "PartsLengthError { expected: 3, actual: 2 }")]
    fn compact_jws_decode_with_jwks_missing_parts() {
        let token = Compact::<PrivateClaims, Empty>::new_encoded(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
            &r#"{
            "keys": [
                        {
                            "kty": "oct",
                            "use": "sig",
                            "kid": "key0",
                            "k": "-clnNQnBupZt23N8McUcZytLhan9OmjlJXmqS7daoeY",
                            "alg": "HS256"
                        }
            ]
        }"#,
        )
        .unwrap();

        let _ = token.decode_with_jwks(&jwks, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn compact_jws_decode_with_jwks_wrong_algorithm() {
        let token = Compact::<PrivateClaims, Empty>::new_encoded(
            "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
            &r#"{
            "keys": [
                        {
                            "kty": "oct",
                            "use": "sig",
                            "kid": "key0",
                            "k": "-clnNQnBupZt23N8McUcZytLhan9OmjlJXmqS7daoeY",
                            "alg": "HS256"
                        }
            ]
        }"#,
        )
        .unwrap();

        let _ = token.decode_with_jwks(&jwks, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "KeyNotFound")]
    fn compact_jws_decode_with_jwks_key_not_found() {
        let token = Compact::<PrivateClaims, Empty>::new_encoded(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
            &r#"{
            "keys": [
                        {
                            "kty": "oct",
                            "use": "sig",
                            "kid": "keyX",
                            "k": "-clnNQnBupZt23N8McUcZytLhan9OmjlJXmqS7daoeY",
                            "alg": "HS256"
                        }
            ]
        }"#,
        )
        .unwrap();

        let _ = token.decode_with_jwks(&jwks, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "KidMissing")]
    fn compact_jws_decode_with_jwks_kid_missing() {
        let token = Compact::<PrivateClaims, Empty>::new_encoded(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             QhdrScTpNXF2d0RbG_UTWu2gPKZfzANj6XC4uh-wOoU",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
            &r#"{
            "keys": [
                        {
                            "kty": "oct",
                            "use": "sig",
                            "kid": "key0",
                            "k": "-clnNQnBupZt23N8McUcZytLhan9OmjlJXmqS7daoeY",
                            "alg": "HS256"
                        }
            ]
        }"#,
        )
        .unwrap();

        let _ = token.decode_with_jwks(&jwks, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "UnsupportedKeyAlgorithm")]
    fn compact_jws_decode_with_jwks_algorithm_not_supported() {
        let token = Compact::<PrivateClaims, Empty>::new_encoded(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
            &r#"{
            "keys": [
                        {
                            "kty": "oct",
                            "use": "sig",
                            "kid": "key0",
                            "k": "-clnNQnBupZt23N8McUcZytLhan9OmjlJXmqS7daoeY",
                            "alg": "A128CBC-HS256"
                        }
            ]
        }"#,
        )
        .unwrap();

        let _ = token.decode_with_jwks(&jwks, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "UnsupportedKeyAlgorithm")]
    fn compact_jws_decode_with_jwks_key_type_not_supported() {
        let token = Compact::<PrivateClaims, Empty>::new_encoded(
            "eyJhbGciOiAiRVMyNTYiLCJ0eXAiOiAiSldUIiwia2lkIjogImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
            &r#"{
            "keys": [
                {
                    "kty": "EC",
                    "d": "oEMWfLRjrJdYa8OdfNz2_X2UrTet1Lnu2fIdlq7-Qd8",
                    "use": "sig",
                    "crv": "P-256",
                    "kid": "key0",
                    "x": "ZnXv09eyorTiF0AdN6HW-kltr0tt0GbgmD2_VGGlapI",
                    "y": "vERyG9Enhy8pEZ6V_pomH8aGjO7cINteCmnV5B9y0f0",
                    "alg": "ES256"
                }
            ]
        }"#,
        )
        .unwrap();

        let _ = token.decode_with_jwks(&jwks, None).unwrap();
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

    #[test]
    fn unverified_header_is_returned_correctly() {
        let encoded_token: Compact<ClaimsSet<PrivateClaims>, Empty> =
            Compact::new_encoded(HS256_PAYLOAD);
        let expected_header = From::from(RegisteredHeader {
            algorithm: SignatureAlgorithm::HS256,
            ..Default::default()
        });

        let unverified_header = not_err!(encoded_token.unverified_header());
        assert_eq!(unverified_header, expected_header);
    }

    #[test]
    fn unverified_payload_is_returned_correctly() {
        let encoded_token: Compact<ClaimsSet<PrivateClaims>, Empty> =
            Compact::new_encoded(HS256_PAYLOAD);
        let expected_payload = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com/"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str(
                    "https://acme-customer.com/"
                )))),
                not_before: Some(1234.into()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let unverified_payload = not_err!(encoded_token.unverified_payload());
        assert_eq!(unverified_payload, expected_payload);
    }

    #[test]
    fn signature_is_returned_correctly() {
        let encoded_token: Compact<ClaimsSet<PrivateClaims>, Empty> =
            Compact::new_encoded(&HS256_PAYLOAD);
        let expected_signature = data_encoding::BASE64URL_NOPAD
            .decode(b"VFCl2un1Kc17odzOe2Ehf4DVrWddu3U4Ux3GFpOZHtc")
            .expect("to not error");

        let signature = not_err!(encoded_token.signature());
        assert_eq!(signature, expected_signature);
    }
}
