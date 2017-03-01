//! Create and parses JWT (JSON Web Tokens)
//!

#![cfg_attr(feature = "dev", allow(unstable_features))]
#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

// #![warn(missing_docs)]
#![doc(test(attr(allow(unused_variables), deny(warnings))))]

extern crate rustc_serialize;
extern crate ring;
extern crate untrusted;

use ring::{digest, hmac, rand, signature};
use ring::constant_time::verify_slices_are_equal;

use rustc_serialize::{json, Encodable, Decodable};
use rustc_serialize::base64::{self, ToBase64, FromBase64};
use rustc_serialize::json::{ToJson, Json};

pub mod errors;
use errors::Error;
use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Copy, Clone, RustcDecodable, RustcEncodable)]
/// The algorithms supported for signing/verifying
pub enum Algorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
}

impl ToJson for Algorithm {
    fn to_json(&self) -> Json {
        use Algorithm::*;

        match *self {
            HS256 => Json::String("HS256".to_string()),
            HS384 => Json::String("HS384".to_string()),
            HS512 => Json::String("HS512".to_string()),
            RS256 => Json::String("RS256".to_string()),
            RS384 => Json::String("RS384".to_string()),
            RS512 => Json::String("RS512".to_string()),
        }
    }
}

impl Algorithm {
    /// Take the payload of a JWT and sign it using the algorithm given.
    /// Returns the base64 url safe encoded of the result
    /// # Secret
    /// This is dependent on the algorithm. For HMAC algorithm, this is some secret string.
    ///
    /// For RSA algorithm, this should be a private key in DER-encoded ASN.1 `RSAPrivateKey` form
    /// (see [RFC 3447 Appendix A.1.2]).
    ///
    /// Only two-prime keys (version 0) keys are supported. The public modulus
    /// (n) must be at least 2048 bits. Currently, the public modulus must be
    /// no larger than 4096 bits.
    ///
    /// Here's one way to generate a key in the required format using OpenSSL:
    ///
    /// ```sh
    /// openssl genpkey -algorithm RSA \
    ///                 -pkeyopt rsa_keygen_bits:2048 \
    ///                 -outform der \
    ///                 -out private_key.der
    /// ```
    ///
    /// Often, keys generated for use in OpenSSL-based software are
    /// encoded in PEM format, which is not supported by `ring`, the cryptographic library used.
    /// PEM-encoded keys that are in `RSAPrivateKey` format can be decoded into the using
    /// an OpenSSL command like this:
    ///
    /// ```sh
    /// openssl rsa -in private_key.pem -outform DER -out private_key.der
    /// ```
    ///
    /// If these commands don't work, it is likely that the private key is in a
    /// different format like PKCS#8, which isn't supported yet.
    ///
    /// [RFC 3447 Appendix A.1.2]:
    ///     https://tools.ietf.org/html/rfc3447#appendix-A.1.2
    pub fn sign(&self, data: &str, secret: &[u8]) -> Result<String, Error> {
        use Algorithm::*;

        match *self {
            HS256 | HS384 | HS512 => Ok(Self::sign_hmac(data, secret, self)),
            RS256 | RS384 | RS512 => Self::sign_rsa(data, secret, self),
        }
    }

    fn sign_hmac(data: &str, secret: &[u8], algorithm: &Algorithm) -> String {
        let digest = match *algorithm {
            Algorithm::HS256 => &digest::SHA256,
            Algorithm::HS384 => &digest::SHA384,
            Algorithm::HS512 => &digest::SHA512,
            _ => unreachable!("Should not happen"),
        };
        let key = hmac::SigningKey::new(digest, secret);
        hmac::sign(&key, data.as_bytes()).as_ref().to_base64(base64::URL_SAFE)
    }

    fn sign_rsa(data: &str, private_key: &[u8], algorithm: &Algorithm) -> Result<String, Error> {
        let key_pair = std::sync::Arc::new(signature::RSAKeyPair::from_der(untrusted::Input::from(private_key))?);
        let mut signing_state = signature::RSASigningState::new(key_pair)?;
        let rng = rand::SystemRandom::new();
        let mut signature = vec![0; signing_state.key_pair().public_modulus_len()];
        let padding_algorithm = match *algorithm {
            Algorithm::RS256 => &signature::RSA_PKCS1_SHA256,
            Algorithm::RS384 => &signature::RSA_PKCS1_SHA384,
            Algorithm::RS512 => &signature::RSA_PKCS1_SHA512,
            _ => unreachable!("Should not happen"),
        };
        signing_state.sign(padding_algorithm, &rng, data.as_bytes(), &mut signature)?;
        Ok(signature.as_slice().to_base64(base64::URL_SAFE))
    }
}

/// A part of the JWT: header and claims specifically
/// Allows converting from/to struct with base64
pub trait Part {
    type Encoded: AsRef<str>;

    fn from_base64<B: AsRef<[u8]>>(encoded: B) -> Result<Self, Error> where Self: Sized;
    fn to_base64(&self) -> Result<Self::Encoded, Error>;
}

impl<T> Part for T
    where T: Encodable + Decodable
{
    type Encoded = String;

    fn to_base64(&self) -> Result<Self::Encoded, Error> {
        let encoded = try!(json::encode(&self));
        Ok(encoded.as_bytes().to_base64(base64::URL_SAFE))
    }

    fn from_base64<B: AsRef<[u8]>>(encoded: B) -> Result<T, Error> {
        let decoded = try!(encoded.as_ref().from_base64());
        let s = try!(String::from_utf8(decoded));
        Ok(try!(json::decode(&s)))
    }
}

#[derive(Debug, PartialEq, RustcDecodable)]
/// A basic JWT header part, the alg defaults to HS256 and typ is automatically
/// set to `JWT`. All the other fields are optional
pub struct Header {
    typ: String,
    pub alg: Algorithm,
    pub jku: Option<String>,
    pub kid: Option<String>,
    pub x5u: Option<String>,
    pub x5t: Option<String>,
}

impl Header {
    pub fn new(algorithm: Algorithm) -> Header {
        Header {
            typ: "JWT".to_string(),
            alg: algorithm,
            jku: None,
            kid: None,
            x5u: None,
            x5t: None,
        }
    }
}

impl Default for Header {
    fn default() -> Header {
        Header::new(Algorithm::HS256)
    }
}

impl Encodable for Header {
    fn encode<S: rustc_serialize::Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        self.to_json().encode(s)
    }
}

impl ToJson for Header {
    fn to_json(&self) -> Json {
        let mut d = BTreeMap::new();
        d.insert("typ".to_string(), self.typ.to_json());
        d.insert("alg".to_string(), self.alg.to_json());

        // Define a macro to reduce boilerplate.
        macro_rules! optional {
            ($field_name:ident) => (
                if let Some(ref value) = self.$field_name {
                    d.insert(stringify!($field_name).to_string(), value.to_json());
                }
            )
        }
        optional!(jku);
        optional!(kid);
        optional!(x5u);
        optional!(x5t);
        Json::Object(d)
    }
}

#[derive(Debug)]
/// The return type of a successful call to decode(...)
pub struct TokenData<T: Part> {
    pub header: Header,
    pub claims: T,
}

/// Compares the signature given with a re-computed signature
pub fn verify(signature: &str, data: &str, secret: &[u8], algorithm: Algorithm) -> bool {
    let actual_signature = match algorithm.sign(data, secret) {
        Ok(signature) => signature,
        Err(_) => return false,
    };

    verify_slices_are_equal(signature.as_ref(), actual_signature.as_ref()).is_ok()
}

/// Encode the claims passed and sign the payload using the algorithm from the header and the secret
pub fn encode<T: Part>(header: Header, claims: &T, secret: &[u8]) -> Result<String, Error> {
    let encoded_header = try!(header.to_base64());
    let encoded_claims = try!(claims.to_base64());
    // seems to be a tiny bit faster than format!("{}.{}", x, y)
    let payload = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");
    let signature = header.alg.sign(&*payload, secret.as_ref())?;

    Ok([payload, signature].join("."))
}

/// Used in decode: takes the result of a rsplit and ensure we only get 2 parts
/// Errors if we don't
macro_rules! expect_two {
    ($iter:expr) => {{
        let mut i = $iter; // evaluate the expr
        match (i.next(), i.next(), i.next()) {
            (Some(first), Some(second), None) => (first, second),
            _ => return Err(Error::InvalidToken)
        }
    }}
}

/// Decode a token into a Claims struct
/// If the token or its signature is invalid, it will return an error
pub fn decode<T: Part>(token: &str, secret: &[u8], algorithm: Algorithm) -> Result<TokenData<T>, Error> {
    let (signature, payload) = expect_two!(token.rsplitn(2, '.'));

    let is_valid = verify(signature, payload, secret, algorithm);

    if !is_valid {
        return Err(Error::InvalidSignature);
    }

    let (claims, header) = expect_two!(payload.rsplitn(2, '.'));

    let header = try!(Header::from_base64(header));
    if header.alg != algorithm {
        return Err(Error::WrongAlgorithmHeader);
    }
    let decoded_claims = try!(T::from_base64(claims));

    Ok(TokenData {
        header: header,
        claims: decoded_claims,
    })
}

#[cfg(test)]
mod tests {
    use std::str;
    use rustc_serialize::base64::{self, ToBase64, FromBase64};
    use super::{encode, decode, Algorithm, Header, verify};

    macro_rules! not_err {
        ($e:expr) => (match $e {
            Ok(e) => e,
            Err(e) => panic!("{} failed with {}", stringify!($e), e),
        })
    }

    #[derive(Debug, PartialEq, Clone, RustcEncodable, RustcDecodable)]
    struct Claims {
        sub: String,
        company: String,
    }

    fn read_private_key() -> &'static [u8] {
        include_bytes!("../test/fixtures/private_key.der")
    }

    fn read_signature_payload() -> &'static [u8] {
        include_bytes!("../test/fixtures/signature_payload.txt")
    }

    #[test]
    fn sign_hs256() {
        let expected = "c0zGLzKEFWj0VxWuufTXiRMk5tlI5MbGDAYhzaxIYjo";
        let result = not_err!(Algorithm::HS256.sign("hello world", b"secret"));
        assert_eq!(result, expected);

        let valid = verify(expected, "hello world", b"secret", Algorithm::HS256);
        assert!(valid);
    }

    /// To generate hash, use
    ///
    /// ```sh
    /// openssl dgst -sha256 -sign test/fixtures/private_key.pem  test/fixtures/signature_payload.txt | base64
    /// ```
    ///
    /// The base64 encoding will be in `STANDARD` form and not URL_SAFE.
    #[test]
    fn sign_rs256() {
        let private_key = read_private_key();
        let payload = not_err!(str::from_utf8(read_signature_payload()));
        // Convert STANDARD base64 to URL_SAFE
        let expected_signature = "rg1MvJA9sH9x5xf8hZ3lFyAeUkz1wShrgB5G5rOlRI6oTZsUGwp7UBkxiopW80iBP/wvIbHEdI86\
                                  Q0jHaG4n1X7ij0NSSbN3LRawFOEodPDvXsk8kaoyUaLsLyFUf4Gdg3z7YSc0ZT8Ry0pKLls7c0ga\
                                  cpdYb7+Vw35+FNwA70tSt6vV5YKiFDDoiTvubM/3gizsDGCPMLVeRKGpSvBPaHtclgbM+kxML4fR\
                                  qqHsNdnbrI/ic+A5E1KFm9oeUAbbwb1dxhz6d6N3jwg8j7ttyskIa4gK9yxBUASYoFaakMDhBfeg\
                                  QAyE/zz7nWs3j9B4cy9a9tVV/3E7N3U5J0xRzQ==";
        let expected_signature = not_err!(str::from_base64(expected_signature));
        let expected_signature = expected_signature.to_base64(base64::URL_SAFE);

        let actual_signature = not_err!(Algorithm::RS256.sign(payload, private_key));
        assert_eq!(expected_signature, actual_signature);

        let valid = verify(&*expected_signature, payload, private_key, Algorithm::RS256);
        assert!(valid);
    }

    #[test]
    fn encode_with_custom_header() {
        let expected_claims = Claims {
            sub: "b@b.com".to_string(),
            company: "ACME".to_string(),
        };
        let mut header = Header::default();
        header.kid = Some("kid".to_string());
        let token = not_err!(encode(header, &expected_claims, "secret".as_ref()));
        let token_data = not_err!(decode::<Claims>(&token, "secret".as_ref(), Algorithm::HS256));
        assert_eq!(expected_claims, token_data.claims);
        assert_eq!("kid", token_data.header.kid.unwrap());
    }

    #[test]
    fn round_trip_hs256() {
        let expected_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.\
                              eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.\
                              C35LD5nqS_Gx9KF19E2wwf_KFcQ7TNqZLThivXZMXKWen9XVjr6kIF_fjZoaA-\
                              F9q1QjK4EAG6ZwFO2l3rL7MFsrOJwcCgfSkcnTLFOI_RewEFKSDDrfeZyXwQo4PlYd\
                              q5i2Ue1hxQwbv4MuVcnW1rEPqb04WMo3pS2IpNkJxbiUyWIz_Ze4enPXby8YRbidHfC0eS0CK\
                              7bvycE8RJC0Ynpdf0lnd_5jZmAQjC_imz9bjL_wLZq-ggl8Bbi-sA8VcIQWLTPbrpCuYPDrXkjdxL\
                              VpJXoBNEEkfNryqD9asu2r2tFJXrSVLxZGV9AAtkks7uk1nkyEfHVQiOE6JrNODA";
        let expected_claims = Claims {
            sub: "b@b.com".to_string(),
            company: "ACME".to_string(),
        };
        let private_key = read_private_key();

        let token = not_err!(encode(Header::new(Algorithm::RS256), &expected_claims, private_key));
        assert_eq!(expected_token, token);

        let token_data = not_err!(decode::<Claims>(&token, private_key, Algorithm::RS256));
        assert_eq!(expected_claims, token_data.claims);
        assert!(token_data.header.kid.is_none());
    }


    #[test]
    fn round_trip_rs256() {
        let expected_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                              eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.\
                              I1BvFoHe94AFf09O6tDbcSB8-jp8w6xZqmyHIwPeSdY";
        let expected_claims = Claims {
            sub: "b@b.com".to_string(),
            company: "ACME".to_string(),
        };

        let token = not_err!(encode(Header::new(Algorithm::HS256),
                                    &expected_claims,
                                    "secret".as_bytes()));
        assert_eq!(expected_token, token);

        let token_data = not_err!(decode::<Claims>(&token, "secret".as_bytes(), Algorithm::HS256));
        assert_eq!(expected_claims, token_data.claims);
        assert!(token_data.header.kid.is_none());
    }

    #[test]
    #[should_panic(expected = "InvalidToken")]
    fn decode_token_missing_parts() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = decode::<Claims>(token, "secret".as_ref(), Algorithm::HS256);
        claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn decode_token_invalid_signature_hs256() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                     eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.wrong";
        let claims = decode::<Claims>(token, "secret".as_ref(), Algorithm::HS256);
        claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn decode_token_invalid_signature_rs256() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                     eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.wrong";
        let private_key = read_private_key();
        let claims = decode::<Claims>(token, private_key, Algorithm::RS256);
        claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn decode_token_wrong_algorithm() {
        let token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.\
                     eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.\
                     pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI";
        let claims = decode::<Claims>(token, "secret".as_ref(), Algorithm::HS256);
        claims.unwrap();
    }

    #[test]
    fn decode_token_with_bytes_secret_hs256() {
        let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.\
                     eyJzdWIiOiIxMjM0NTY3ODkwIiwiY29tcGFueSI6Ikdvb2dvbCJ9.\
                     27QxgG96vpX4akKNpD1YdRGHE3_u2X35wR3EHA2eCrs";
        let claims = decode::<Claims>(token, b"\x01\x02\x03", Algorithm::HS256);
        assert!(claims.is_ok());
    }

    #[test]
    fn decode_token_with_shuffled_header_fields() {
        let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.\
                     eyJjb21wYW55IjoiMTIzNDU2Nzg5MCIsInN1YiI6IkpvaG4gRG9lIn0.\
                     SEIZ4Jg46VGhquuwPYDLY5qHF8AkQczF14aXM3a2c28";
        let claims = decode::<Claims>(token, "secret".as_ref(), Algorithm::HS256);
        assert!(claims.is_ok());
    }
}
