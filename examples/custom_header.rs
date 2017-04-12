extern crate chrono;
extern crate biscuit;
#[macro_use]
extern crate serde_derive;

use std::default::Default;
use std::str::FromStr;

use chrono::UTC;
use biscuit::{ClaimsSet, RegisteredClaims, SingleOrMultiple};
use biscuit::jwa::SignatureAlgorithm;
use biscuit::jws::{Compact, Header, RegisteredHeader, Secret};
use biscuit::errors::{Error, ValidationError};

#[derive(Debug, Serialize, Deserialize)]
struct PrivateClaims {
    company: String,
    department: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PrivateHeader {
    purpose: String,
}

fn main() {
    let my_claims = ClaimsSet::<PrivateClaims> {
        registered: RegisteredClaims {
            issuer: Some(FromStr::from_str("https://www.acme.com").unwrap()),
            subject: Some(FromStr::from_str("John Doe").unwrap()),
            audience: Some(SingleOrMultiple::Single(FromStr::from_str("htts://acme-customer.com").unwrap())),
            not_before: Some(UTC::now().into()),
            ..Default::default()
        },
        private: PrivateClaims {
            department: "Toilet Cleaning".to_string(),
            company: "ACME".to_string(),
        },
    };
    let key = "secret";
    let signing_secret = Secret::Bytes(key.to_string().into_bytes());

    let header = Header {
        registered: RegisteredHeader {
            key_id: Some("signing_key".to_string()),
            algorithm: SignatureAlgorithm::HS512,
            ..Default::default()
        },
        private: PrivateHeader { purpose: "Toilet cleaning".to_string() },
    };

    let jwt = Compact::new_decoded(header, my_claims);
    let token = match jwt.encode(&signing_secret) {
        Ok(t) => t,
        Err(_) => panic!(), // in practice you would return the error
    };

    let jwt = match token.decode(&signing_secret,
                                 SignatureAlgorithm::HS256) {
        Ok(c) => c,
        Err(err) => {
            match err {
                // Example on how to handle a specific error
                Error::ValidationError(ValidationError::InvalidToken) => panic!(),
                _ => panic!(),
            }
        }
    };
    println!("{:?}", jwt);
    println!("{:?}", jwt.header());
}
