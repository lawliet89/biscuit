extern crate chrono;
extern crate biscuit;
#[macro_use]
extern crate serde_derive;

use std::default::Default;
use std::str::FromStr;

use chrono::UTC;
use biscuit::{ClaimsSet, RegisteredClaims, SingleOrMultiple};
use biscuit::jws::{Compact, Algorithm, Header, Secret};
use biscuit::errors::{Error, ValidationError};

#[derive(Debug, Serialize, Deserialize)]
struct PrivateClaims {
    company: String,
    department: String,
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

    let mut header = Header::default();
    header.key_id = Some("signing_key".to_string());
    header.algorithm = Algorithm::HS512;

    let jwt = Compact::new_decoded(header, my_claims);
    let token = match jwt.encode(Secret::Bytes(key.to_string().into_bytes())) {
        Ok(t) => t,
        Err(_) => panic!(), // in practice you would return the error
    };

    let jwt = match token.decode(Secret::Bytes(key.to_string().into_bytes()),
                       Algorithm::HS256) {
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
