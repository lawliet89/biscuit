extern crate chrono;
extern crate jwt;
#[macro_use]
extern crate serde_derive;

use std::default::Default;

use chrono::UTC;
use jwt::{ClaimsSet, RegisteredClaims, SingleOrMultipleStrings};
use jwt::jws::{Algorithm, Header, Secret};
use jwt::errors::{Error, ValidationError};

#[derive(Debug, Serialize, Deserialize)]
struct PrivateClaims {
    company: String,
    department: String,
}

fn main() {
    let my_claims = ClaimsSet::<PrivateClaims> {
        registered: RegisteredClaims {
            issuer: Some("https://www.acme.com".to_string()),
            subject: Some("John Doe".to_string()),
            audience: Some(SingleOrMultipleStrings::Single("htts://acme-customer.com".to_string())),
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

    let token = match my_claims.encode(header, Secret::Bytes(key.to_string().into_bytes())) {
        Ok(t) => t,
        Err(_) => panic!(), // in practice you would return the error
    };

    let (headers, claims) = match ClaimsSet::<PrivateClaims>::decode(&token,
                                             Secret::Bytes(key.to_string().into_bytes()),
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
    println!("{:?}", claims);
    println!("{:?}", headers);
}
