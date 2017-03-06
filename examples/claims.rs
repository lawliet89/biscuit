extern crate jwt;
#[macro_use]
extern crate serde_derive;

use jwt::{ClaimsSet, RegisteredClaims, SingleOrMultipleStrings};
use jwt::jws::{Algorithm, Header, Secret};
use jwt::errors::{Error, ValidationError};

#[derive(Debug, Serialize, Deserialize)]
struct PrivateClaims {
    company: String,
    department: String,
}

// Example validation implementation
impl PrivateClaims {
    fn is_valid(&self) -> bool {
        if self.company != "ACME" {
            return false;
        }
        // expiration etc

        true
    }
}

#[allow(match_wild_err_arm)]
fn main() {
    let my_claims = ClaimsSet::<PrivateClaims> {
        registered: RegisteredClaims {
            iss: Some("https://www.acme.com".to_string()),
            sub: Some("John Doe".to_string()),
            aud: Some(SingleOrMultipleStrings::Single("htts://acme-customer.com".to_string())),
            exp: None,
            nbf: Some(1234),
            iat: None,
            jti: None,
        },
        private: PrivateClaims {
            department: "Toilet Cleaning".to_string(),
            company: "ACME".to_string(),
        },
    };
    let key = "secret";
    let token = match my_claims.encode(Header::default(),
                                       Secret::Bytes(key.to_string().into_bytes())) {
        Ok(t) => t,
        Err(_) => panic!(), // in practice you would return the error
    };

    println!("{:?}", token);

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
    println!("{:?}", claims.private.is_valid());
}
