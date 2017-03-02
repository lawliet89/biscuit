extern crate jwt;
#[macro_use]
extern crate serde_derive;

use jwt::{encode, decode};
use jwt::jws::{Algorithm, Header};
use jwt::errors::Error;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
}

fn main() {
    let my_claims = Claims {
        sub: "b@b.com".to_owned(),
        company: "ACME".to_owned(),
    };
    let key = "secret";

    let mut header = Header::default();
    header.kid = Some("signing_key".to_owned());
    header.alg = Algorithm::HS512;

    let token = match encode(header, &my_claims, key.as_ref()) {
        Ok(t) => t,
        Err(_) => panic!(), // in practice you would return the error
    };

    let token_data = match decode::<Claims>(&token, key.as_ref(), Algorithm::HS512) {
        Ok(c) => c,
        Err(err) => {
            match err {
                Error::InvalidToken => panic!(), // Example on how to handle a specific error
                _ => panic!(),
            }
        }
    };
    println!("{:?}", token_data.claims);
    println!("{:?}", token_data.header);
}
