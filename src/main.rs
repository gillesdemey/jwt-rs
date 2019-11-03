#[macro_use]
extern crate serde_derive;
extern crate jsonwebtoken as jwt;
extern crate uuid;

use uuid::{Uuid, Version};
use jwt::{decode, Header, Algorithm, TokenData, Validation};

// these constants define either a user or application JWT token
const APP_PREFIX: &str = "applications/";
const USER_PREFIX: &str = "users/";
const RANDOM_UUID: Version = Version::Random;

// this struct will declare the payload of the JWT tokens
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
   sub: String,
   tenant: String,
   domain: String,
   iss: String
}

fn main() {
    let jwt_token: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjZjY2M4ODQzLWQ3OGQtNDllOC04NGM0LTM3MzRhNGFmOTkyOSJ9.eyJ0ZW5hbnQiOiJhYmMxMjMiLCJkb21haW4iOiJ0ZXN0LmRvbWFpbi5jb20iLCJzdWIiOiJ1c2Vycy9tZSIsImlzcyI6Imp3dC1ycyIsImV4cCI6MTU3NzgzNjgwMH0.oi9yQWCKtESV9C6FTd_b4s1aza2SZn-Ns9zGM8orlIE";

    // decode returns a Result<TokenData> so we have to unwrap for it to panic on Error
    let token = decode::<Claims>(&jwt_token, b"foo", &Validation::new(Algorithm::HS256)).unwrap();

    // token is an Option<TokenData>
    verify_token(&token).unwrap();

    println!("{:#?}", token);
}

fn verify_token(data: &TokenData<Claims>) -> Result<&TokenData<Claims>, &'static str> {
    verify_header(&data.header).unwrap();
    verify_claims(&data.claims).unwrap();

    Ok(data)
}

// The header needs a valid "kid" claim
fn verify_header(header: &Header) -> Result<&Header, &'static str> {
    match header.kid {
        None => Err("No kid claim found in the header"),
        Some(ref kid) => {
            match has_valid_key_id(kid) {
                None => Err("Header contained invalid kid value"),
                Some(ref _version) => Ok(&header)
            }
        },
    }
}

// must be a UUID v4 (alias Random)
fn has_valid_key_id(kid: &str) -> Option<Version> {
    let u = Uuid::parse_str(kid).unwrap(); // try parsing it as a UUID
    u.get_version().filter(|v| v == &RANDOM_UUID) // validate it's a UUID v4 (random)
}

// verify the payload of the token
fn verify_claims(claims: &Claims) -> Result<&Claims, &'static str> {
    Ok(claims)
}
