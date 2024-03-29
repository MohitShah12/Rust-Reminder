use rocket::{http::Status,Request};
use rocket::request::{FromRequest, Outcome};
use jsonwebtoken::{
    decode,Algorithm, DecodingKey,TokenData, Validation,
};
extern crate dotenv;
use dotenv::dotenv;
use serde::{Deserialize, Serialize};
use crate::private::JWT_SECRET;





#[derive(Debug, Deserialize, Serialize)]
pub struct AuthorizedUser {
    pub sub: String,
}

#[derive(Debug)]
enum AuthError{
    Unauthorized,
    Invalid
}

impl From<AuthError> for Status{
    fn from(error: AuthError) -> Status {
        match error{
            AuthError::Unauthorized => Status::Unauthorized,
            AuthError::Invalid => Status::Forbidden
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}


fn check_data_from_token(auth_header: Option<&str>) -> Result<Vec<&str>, AuthError> {
    return if let Some(auth_string) = auth_header {
        let vec_header = auth_string.split_whitespace().collect::<Vec<_>>();
        if vec_header.len() != 2
            && vec_header[0] == "Bearer"
            && !vec_header[0].is_empty()
            && !vec_header[1].is_empty()
        {
            Err(AuthError::Invalid)
        } else {
            Ok(vec_header)
        }
    } else {
        Err(AuthError::Unauthorized)
    };
}

fn decode_jwt(token: String, secret: &'static str) -> Result<TokenData<Claims>, AuthError> {
    dotenv().ok();
    let secret= secret;
    println!("{}",secret);
    //converting secret from str slice to byte slice
    let secret_key = secret.as_bytes();

    //decoding tokens
    let token = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(secret_key),
        &Validation::new(Algorithm::HS256),
    );
    println!("Token: {:?}",token);
    match token {
        Ok(token_string) => Ok(token_string),
        Err(_) => Err(AuthError::Unauthorized),
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthorizedUser {
    type Error = &'static str;
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        //getting bearer token from user
        let auth_header = request.headers().get_one("Authorization");
        println!("Hiiii");
        println!("header: {:?}",auth_header);
        match check_data_from_token(auth_header) {
            Ok(vec_header) => match decode_jwt(vec_header[1].to_string(), JWT_SECRET) {
                Ok(token_data) =>{ Outcome::Success(AuthorizedUser {
                    sub: token_data.claims.sub,
                })},
                Err(error) => Outcome::Error((error.into(), "Invalid User!!")),
            },
            Err(error) => Outcome::Error((error.into(), "Invalid User")),
        }
    }
}
