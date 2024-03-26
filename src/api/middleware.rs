use rocket::{http::Status,Request};
use rocket::request::{FromRequest, Outcome};
use jsonwebtoken::{
    decode,Algorithm, DecodingKey,TokenData, Validation,
};
extern crate dotenv;
use dotenv::dotenv;
use serde::{Deserialize, Serialize};
use std::env;
use crate::private::JWT_SECRET;


#[derive(Debug, Deserialize, Serialize)]
pub struct AuthorizedUser {
    pub sub: String,
    pub mail: String
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    pub sub: String,
    pub mail: String,
    pub exp: usize,
}
pub enum DecodeJwtHelper {
    Ok(TokenData<Claims>),
    Err,
}

fn check_data_from_token(auth_header: Option<&str>) -> Result<Vec<&str>, ()> {
    return if let Some(auth_string) = auth_header {
        let vec_header = auth_string.split_whitespace().collect::<Vec<_>>();
        if vec_header.len() != 2
            && vec_header[0] == "Bearer"
            && !vec_header[0].is_empty()
            && !vec_header[1].is_empty()
        {
            Err(())
        } else {
            Ok(vec_header)
        }
    } else {
        Err(())
    };
}

fn decode_jwt(token: String, secret: &'static str) -> DecodeJwtHelper {
    dotenv().ok();
    let secret= secret;
    println!("{}",secret);
    let secret_key = secret.as_bytes();
    let token = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(secret_key),
        &Validation::new(Algorithm::HS256),
    );
    println!("Token: {:?}",token);
    match token {
        Ok(token_string) => DecodeJwtHelper::Ok(token_string),
        Err(_) => DecodeJwtHelper::Err,
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthorizedUser {
    type Error = &'static str;
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let auth_header = request.headers().get_one("Authorization");
        println!("Hiiii");
        println!("header: {:?}",auth_header);
        match check_data_from_token(auth_header) {
            Ok(vec_header) => match decode_jwt(vec_header[1].to_string(), JWT_SECRET) {
                DecodeJwtHelper::Ok(token_data) =>{ Outcome::Success(AuthorizedUser {
                    sub: token_data.claims.sub,
                    mail: token_data.claims.mail
                })},
                DecodeJwtHelper::Err => Outcome::Error((Status::Unauthorized, "Invalid User!!")),
            },
            Err(_) => Outcome::Error((Status::Unauthorized, "Invalid User")),
        }
    }
}