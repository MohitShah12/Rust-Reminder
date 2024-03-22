use crate::{models::user_model::{User},repository::mongodb_repo::{MongoRepo}};
use mongodb::{results::{InsertOneResult}};
use rocket::{http::{Status,Header as rocketHeader}, serde::json::{Json}, State};
use serde::{Serialize, Deserialize};
use pwhash::bcrypt;
use rocket::response::{Response, status::Custom};
use serde_json::{json, Value as JsonValue};
use jsonwebtoken::{EncodingKey, Header, encode, decode, DecodingKey, Validation, Algorithm};
extern crate dotenv;
use dotenv::dotenv;
use std::env;
use regex::Regex;
use chrono::{Utc, Duration};



fn is_valid_email(email:&str) -> bool{
    let reg = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
    reg.is_match(email)
}
fn is_valid_password(password:&str) -> bool{
      // Check for minimum length
      if password.len() < 5 {
        return false;
    }

    // Check for at least one uppercase letter
    let uppercase_regex = Regex::new(r"[A-Z]").unwrap();
    if !uppercase_regex.is_match(password) {
        return false;
    }

    // Check for at least one lowercase letter
    let lowercase_regex = Regex::new(r"[a-z]").unwrap();
    if !lowercase_regex.is_match(password) {
        return false;
    }

    // Check for at least one digit
    let digit_regex = Regex::new(r"\d").unwrap();
    if !digit_regex.is_match(password) {
        return false;
    }

    // Check for at least one special character
    let special_char_regex = Regex::new(r"[!@#$%^&*()-=_+]").unwrap();
    if !special_char_regex.is_match(password) {
        return false;
    }

    // All checks passed, password is valid
    true
}


#[post("/signup", data = "<new_user>")]
pub fn create_user(db:&State<MongoRepo>, new_user:Json<User>) -> Result<Json<InsertOneResult>, Custom<JsonValue>>{

    let new_user_data = new_user.into_inner();

    if !(is_valid_email(&new_user_data.email)){
        let json_response = json!({"error":"Please provide a valid email"});
        return Err(Custom(Status::BadRequest, json_response.into()));
    }

    if !is_valid_password(&new_user_data.password){
        let json_response = json!({"error":"Password must contain at least 1 uppercase letter, 1 lowercase letter, 1 special character, 1 number, and be at least 5 characters long"});
        return Err(Custom(Status::BadRequest, json_response.into()));
    }

    let existing_user = db.find_user_by_email(&new_user_data.email);

    if let Ok(_) = existing_user{
        let json_response = json!({ "error": "User with the same email already exists" });
        return Err(Custom(Status::InternalServerError, json_response.into()));   
        
    }

    let hash_pass = bcrypt::hash(new_user_data.password.to_owned()).unwrap();

    let user_data = User{
        id:None,
        name:new_user_data.name.to_owned(),
        email:new_user_data.email.to_owned(),
        password:hash_pass.to_owned()
    };
    let user_deatil = db.db_create_user(user_data);
    match user_deatil {
        Ok(user) => Ok(Json(user)),
        Err(_) => {
            let json_response = json!({ "error": "Internal Server Error" });
            Err(Custom(Status::InternalServerError, json_response.into()))
        } 
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Login {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims{
    sub : String,
    exp: i64
}

#[post("/login", data = "<login>")]
pub fn login(db: &State<MongoRepo>, login: Json<Login>) -> Result<Json<JsonValue>, Custom<JsonValue>> {
    dotenv().ok();
    let login_data = login.into_inner();
    println!("Attempting login for user {}", login_data.email);

    // Retrieve user from the database based on the provided email
    let user_detail = db.find_user_by_email(&login_data.email);

    match user_detail {
        Ok(user_opt) => {
            match user_opt {
                Some(user) => {
                    // Verify the password
                    if bcrypt::verify(&login_data.password, &user.password) {
                        // Passwords match, return the user
                        let expiration = Utc::now() + Duration::hours(1);
                        let claims = Claims {
                            sub: user.id.unwrap().to_string(),
                            exp: expiration.timestamp(), // Add expiration time to the claims
                        };
                        let secret = match env::var("SECRETKEY") {
                            Ok(v) => v.to_string(),
                            Err(_) => {
                                let json_response = json!({ "error": "Failed to get secret key" });
                                return Err(Custom(Status::InternalServerError, json_response.into()));
                            }
                        };
                        let secret_key = secret.as_bytes();

                        let token = match encode(&Header::default(), &claims, &EncodingKey::from_secret(secret_key)) {
                            Ok(t)=>{
                                println!("Your Token : {}",t);
                                t
                            }
                            Err(_)=>{
                                let json_response = json!({ "error": "Failed to generate JWT" });
                                return Err(Custom(Status::InternalServerError, json_response.into()));
                            }
                        };

                        // Create a response with the token set in the header
                        let response = Response::build()
                            .status(Status::Ok)
                            .header(rocketHeader::new("X-Token", &token))
                            .finalize();
                        println!("This is a token: {:?}",response);
                        let our_user = decode::<Claims>(&token, &DecodingKey::from_secret(secret_key), &Validation::new(Algorithm::HS256));
                        println!("hello: {:?}",our_user.unwrap().claims.exp);
                        Ok(Json(json!({"token":token})))
                    } else {
                        // Passwords don't match
                        let json_response = json!({ "error": "Wrong Credentials" });
                        Err(Custom(Status::Unauthorized, json_response.into()))
                    }
                }
                None => {
                    // No user found with the provided email
                    let json_response = json!({ "error": "No user found" });
                    Err(Custom(Status::NotFound, json_response.into()))
                }
            }
        }
        Err(msg) => {
            // Internal server error
            let json_response = json!({ "error": "Internal Server Error", "details": msg });
            Err(Custom(Status::InternalServerError, json_response.into()))
        }
    }
}
