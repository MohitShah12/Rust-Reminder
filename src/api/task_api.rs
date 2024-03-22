use crate::{models::task_model::Task, repository::mongodb_repo::MongoRepo};
use mongodb::results::InsertOneResult;
use rocket::{http::Status, response::status::Custom, serde::json::Json, Request, State};
use rocket::request::{FromRequest, Outcome};
use mongodb::bson::{oid::ObjectId, Bson};
// use rocket::

// use serde::{Serialize, Deserialize};
use chrono::{DateTime, ParseError, Utc};
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
// use rocket::response::status::Custom;
use serde_json::{json, Value as JsonValue};
extern crate dotenv;
use dotenv::dotenv;
use serde::{Deserialize, Serialize};
use std::env;
use crate::private::JWT_SECRET;

fn parse_remider_date(date_str: &str) -> Result<DateTime<Utc>, ParseError> {
    println!("Bye: {}", date_str);
    DateTime::parse_from_rfc3339(date_str).map(|dt| dt.with_timezone(&Utc))
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthorizedUser {
    sub: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    pub sub: String,
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
    println!("{:?}",token);
    match token {
        Ok(token_string) => DecodeJwtHelper::Ok(token_string),
        Err(_) => DecodeJwtHelper::Err,
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthorizedUser {
    type Error = ();
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let auth_header = request.headers().get_one("Authorization");
        println!("Hiiii");
        println!("Bhai Bhai {:?}",auth_header);
        match check_data_from_token(auth_header) {
            Ok(vec_header) => match decode_jwt(vec_header[1].to_string(), JWT_SECRET) {
                DecodeJwtHelper::Ok(token_data) =>{ Outcome::Success(AuthorizedUser {
                    sub: token_data.claims.sub,
                })},
                DecodeJwtHelper::Err => Outcome::Error((Status::Unauthorized, ())),
            },
            Err(_) => Outcome::Error((Status::Unauthorized, ())),
        }
    }
}

#[post("/addreminder", data = "<new_task>")]
pub fn add_reminder(
    db: &State<MongoRepo>,
    new_task: Json<Task>,
    auth:AuthorizedUser
) -> Result<Json<InsertOneResult>, Custom<JsonValue>> {
    let new_task_data = new_task.into_inner();
    println!("an: {}", new_task_data.task.is_empty());
    println!("Bhai : {:?}",auth.sub);

    let user_id = match ObjectId::parse_str(auth.sub){
        Ok(object_id) => Some(object_id),
        Err(_) => None,
    };
    if new_task_data.task.is_empty() {
        let json_response = json!({"error" : "Please provide a task"});
        return Err(Custom(Status::BadRequest, json_response.into()));
    }

    if new_task_data.description.is_empty() {
        let json_response = json!({"error" : "Please provide a description"});
        return Err(Custom(Status::BadRequest, json_response.into()));
    }

    // Check if the date is valid
    if let Some(reminder_date) = new_task_data.reminder_date {
        if reminder_date < Utc::now() {
            let json_response = json!({"error": "Reminder date must be in the future"});
            return Err(Custom(Status::BadRequest, json_response.into()));
        }
        let parse_date = match parse_remider_date(&reminder_date.to_rfc3339()) {
            Ok(parsed_date) => parsed_date,
            Err(_) => {
                let json_response = json!({"error":"Date formate is not valid"});
                return Err(Custom(Status::BadRequest, json_response.into()));
            }
        };
        println!("hello: {}", parse_date);
    }

    let task_data = Task {
        id: None,
        task: new_task_data.task.to_owned(),
        description: new_task_data.description.to_owned(),
        reminder_date: new_task_data.reminder_date,
        user_id:Some(user_id.expect("REASON"))
    };
    let task_detail = db.db_create_task(task_data);
    match task_detail {
        Ok(reminder) => Ok(Json(reminder)),
        Err(_) => {
            let json_response = json!({ "error": "Internal Server Error" });
            Err(Custom(Status::InternalServerError, json_response.into()))
        }
    }
}

#[get("/showreminder")]
pub fn get_reminder(db: &State<MongoRepo>) -> Result<Json<Vec<Task>>, Custom<JsonValue>> {
    let task_deatils = db.get_all_tasks();
    match task_deatils {
        Ok(task) => Ok(Json(task)),
        Err(_) => {
            let json_response = json!({ "error": "No tasks found" });
            Err(Custom(Status::NotFound, json_response.into()))
        }
    }
}

#[put("/updatereminder/<id>", data = "<new_task>")]
pub fn update_reminder(
    db: &State<MongoRepo>,
    id: String,
    auth:AuthorizedUser,
    new_task: Json<Task>,
) -> Result<Json<Task>, Custom<JsonValue>> {
    let id = id;
    let user_id = match ObjectId::parse_str(auth.sub){
        Ok(object_id) => Some(object_id),
        Err(_) => None,
    };
    if id.is_empty() {
        let json_response = json!({"error":"Id of task is requires"});
        return Err(Custom(Status::BadRequest, json_response.into()));
    }
    let new_task_data = Task {
        id: None,
        task: new_task.task.to_owned(),
        description: new_task.description.to_owned(),
        reminder_date: new_task.reminder_date,
        user_id:Some(user_id.expect("REASON"))
    };

    let new_task_detail = db.update_task(&id, &new_task_data);
    match new_task_detail {
        Ok(update) => {
            if update.matched_count == 1 {
                let updated_task = new_task_data;
                return Ok(Json(updated_task));
            } else {
                let json_response = json!({ "error": "No tasks was updated" });
                Err(Custom(Status::NotFound, json_response.into()))
            }
        }
        Err(_) => {
            let json_response = json!({ "error": "No tasks was updated" });
            Err(Custom(Status::NotFound, json_response.into()))
        }
    }
}

#[delete("/deletereminder/<id>")]
pub fn delete_reminder(db: &State<MongoRepo>, id: String) -> Result<Json<&str>, Custom<JsonValue>> {
    let id = id;
    println!("{}", id);
    if id.is_empty() {
        let json_response = json!({"error":"Id of task is requires"});
        return Err(Custom(Status::BadRequest, json_response.into()));
    };
    let deleted_task = db.delete_task(&id);
    println!("{:?}", deleted_task);
    match deleted_task {
        Ok(deleted) => {
            if deleted.deleted_count == 1 {
                return Ok(Json("Deleted task successfully"));
            } else {
                let json_response = json!({ "error": "No tasks was deleted" });
                Err(Custom(Status::NotFound, json_response.into()))
            }
        }
        Err(_) => {
            let json_response = json!({ "error": "No tasks was updated" });
            Err(Custom(Status::NotFound, json_response.into()))
        }
    }
}
