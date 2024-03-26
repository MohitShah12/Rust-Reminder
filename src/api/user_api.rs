use crate::{models::user_model::{User},repository::mongodb_repo::{MongoRepo}};
use mongodb::{results::{InsertOneResult}};
use rocket::{serde::json::{Json}, State};
use rocket::response::{status::Custom};
use serde_json::{Value as JsonValue};
extern crate dotenv;
use crate::routes::user_routes;


#[post("/signup", data = "<new_user>")]
pub fn create_user(db:&State<MongoRepo>,new_user:Json<User>) -> Result<Json<InsertOneResult>, Custom<JsonValue>>{
    user_routes::create_user_route(db, new_user)
}

use user_routes::Login as routeLogin;

#[post("/login", data = "<login>")]
pub fn login(db: &State<MongoRepo>, login: Json<routeLogin>) -> Result<Json<JsonValue>, Custom<JsonValue>> {
    user_routes::login_route(db,login)
}
