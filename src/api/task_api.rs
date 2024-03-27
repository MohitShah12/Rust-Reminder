use crate::{models::task_model::Task, repository::mongodb_repo::MongoRepo};
use mongodb::results::InsertOneResult;
use rocket::{response::status::Custom, serde::json::Json, State};
use serde_json::{Value as JsonValue};
extern crate dotenv;
use serde::{Deserialize, Serialize};
use crate::routes::task_routes;
use crate::api::middleware;
use middleware::AuthorizedUser as AuthUser;

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    pub sub: String,
    pub mail: String,
    pub exp: usize,
}


#[post("/addreminder", data = "<new_task>")]
pub fn add_reminder(
    db: &State<MongoRepo>,
    new_task: Json<Task>,
    auth:AuthUser
) -> Result<Json<InsertOneResult>, Custom<JsonValue>> {
    task_routes::add_reminder_route(db, new_task, auth)
}

#[get("/showreminder")]
pub fn get_reminder(db: &State<MongoRepo>, auth:AuthUser) -> Result<Json<Vec<Task>>, Custom<JsonValue>> {
    println!("dcgvcgh: {:?}",auth);
    task_routes::get_reminder_route(db, auth)
}

#[put("/updatereminder/<id>", data = "<new_task>")]
pub fn update_reminder(
    db: &State<MongoRepo>,
    id: String,
    auth:AuthUser,
    new_task: Json<Task>,
) -> Result<Json<Task>, Custom<JsonValue>> {
    task_routes::update_reminder_route(db, id, auth, new_task)
}

#[delete("/deletereminder/<id>")]
pub fn delete_reminder(db: &State<MongoRepo>, id: String, auth:AuthUser) -> Result<Json<&str>, Custom<JsonValue>> {
    task_routes::delete_reminder_route(db, id, auth)
}
