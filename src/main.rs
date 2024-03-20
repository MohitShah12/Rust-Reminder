mod repository;
mod models;
mod api;

#[macro_use]
extern crate rocket;

use api::user_api::{create_user, login};
use repository::mongodb_repo::MongoRepo;
use rocket::{Rocket, build};

#[launch]
fn rocket() -> _ {
    println!("Rocket was launched");
    let db = MongoRepo::create_db();

    rocket::build()
        .manage(db)
        .mount("/", routes![create_user,login])
}
