mod repository;
mod models;
mod api;
mod private;
mod routes;

#[macro_use]
extern crate rocket;

use api::user_api::{create_user, login};
use api::task_api::{add_reminder,get_reminder,update_reminder,delete_reminder};
use repository::mongodb_repo::MongoRepo;
// use rocket::{Rocket, build};

#[launch]
fn rocket() -> _ {
    println!("Rocket was launched");
    let db = MongoRepo::create_db();

    rocket::build()
        .manage(db)
        .configure(rocket::Config::figment().merge(("port", 3000)))
        .mount("/", routes![create_user,login])
        .mount("/api", routes![add_reminder,get_reminder,update_reminder,delete_reminder])
}
