use std::env;
extern crate dotenv;
use dotenv::dotenv;
use mongodb::bson;
use mongodb::error::Error as MongoError;
use crate::api::user_api::Login;
use pwhash::unix;

use mongodb::{
    bson::{extjson::de::Error, oid::ObjectId, doc, Document},
    results::{InsertOneResult, UpdateResult, DeleteResult},
    sync::{Client, Collection}
};

use crate::models::user_model::User;

pub struct MongoRepo{
    user_col : Collection<User>
}


impl MongoRepo{
    pub fn create_db() -> Self{
        dotenv().ok();
        let uri = match env::var("MONGOURI"){
            Ok(v) => v.to_string(),
            Err(_) => format!("Error in loading env variable")
        };

        println!("mongouri:{}",uri);
        let client = Client::with_uri_str(uri).unwrap();
        let db = client.database("Rust_Reminder");
        let user_col = db.collection::<User>("users");
        MongoRepo { user_col }
    }

    pub fn db_create_user(&self , new_user:User) -> Result<InsertOneResult,Error>{
        let new_user_doc = User{
            id:None,
            name:new_user.name,
            email:new_user.email,
            password:new_user.password
        };

        let user = self.user_col.insert_one(new_user_doc, None).ok().expect("failed to create user");

        Ok(user)
    }


    pub fn find_user_by_email(&self, email:&str) -> Result<Option<User>, String> {
        let filter = doc! {"email": email};
        match self.user_col.find_one(filter,None) {
            Ok(Some(user)) => Ok(Some(user)),
            Ok(None) => Err(String::from("User was not found")),
            Err(e) => Err(format!("Error: {}",e))
        }
    }

    
}