use std::env;
use std::str::FromStr;
extern crate dotenv;
use dotenv::dotenv;
use mongodb::error::Error as MongoError;
use chrono::{DateTime, Utc};
use mongodb::bson::{Bson};

use mongodb::{
    bson::{extjson::de::Error, oid::ObjectId, doc},
    results::{InsertOneResult, UpdateResult, DeleteResult},
    sync::{Client, Collection}
};

use crate::models::user_model::User;
use crate::models::task_model::Task;

pub struct MongoRepo{
    user_col : Collection<User>,
    task_col : Collection<Task>
}

fn convert_to_bson_datetime(date: DateTime<Utc>) -> mongodb::bson::DateTime {
    let timestamp = date.timestamp();
    let milliseconds = timestamp * 1000 + date.timestamp_subsec_millis() as i64;
    mongodb::bson::DateTime::from_millis(milliseconds)
}


impl MongoRepo{

    //crearting the database
    pub fn create_db() -> Self{
        dotenv().ok();
        let uri = match env::var("MONGOURI"){
            Ok(v) => v.to_string(),
            Err(_) => format!("Error in loading env variable")
        };

        println!("mongouri:{}",uri);
        let client = Client::with_uri_str(uri).unwrap();
        let db = client.database("Rust_Reminder");
        //creating user collection
        let user_col = db.collection::<User>("users");
        //creating task collection
        let task_col = db.collection::<Task>("tasks");
        MongoRepo { user_col,task_col }
    }

    //creating new user
    pub fn db_create_user(&self , new_user:User) -> Result<InsertOneResult,Error>{
        //getting all datas from user
        let new_user_doc = User{
            id:None,
            name:new_user.name,
            email:new_user.email,
            password:new_user.password
        };
        //creating a user
        let user = self.user_col.insert_one(new_user_doc, None).ok().expect("failed to create user");

        Ok(user)
    }

    //finding the user from email id
    pub fn find_user_by_email(&self, email:&str) -> Result<Option<User>, String> {
        let filter = doc! {"email": email};
        match self.user_col.find_one(filter,None) {
            Ok(Some(user)) => Ok(Some(user)),
            Ok(None) => Err(String::from("User was not found")),
            Err(e) => Err(format!("Error: {}",e))
        }
    }

    //creating a new task
    pub fn db_create_task(&self, new_task:Task) -> Result<InsertOneResult,Error>{
        //getting all datas from user
        let new_task_doc = Task{
            id:None,
            task:new_task.task,
            description:new_task.description,
            reminder_date:new_task.reminder_date,
            user_id:new_task.user_id,
            user_email:new_task.user_email,
            image:new_task.image

        };
        let task = self.task_col.insert_one(new_task_doc,None).ok().expect("failed to load task");
        Ok(task)
    }
    //finding user from id
    pub fn find_user_from_id(&self, id:Option<ObjectId>) -> Result<Option<User>,String>{
        let filter = doc!{"_id":id.unwrap()};
        match self.user_col.find_one(filter,None){
            Ok(Some(user)) => Ok(Some(user)),
            Ok(None) => Err(String::from("No users found")),
            Err(e) => Err(format!("Error: {}",e)) 
        }
    }

    //getting all the tasks from the given user
    pub fn get_all_tasks(&self, id:String) -> Result<Vec<Task>, MongoError> {
        let uid = match ObjectId::from_str(id.as_str()) {
            Ok(id) => Some(id),
            Err(_) => None
        };
        println!("{:?}",uid.unwrap());
        let filter = doc!{"user_id":uid.unwrap()};
        println!("{}",filter);
        let cursor = self.task_col.find(filter, None).unwrap();
        let users = cursor.map(|doc| doc.unwrap()).collect();
        Ok(users)
    }

    //updating the task
    pub fn update_task(&self, id:&String,new_task:&Task) -> Result<UpdateResult, MongoError>{
        //getting objectd from params
        let obj_id = ObjectId::parse_str(id).unwrap();
        //finding task from the given id
        let filter= doc!{"_id":obj_id};
        let reminder_date_bson = match new_task.reminder_date {
            Some(date) => Some(Bson::DateTime(convert_to_bson_datetime(date))),
            None => None,
        };
        //updating the task
        let new_doc = doc!{
            "$set":{
                "id":new_task.id,
                "task":&new_task.task,
                "description":&new_task.description,
                "reminder_date":reminder_date_bson
            },
        };
        match self.task_col.update_one(filter, new_doc, None){
            Ok(result) => Ok(result),
            Err(e) => Err(e)
            
        }
    }
    //deleting task
    pub fn delete_task(&self , id:&String) -> Result<DeleteResult, MongoError>{
        //getting objectd from params
        let obj_id= ObjectId::parse_str(id).unwrap();
        //finding task from the given id
        let filter = doc!{"_id":obj_id};
        match self.task_col.delete_one(filter, None) {
            Ok(result) => Ok(result),
            Err(e) => Err(e)
        }
    }

}