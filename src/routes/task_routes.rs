use crate::{models::{task_model::Task}, repository::mongodb_repo::MongoRepo};
use mongodb::results::InsertOneResult;
use rocket::{http::Status, response::status::Custom, serde::json::Json,State};
use mongodb::bson::{oid::ObjectId};
use std::thread;
use chrono::{DateTime, ParseError, Utc};
use serde_json::{json, Value as JsonValue};
extern crate dotenv;
use crate::api::helper;
use crate::api::middleware;
use middleware::AuthorizedUser;
use image::GenericImageView;

fn parse_remider_date(date_str: &str) -> Result<DateTime<Utc>, ParseError> {
    println!("Date: {}", date_str);
    DateTime::parse_from_rfc3339(date_str).map(|dt| dt.with_timezone(&Utc))
}


//add task : /api/addtask
pub fn add_reminder_route(
    db: &State<MongoRepo>,
    new_task: Json<Task>,
    auth:AuthorizedUser
) -> Result<Json<InsertOneResult>, Custom<JsonValue>> {
    let new_task_data = new_task.into_inner();
    println!("Check Task: {}", new_task_data.task.is_empty());
    println!("Auth: {:?}",auth);
    println!("id : {:?}",auth.sub);
    println!("mail : {:?}",auth.mail);

    //getting user id from token and converting it to Option<ObjectId>
    let user_id = match ObjectId::parse_str(auth.sub){
        Ok(object_id) => Some(object_id),
        Err(_) => None,
    };

    //validating task
    if new_task_data.task.is_empty() {
        let json_response = json!({"error" : "Please provide a task"});
        return Err(Custom(Status::BadRequest, json_response.into()));
    }

    //validating description
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
        println!("new date: {}", parse_date);
    }
    let task_image = new_task_data.image.to_owned();

    //creating new task
    let task_data = Task {
        id: None,
        task: new_task_data.task.to_owned(),
        description: new_task_data.description.to_owned(),
        reminder_date: new_task_data.reminder_date,
        user_id:Some(user_id.expect("REASON")),
        user_email: Some(auth.mail),
        image: task_image.clone()
    };
    let img = image::open(task_image.as_ref().unwrap()).expect("Failed to open image");
    img.save("TaskImg.jpeg").expect("Failed to save image");
    //calling the mongodb create task function
    let task_detail = db.db_create_task(task_data);
    match task_detail {
        Ok(reminder) => Ok(Json(reminder)),
        Err(_) => {
            let json_response = json!({ "error": "Internal Server Error" });
            Err(Custom(Status::InternalServerError, json_response.into()))
        }
    }
}


//get all the reminders of user : /api/showreminders
pub fn get_reminder_route(db: &State<MongoRepo>, auth:AuthorizedUser) -> Result<Json<Vec<Task>>, Custom<JsonValue>> {
    //from mail fecting all the mathcing reminders
    let task_details = db.get_all_tasks(&auth.mail);
    println!("task details :{:?}",task_details.clone().unwrap().len());

    //if users have no reminders
    if task_details.clone().unwrap().len() == 0{
        //if there are no tasks to show
        let json_response = json!({"no reminders":"No reminders to show"});
        return Err(Custom(Status::NotFound, json_response.into()));
    }
    let task_vec = match task_details {
        Ok(tasks) => tasks,
        Err(_) => return Err(Custom(Status::NotFound, json!({ "error": "No tasks found" }).into())),
    };

    
    // Iterate over tasks to schedule reminders
    for task in &task_vec {
        if let Some(reminder_date) = task.reminder_date {
            let now = Utc::now();
            let email = auth.mail.clone();
            // println!("email of user: {}",email);
            if reminder_date <= now {
                // Send reminder when the time is equal to the Utc time
                if reminder_date == now{
                    if let Err(err) = helper::send_email_notification(&email, &task.task, &task.description) {
                        println!("Failed to send reminder for task {}: {}", task.task, err);
                    } else {
                        println!("Reminder sent for task {}", task.task);
                    }
                }
            } else {
                // Calculate the duration to wait before sending the reminder
                let duration_until_reminder = reminder_date.signed_duration_since(now).to_std().unwrap();
                let task_clone = task.clone();
                thread::spawn(move || {
                    thread::sleep(duration_until_reminder);
                    if let Err(err) = helper::send_email_notification(&email, &task_clone.task, &task_clone.description) {
                        println!("Failed to send reminder for task {}: {}", task_clone.task, err);
                    } else {
                        println!("Reminder sent for task {}", task_clone.task);
                    }
                });
            }
        }
    }

    // Return the Vec<Task> as JSON
    Ok(Json(task_vec))
}

//update all the reminders /api/updarereminder/:id
pub fn update_reminder_route(
    db: &State<MongoRepo>,
    id: String,
    auth:AuthorizedUser,
    new_task: Json<Task>,
) -> Result<Json<Task>, Custom<JsonValue>> {
    //get id from params
    let id = id;

    //get userid from toke
    let user_id = match ObjectId::parse_str(auth.sub){
        Ok(object_id) => Some(object_id),
        Err(_) => None,
    };
    if id.is_empty() {
        let json_response = json!({"error":"Id of task is requires"});
        return Err(Custom(Status::BadRequest, json_response.into()));
    }
     let task_image = new_task.image.to_owned();

     //updating te task
    let new_task_data = Task {
        id: None,
        task: new_task.task.to_owned(),
        description: new_task.description.to_owned(),
        reminder_date: new_task.reminder_date,
        user_id:Some(user_id.expect("REASON")),
        user_email:Some(auth.mail),
        image:task_image.clone()
    };
    //validating provided task
    if new_task_data.task.is_empty() {
        let json_response = json!({"error" : "Please provide a task"});
        return Err(Custom(Status::BadRequest, json_response.into()));
    }
    //validating provided description
    if new_task_data.description.is_empty() {
        let json_response = json!({"error" : "Please provide a description"});
        return Err(Custom(Status::BadRequest, json_response.into()));
    }
    let new_task_detail = db.update_task(&id, &new_task_data);
    //validating provided date
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
        println!("new date: {}", parse_date);
    }

    match new_task_detail {
        Ok(update) => {
            if update.matched_count == 1 {
                let updated_task = new_task_data;
                return Ok(Json(updated_task));
            } else {
                //if id is invalid
                let json_response = json!({ "error": "No task with given id was found" });
                Err(Custom(Status::NotFound, json_response.into()))
            }
        }
        Err(_) => {
            let json_response = json!({ "error": "No tasks was updated" });
            Err(Custom(Status::NotFound, json_response.into()))
        }
    }
}


//deleting task : /api/deletereminder/:id
pub fn delete_reminder_route(db: &State<MongoRepo>, id: String, auth:AuthorizedUser) -> Result<Json<&str>, Custom<JsonValue>> {
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
                //if id is invalid
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
