use lettre::{Message, SmtpTransport, Transport, message::{Mailbox}};
use std::error::Error;
use lettre::transport::smtp::authentication::{Credentials};
use regex::Regex;
extern crate dotenv;
use dotenv::dotenv;
use std::env;


pub fn is_valid_email(email:&str) -> bool{
    let reg = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
    reg.is_match(email)
}
pub fn is_valid_password(password:&str) -> bool{
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

pub fn send_email_notification(recipient:&str, task_name:&str, task_desc:&str)->Result<(), Box<dyn Error>>{
    dotenv().ok();
    let email_message = format!("This is a Reminder for your Task...🗒️ \n Task name : {} \n Description : {}", task_name, task_desc);
    let mail_add = match env::var("MAIL_ID") {
        Ok(mail) => mail,
        Err(e) =>  format!("No mail found {}",e)
    };

    let pass = match env::var("PASSWORD") {
        Ok(mail) => mail,
        Err(e) =>  format!("No password found {}",e)
    };
    let sender_mailbox = Mailbox::new(None, mail_add.parse().unwrap());
    let recipient_mailbox = Mailbox::new(None, recipient.parse().unwrap());
    let email = Message::builder()
        .from(sender_mailbox)
        .to(recipient_mailbox)
        .subject("Task Reminder")
        .body(email_message)
        .unwrap();

    let credentials = Credentials::new(mail_add.to_string(), pass.to_string());

    let mailer = SmtpTransport::relay("smtp.gmail.com")
        .unwrap()
        .credentials(credentials)
        .build();

 let result = mailer.send(&email);
    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(Box::new(e)),
    }

}