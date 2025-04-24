use std::error::Error;
use ureq::{Agent, Error as UreqError};

pub fn get_contents(url: &str) -> Result<String, Box<dyn Error>> {
    let agent = ureq::agent();

    let mut response = agent.get(url).call()?;
    let body = response.body_mut().read_to_string()?;

    if body.is_empty() {
        return Err("content not found".into());
    }
    println!("[i] Body: {}", body.len());

    Ok(body)
}