use std::error::Error;

pub async fn get_contents(url: &str) -> Result<String, Box<dyn Error>> {
    let body = reqwest::get(url)
        .await?
        .text()
        .await?;

    if body.is_empty() {
        return Err("content not found".into());
    }
    println!("[i] Body: {}", body.len());

    Ok(body)
}
