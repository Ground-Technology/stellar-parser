#[path = "../mock.rs"]
mod mock;

use stellar_tvc_example::Error;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "smoke") {
        let mock_url = args
            .get(1)
            .map(String::as_str)
            .unwrap_or("http://127.0.0.1:44021");
        let tvc_url = args
            .get(2)
            .map(String::as_str)
            .unwrap_or("http://tvc:44020");
        let response = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()?
            .post(format!("{mock_url}/test/run"))
            .json(&serde_json::json!({"tvcUrl": tvc_url}))
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(format!("smoke failed ({status}): {body}").into());
        }
        println!("{body}");
        return Ok(());
    }
    let listener = tokio::net::TcpListener::bind("0.0.0.0:44021").await?;
    eprintln!("Mock Turnkey listening on 44021 (local testing only)");
    axum::serve(listener, mock::router(mock::Mock::new())).await?;
    Ok(())
}
