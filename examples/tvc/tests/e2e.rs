#[path = "../src/mock.rs"]
mod mock;

use stellar_tvc_example::{Config, Error};
use turnkey_api_key_stamper::{Stamp, TurnkeyP256ApiKey};

async fn serve(router: axum::Router) -> Result<(String, tokio::task::JoinHandle<()>), Error> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.expect("HTTP server");
    });
    Ok((format!("http://{address}"), task))
}

#[tokio::test]
async fn signed_webhook_to_signed_vote_over_http() -> Result<(), Error> {
    let state = mock::Mock::new();
    let (mock_url, mock_task) = serve(mock::router(state.clone())).await?;
    let config = Config {
        organization_id: mock::ORGANIZATION.into(),
        network_passphrase: mock::NETWORK.into(),
        allowed_contract: mock::CONTRACT.parse()?,
        turnkey_api_url: mock_url.clone(),
    };
    let (app_url, app_task) = serve(stellar_tvc_example::router(
        config,
        TurnkeyP256ApiKey::generate(),
    )?)
    .await?;
    let result = reqwest::Client::new()
        .post(format!("{mock_url}/test/run"))
        .json(&serde_json::json!({"tvcUrl": app_url}))
        .send()
        .await?;
    let status = result.status();
    let body = result.text().await?;
    assert!(status.is_success(), "{status}: {body}");
    let result: serde_json::Value = serde_json::from_str(&body)?;
    assert!(
        result["passed"].as_u64().is_some_and(|count| count >= 25),
        "{body}"
    );
    let request =
        serde_json::json!({"organizationId": mock::ORGANIZATION, "activityId": "delivery-checks"})
            .to_string();
    let key = TurnkeyP256ApiKey::generate();
    let stamp = key.stamp(request.as_bytes())?;
    let response = reqwest::Client::new()
        .post(format!("{mock_url}/public/v1/query/get_activity"))
        .header(&stamp.name, &stamp.value)
        .body(request)
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    app_task.abort();
    mock_task.abort();
    Ok(())
}
