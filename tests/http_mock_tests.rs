#![cfg(feature = "http-mock")]

use httpmock::{Method::GET, MockServer};
use serde_json::json;
use xcloud::{asc::AppStoreConnectClient, Config};

#[tokio::test]
async fn list_ci_products_uses_custom_base_url() {
    let server = MockServer::start();

    let _m = server.mock(|when, then| {
        when.method(GET)
            .path("/v1/ciProducts")
            .query_param("limit", "200");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({"data": [{"id": "prod1", "attributes": {"name":"Demo"}}]}));
    });

    // Build client with mock base URL and a static token to avoid signing logic
    let cfg = Config {
        issuer_id: "ignored".into(),
        key_id: "ignored".into(),
        p8_private_key_pem: "ignored".into(),
    };
    let client = AppStoreConnectClient::new(cfg, true)
        .unwrap()
        .with_static_token("test")
        .with_base_url(reqwest::Url::parse(&server.base_url()).unwrap());

    let products = client.list_ci_products().await.unwrap();
    assert_eq!(products.len(), 1);
    assert_eq!(products[0]["id"], "prod1");
}
