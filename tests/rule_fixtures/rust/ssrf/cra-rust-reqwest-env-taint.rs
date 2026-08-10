fn requested_url() -> String {
    std::env::var("FETCH_URL").unwrap_or_default()
}

async fn bad_across_helper() {
    let target = requested_url();
    // ruleid: cra-rust-reqwest-env-taint
    let _response = reqwest::get(target).await;
}

async fn bad() {
    let target = std::env::args().nth(1).unwrap_or_default();
    // ruleid: cra-rust-reqwest-env-taint
    let _response = reqwest::get(target).await;
}

async fn bad_post() {
    let target = std::env::var("WEBHOOK_URL").unwrap_or_default();
    let client = reqwest::Client::new();
    // ruleid: cra-rust-reqwest-env-taint
    let _response = client.post(target).send().await;
}

async fn good() {
    // ok: cra-rust-reqwest-env-taint
    let _response = reqwest::get("https://updates.example.com/manifest.json").await;
}
