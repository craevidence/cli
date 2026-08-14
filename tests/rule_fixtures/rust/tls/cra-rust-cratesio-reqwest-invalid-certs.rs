fn direct_async() {
    // ruleid: cra-rust-cratesio-reqwest-invalid-certs
    let _ = ::reqwest::Client::builder().danger_accept_invalid_certs(true);

    // ruleid: cra-rust-cratesio-reqwest-invalid-certs
    let _ = ::reqwest::ClientBuilder::new().danger_accept_invalid_hostnames(true);
}

fn direct_blocking() {
    // ruleid: cra-rust-cratesio-reqwest-invalid-certs
    let _ = ::reqwest::blocking::Client::builder().danger_accept_invalid_certs(true);

    // ruleid: cra-rust-cratesio-reqwest-invalid-certs
    let _ = ::reqwest::blocking::ClientBuilder::new()
        .danger_accept_invalid_hostnames(true);
}

fn unsupported_or_safe() {
    // ok: cra-rust-cratesio-reqwest-invalid-certs
    let _ = reqwest::Client::builder().danger_accept_invalid_certs(true);

    // ok: cra-rust-cratesio-reqwest-invalid-certs
    let _ = ::reqwest::Client::builder().danger_accept_invalid_certs(false);

    let enabled = true;
    // ok: cra-rust-cratesio-reqwest-invalid-certs
    let _ = ::reqwest::Client::builder().danger_accept_invalid_certs(enabled);

    // ok: cra-rust-cratesio-reqwest-invalid-certs
    let _ = ::reqwest::Client::builder().timeout(timeout())
        .danger_accept_invalid_certs(true);
}
