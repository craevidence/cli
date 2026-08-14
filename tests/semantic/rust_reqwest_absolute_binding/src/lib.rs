pub fn insecure_clients() {
    let _ = ::reqwest::Client::builder().danger_accept_invalid_certs(true);
    let _ = ::reqwest::ClientBuilder::new().danger_accept_invalid_hostnames(true);
    let _ = ::reqwest::blocking::Client::builder().danger_accept_invalid_certs(true);
    let _ = ::reqwest::blocking::ClientBuilder::new()
        .danger_accept_invalid_hostnames(true);
}

pub fn outside_the_narrow_profile(enabled: bool) {
    let _ = reqwest::Client::builder().danger_accept_invalid_certs(true);
    let _ = ::reqwest::Client::builder().danger_accept_invalid_certs(false);
    let _ = ::reqwest::Client::builder().danger_accept_invalid_certs(enabled);
}
