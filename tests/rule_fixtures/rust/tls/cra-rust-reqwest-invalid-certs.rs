fn bad() -> reqwest::Client {
    // ruleid: cra-rust-reqwest-invalid-certs
    reqwest::Client::builder().danger_accept_invalid_certs(true).build().unwrap()
}

fn bad_hostname_validation() -> reqwest::Client {
    // ruleid: cra-rust-reqwest-invalid-certs
    reqwest::Client::builder().danger_accept_invalid_hostnames(true).build().unwrap()
}

fn bad_tls_hostname_validation() -> reqwest::Client {
    // ruleid: cra-rust-reqwest-invalid-certs
    reqwest::Client::builder().tls_danger_accept_invalid_hostnames(true).build().unwrap()
}

fn good() -> reqwest::Client {
    // ok: cra-rust-reqwest-invalid-certs
    reqwest::Client::builder().danger_accept_invalid_certs(false).build().unwrap()
}

#[cfg(test)]
mod tests {
    fn fixture_client() -> reqwest::Client {
        // ok: cra-rust-reqwest-invalid-certs
        reqwest::Client::builder().danger_accept_invalid_certs(true).build().unwrap()
    }
}
