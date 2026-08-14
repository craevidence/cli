extern crate self as reqwest;

pub struct Client;
pub struct Builder;

impl Client {
    pub fn builder() -> Builder {
        Builder
    }
}

impl Builder {
    pub fn danger_accept_invalid_certs(self, _enabled: bool) -> Self {
        self
    }
}

pub fn application_call() {
    let _ = ::reqwest::Client::builder().danger_accept_invalid_certs(true);
}
