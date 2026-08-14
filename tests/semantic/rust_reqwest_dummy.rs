pub struct Client;

pub struct ClientBuilder;

impl Client {
    pub fn builder() -> ClientBuilder {
        ClientBuilder
    }
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn danger_accept_invalid_certs(self, _enabled: bool) -> Self {
        self
    }

    pub fn danger_accept_invalid_hostnames(self, _enabled: bool) -> Self {
        self
    }
}

pub mod blocking {
    pub use super::ClientBuilder;

    pub struct Client;

    impl Client {
        pub fn builder() -> ClientBuilder {
            ClientBuilder
        }
    }
}
