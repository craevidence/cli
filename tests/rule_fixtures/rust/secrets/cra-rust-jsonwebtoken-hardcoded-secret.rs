fn bad_encoding_key() {
    // ruleid: cra-rust-jsonwebtoken-hardcoded-secret
    let key = jsonwebtoken::EncodingKey::from_secret(b"development-secret");
}

fn bad_decoding_key() {
    // ruleid: cra-rust-jsonwebtoken-hardcoded-secret
    let key = jsonwebtoken::DecodingKey::from_secret(b"development-secret");
}

fn bad_base64_key() {
    // ruleid: cra-rust-jsonwebtoken-hardcoded-secret
    let key = jsonwebtoken::EncodingKey::from_base64_secret("ZGV2ZWxvcG1lbnQtc2VjcmV0");
}

const EMBEDDED_SECRET: &str = "development-secret";

fn bad_literal_as_bytes() {
    // ruleid: cra-rust-jsonwebtoken-hardcoded-secret
    let key = jsonwebtoken::EncodingKey::from_secret("development-secret".as_bytes());
}

fn bad_const_as_bytes() {
    // ruleid: cra-rust-jsonwebtoken-hardcoded-secret
    let key = jsonwebtoken::DecodingKey::from_secret(EMBEDDED_SECRET.as_bytes());
}

fn good() {
    let secret = std::env::var("JWT_SECRET").unwrap();
    // ok: cra-rust-jsonwebtoken-hardcoded-secret
    let key = jsonwebtoken::EncodingKey::from_secret(secret.as_bytes());
}

fn good_base64_key() {
    let secret = std::env::var("JWT_SECRET_BASE64").unwrap();
    // ok: cra-rust-jsonwebtoken-hardcoded-secret
    let key = jsonwebtoken::EncodingKey::from_base64_secret(&secret);
}

#[cfg(test)]
mod tests {
    fn fixture_key() {
        // ok: cra-rust-jsonwebtoken-hardcoded-secret
        let key = jsonwebtoken::EncodingKey::from_secret(b"test-only-secret");
    }
}


#[cfg(test)]
mod test {
    fn fixture_key() {
        // ok: cra-rust-jsonwebtoken-hardcoded-secret
        let key = jsonwebtoken::EncodingKey::from_secret(b"test-only-secret");
    }
}
