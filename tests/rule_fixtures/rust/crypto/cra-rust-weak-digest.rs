fn bad_md5(value: &[u8]) {
    // ruleid: cra-rust-weak-digest
    let digest = md5::compute(value);
}

fn bad_sha1() {
    // ruleid: cra-rust-weak-digest
    let digest = sha1::Sha1::new();
}

fn bad_md5_constructor() {
    // ruleid: cra-rust-weak-digest
    let digest = md5::Md5::new();
}

fn good() {
    // ok: cra-rust-weak-digest
    let digest = sha2::Sha256::new();
}
