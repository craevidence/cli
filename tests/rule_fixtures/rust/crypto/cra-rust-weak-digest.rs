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

fn bad_sha1_default() {
    // ruleid: cra-rust-weak-digest
    let digest = Sha1::default();
}

fn bad_sha1_one_shot(value: &[u8]) {
    // ruleid: cra-rust-weak-digest
    let digest = Sha1::digest(value);
}

fn bad_md5_one_shot(value: &[u8]) {
    // ruleid: cra-rust-weak-digest
    let digest = Md5::digest(value);
}

fn bad_sha1_one_shot_qualified(value: &[u8]) {
    // ruleid: cra-rust-weak-digest
    let digest = sha1::Sha1::digest(value);
}

fn good() {
    // ok: cra-rust-weak-digest
    let digest = sha2::Sha256::new();
}

fn good_one_shot(value: &[u8]) {
    // ok: cra-rust-weak-digest
    let digest = Sha256::digest(value);
}

fn good_default() {
    // ok: cra-rust-weak-digest
    let digest = Sha512::default();
}
