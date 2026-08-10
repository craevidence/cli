use std::process::Command;

fn command_argument() -> String {
    std::env::args().nth(1).unwrap()
}

fn bad_across_helper() {
    let command = command_argument();
    // ruleid: cra-rust-shell-command-env-args
    Command::new("sh").arg("-c").arg(command).status().unwrap();
}

fn bad() {
    let command = std::env::args().nth(1).unwrap();
    // ruleid: cra-rust-shell-command-env-args
    Command::new("sh").arg("-c").arg(command).status().unwrap();
}

fn bad_args() {
    let command = std::env::args().nth(1).unwrap();
    // ruleid: cra-rust-shell-command-env-args
    Command::new("bash").args(["-c", command]).status().unwrap();
}

fn bad_multistatement() {
    let command = std::env::args().nth(1).unwrap();
    let mut process = Command::new("sh");
    process.arg("-c");
    // ruleid: cra-rust-shell-command-env-args
    process.arg(command);
    process.status().unwrap();
}

fn good() {
    let value = std::env::args().nth(1).unwrap();
    // ok: cra-rust-shell-command-env-args
    Command::new("/usr/bin/lookup").arg(value).status().unwrap();
}
