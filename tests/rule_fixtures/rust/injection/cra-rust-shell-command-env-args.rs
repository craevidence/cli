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

fn bad_args_slice_reference() {
    let command = std::env::args().nth(1).unwrap();
    // ruleid: cra-rust-shell-command-env-args
    Command::new("bash").args(&["-c", &command]).status().unwrap();
}

fn bad_args_slice_reference_as_str() {
    let command = std::env::args().nth(1).unwrap();
    // ruleid: cra-rust-shell-command-env-args
    Command::new("bash").args(&["-c", command.as_str()]).status().unwrap();
}

fn bad_collected_args() {
    let arguments: Vec<String> = std::env::args().collect();
    // ruleid: cra-rust-shell-command-env-args
    Command::new("sh").arg("-c").arg(&arguments[1]).status().unwrap();
}

fn bad_var_os() {
    let command = std::env::var_os("BUILD_COMMAND").unwrap();
    // ruleid: cra-rust-shell-command-env-args
    Command::new("sh").arg("-c").arg(command).status().unwrap();
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

fn good_constant_args_slice() {
    // ok: cra-rust-shell-command-env-args
    Command::new("bash").args(&["-c", "id -u"]).status().unwrap();
}
