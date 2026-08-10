fn requested_path() -> String {
    std::env::var("DOCUMENT_PATH").unwrap_or_default()
}

fn bad_across_helper() {
    let path = requested_path();
    // ruleid: cra-rust-file-env-taint
    let _content = std::fs::read_to_string(path);
}

fn bad() {
    let path = std::env::args().nth(1).unwrap_or_default();
    // ruleid: cra-rust-file-env-taint
    let _content = std::fs::read(path);
}

async fn bad_tokio_read() {
    let path = std::env::var("DOCUMENT_PATH").unwrap_or_default();
    // ruleid: cra-rust-file-env-taint
    let _content = tokio::fs::read(path).await;
}

fn good() {
    // ok: cra-rust-file-env-taint
    let _content = std::fs::read("/srv/app/config.toml");
}

fn good_canonical_containment() {
    let base = std::fs::canonicalize("/srv/app/documents").unwrap();
    let requested = std::path::PathBuf::from(
        std::env::var("DOCUMENT_PATH").unwrap_or_default(),
    );
    let path = std::fs::canonicalize(base.join(requested)).unwrap();
    if !path.starts_with(&base) {
        return;
    }
    // ok: cra-rust-file-env-taint
    let _content = std::fs::read(path);
}

fn bad_late_containment() {
    let base = std::fs::canonicalize("/srv/app/documents").unwrap();
    let requested = std::path::PathBuf::from(
        std::env::var("DOCUMENT_PATH").unwrap_or_default(),
    );
    let path = std::fs::canonicalize(base.join(requested)).unwrap();
    // ruleid: cra-rust-file-env-taint
    let _content = std::fs::read(&path);
    if !path.starts_with(&base) {
        return;
    }
}

fn bad_uncanonicalized_containment() {
    let base = std::path::PathBuf::from("/srv/app/documents");
    let requested = std::path::PathBuf::from(
        std::env::var("DOCUMENT_PATH").unwrap_or_default(),
    );
    let path = base.join(requested);
    if !path.starts_with(&base) {
        return;
    }
    // ruleid: cra-rust-file-env-taint
    let _content = std::fs::read(path);
}

fn reported_if_let_containment_path_new() {
    let base = std::path::Path::new("/srv/app/documents");
    let requested = std::env::var("DOCUMENT_PATH").unwrap_or_default();
    let candidate = base.join(&requested);
    if let Ok(path) = candidate.canonicalize() {
        if path.starts_with(base) {
            // Correct containment, reported because this shape is not modeled.
            // ruleid: cra-rust-file-env-taint
            let _content = std::fs::read(&path);
        }
    }
}

fn bad_if_let_without_containment() {
    let base = std::path::Path::new("/srv/app/documents");
    let requested = std::env::var("DOCUMENT_PATH").unwrap_or_default();
    let candidate = base.join(&requested);
    if let Ok(path) = candidate.canonicalize() {
        // ruleid: cra-rust-file-env-taint
        let _content = std::fs::read(&path);
    }
}

fn bad_if_let_base_from_process_input() {
    let base = std::env::var("DOCUMENT_ROOT").unwrap();
    let requested = std::env::var("DOCUMENT_PATH").unwrap_or_default();
    let candidate = std::path::PathBuf::from(requested);
    if let Ok(path) = candidate.canonicalize() {
        if path.starts_with(base) {
            // ruleid: cra-rust-file-env-taint
            let _content = std::fs::read(&path);
        }
    }
}

fn bad_if_let_guard_compares_path_to_itself() {
    let requested = std::env::var("DOCUMENT_PATH").unwrap_or_default();
    let candidate = std::path::PathBuf::from(requested);
    if let Ok(path) = candidate.canonicalize() {
        if path.starts_with(&path) {
            // ruleid: cra-rust-file-env-taint
            let _content = std::fs::read(&path);
        }
    }
}

fn bad_if_let_read_outside_guard_body() {
    let base = std::path::Path::new("/srv/app/documents");
    let requested = std::env::var("DOCUMENT_PATH").unwrap_or_default();
    let candidate = base.join(&requested);
    if let Ok(path) = candidate.canonicalize() {
        if path.starts_with(base) {
            println!("contained");
        }
        // ruleid: cra-rust-file-env-taint
        let _content = std::fs::read(&path);
    }
}

fn bad_if_let_base_reassigned_from_process_input() {
    let mut base = std::path::PathBuf::from("/srv/app/documents");
    base = std::path::PathBuf::from(std::env::var("DOCUMENT_ROOT").unwrap());
    let requested = std::env::var("DOCUMENT_PATH").unwrap_or_default();
    let candidate = std::path::PathBuf::from(requested);
    if let Ok(path) = candidate.canonicalize() {
        if path.starts_with(base) {
            // ruleid: cra-rust-file-env-taint
            let _content = std::fs::read(&path);
        }
    }
}

fn bad_match_containment_not_modeled() {
    let base = std::path::Path::new("/srv/app/documents");
    let requested = std::env::var("DOCUMENT_PATH").unwrap_or_default();
    let candidate = base.join(&requested);
    match candidate.canonicalize() {
        Ok(path) => {
            if path.starts_with(base) {
                // ruleid: cra-rust-file-env-taint
                let _content = std::fs::read(&path);
            }
        }
        Err(_) => {}
    }
}

fn reported_if_let_containment_pathbuf_base() {
    let base = std::path::PathBuf::from("/srv/app/documents");
    let requested = std::env::var("DOCUMENT_PATH").unwrap_or_default();
    let candidate = base.join(&requested);
    if let Ok(path) = candidate.canonicalize() {
        if path.starts_with(base) {
            // Correct containment, reported because this shape is not modeled.
            // ruleid: cra-rust-file-env-taint
            let _content = std::fs::read(&path);
        }
    }
}

fn reported_if_let_containment_canonicalized_base() {
    let base = std::fs::canonicalize("/srv/app/documents").unwrap();
    let requested = std::env::var("DOCUMENT_PATH").unwrap_or_default();
    let candidate = base.join(&requested);
    if let Ok(path) = candidate.canonicalize() {
        if path.starts_with(base) {
            // Correct containment, reported because this shape is not modeled.
            // ruleid: cra-rust-file-env-taint
            let _content = std::fs::read(&path);
        }
    }
}
