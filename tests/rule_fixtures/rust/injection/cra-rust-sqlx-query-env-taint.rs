fn requested_name() -> String {
    std::env::var("USER_NAME").unwrap_or_default()
}

fn bad_across_helper() {
    let name = requested_name();
    let query_text = format!("SELECT * FROM users WHERE name = '{}'", name);
    // ruleid: cra-rust-sqlx-query-env-taint
    let query = sqlx::query(&query_text);
}

fn bad() {
    let name = std::env::args().nth(1).unwrap_or_default();
    // ruleid: cra-rust-sqlx-query-env-taint
    let query = sqlx::query(&format!("SELECT * FROM users WHERE name = '{}'", name));
}

fn bad_query_scalar() {
    let name = std::env::var("USER_NAME").unwrap_or_default();
    let query_text = format!("SELECT id FROM users WHERE name = '{}'", name);
    // ruleid: cra-rust-sqlx-query-env-taint
    let query = sqlx::query_scalar(&query_text);
}

fn good() {
    let name = std::env::var("USER_NAME").unwrap_or_default();
    // ok: cra-rust-sqlx-query-env-taint
    let query = sqlx::query("SELECT * FROM users WHERE name = ?").bind(name);
}
