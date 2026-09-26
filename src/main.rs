mod http::http;
mod graphql:schema;
mod graphql::scan;
mod sock::sock;

/// Mirrors the original `int graphql_scanning(char *path, bool gobuster, char target_url)`
/// entry point, returning a C-style exit code.
pub fn run_graphql_scanning(path: &str, gobuster: bool, target_url: Option<&str>) -> i32 {
    match scan::graphql_scanning(path, gobuster, target_url) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("scan failed: {}", e);
            1
        }
    }
}

fn main() {
    // Example: scan a single explicit target, no gobuster wordlist.
    // let code = run_graphql_scanning("./output", false, Some("https://example.com/graphql"));

    // Example: filter a gobuster.txt in ./output for api/graphql paths first.
    // let code = run_graphql_scanning("./output", true, None);
}
