use std::fs;
use std::io::{self, Write};

use crate::http::{self, Request};
use crate::schema;
use crate::sock;

const SOCK_PATH: &str = "/tmp/sentinel.sock";

/// Reads a file and returns its content starting at the first `{`,
/// mirroring the C version's preamble-skipping behavior (useful when
/// a response has stray text/headers before the JSON body).
pub fn read_json_from_file(filename: &str) -> io::Result<String> {
    let raw = fs::read_to_string(filename)?;
    match raw.find('{') {
        Some(idx) => Ok(raw[idx..].to_string()),
        None => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no JSON object found",
        )),
    }
}

/// Parses a JSON file as a GraphQL introspection result and returns a
/// formatted schema + security report as a String.
///
/// The C version instead prints straight to stdout and, when the
/// caller wants that output as a string (`capture_introspection_check`),
/// has to `dup2()` stdout into a temporary `open_memstream()` FILE*,
/// call this function for its side effects, then restore stdout and
/// read back what was captured. Returning the String directly here
/// makes that whole dance unnecessary.
pub fn introspection_check(intro_json: &str) -> Result<String, String> {
    let data = read_json_from_file(intro_json).map_err(|e| e.to_string())?;
    let json: serde_json::Value = serde_json::from_str(&data).map_err(|e| e.to_string())?;

    let schema_data = schema::build_schema_data(&json).ok_or("failed to build schema data")?;

    let mut out = String::new();
    out.push_str(&schema::format_schema_data(&schema_data));
    out.push_str(&schema::format_security_analysis(&schema_data));
    Ok(out)
}

/// Probes each URL in `api_path` with a raw introspection-style POST
/// and writes the ones that look like GraphQL endpoints to `graphql_path`.
pub fn detect_graphql(api_path: &str, graphql_path: &str) -> io::Result<bool> {
    let json = fs::read_to_string("glassworm/graphql/uni.json")?;
    let api = fs::read_to_string(api_path)?;
    let mut graphql_file = fs::File::create(graphql_path)?;

    let mut found_any = false;

    for line in api.lines() {
        let api_url = line.trim();
        if api_url.is_empty() {
            continue;
        }

        let mut r = Request::default();
        if !http::http_send_post(Some(&mut r), api_url, false, None, true, Some(&json)) {
            eprintln!("HTTP POST failed for {}", api_url);
            continue;
        }
        if r.code != 200 {
            eprintln!("Non-200 response for {}", api_url);
            continue;
        }

        let resp = match read_json_from_file(&r.filename) {
            Ok(s) => s,
            Err(_) => continue,
        };

        if resp.contains("__schema")
            || resp.contains("\"data\"")
            || resp.contains("\"errors\"")
            || resp.contains("\"query\"")
        {
            println!("[+] GraphQL detected at {}", api_url);
            writeln!(graphql_file, "{}", api_url)?;
            found_any = true;
        }
    }

    Ok(found_any)
}

/// Main orchestration:
///   For each URL in graphql.txt:
///     1. send introspection query over the socket
///     2. receive the peer's JSON reply over the socket
///     3. POST that JSON to the GraphQL endpoint
///     4. analyze the HTTP response
///     5. send the analysis result back over the socket
///   Finish when all URLs are processed.
///
/// `target_url`: the C original declared this as a bare `char`
/// (a single byte), which can't hold a URL -- almost certainly a typo
/// for `char *`. It's typed correctly here as `Option<&str>`, matching
/// how it's actually used (`fprintf(api_file, "%s\n", target_url)`).
pub fn graphql_scanning(path: &str, gobuster: bool, target_url: Option<&str>) -> io::Result<()> {
    let listener = sock::init_socket(SOCK_PATH)?;
    let mut client = sock::accept_connection(&listener)?;

    let introspection_json = fs::read_to_string("glassworm/graphql/introspection.json")?;

    let api_path = format!("{}/api.txt", path);
    let graphql_path = format!("{}/graphql.txt", path);

    if gobuster {
        let gobuster_path = format!("{}/gobuster.txt", path);
        let gobuster_content = fs::read_to_string(&gobuster_path)?;

        let mut api_file = fs::File::create(&api_path)?;
        for line in gobuster_content.lines() {
            let url = line.trim();
            if url.contains("graphql") || url.contains("api") {
                writeln!(api_file, "{}", url)?;
            }
        }
    } else {
        let mut api_file = fs::File::create(&api_path)?;
        if let Some(url) = target_url {
            writeln!(api_file, "{}", url)?;
        }
    }

    match detect_graphql(&api_path, &graphql_path) {
        Ok(true) => println!("[+] GraphQL detection completed."),
        Ok(false) => println!("[-] No GraphQL endpoints found."),
        Err(e) => eprintln!("[-] GraphQL detection error: {}", e),
    }

    let graphql_content = fs::read_to_string(&graphql_path)?;

    let mut sent_count = 0u32;
    let mut recv_buf = vec![0u8; 1024 * 256];

    for line in graphql_content.lines() {
        let graphql_url = line.trim();
        if graphql_url.is_empty() {
            continue;
        }

        // 1) Send the introspection query over the socket.
        if sock::send_message(&mut client, &introspection_json).is_err() {
            eprintln!("[-] socket send failed for {}", graphql_url);
            continue;
        }
        println!("[+] Sent introspection query over socket for {}", graphql_url);

        // 2) Receive the peer's response over the socket.
        let n = match sock::receive_message(&mut client, &mut recv_buf) {
            Ok(n) if n > 0 => n,
            _ => {
                eprintln!("[-] no socket reply for {}", graphql_url);
                continue;
            }
        };
        let recv_text = String::from_utf8_lossy(&recv_buf[..n]).into_owned();

        // 3) POST that response body to the GraphQL endpoint.
        let mut r = Request::default();
        if !http::http_send_post(Some(&mut r), graphql_url, false, None, true, Some(&recv_text)) {
            eprintln!("[-] HTTP POST failed for {}", graphql_url);
            continue;
        }
        if r.code != 200 {
            eprintln!("[-] Non-200 ({}) from {}", r.code, graphql_url);
            continue;
        }
        sent_count += 1;
        println!("[+] Response from {} saved to {}", graphql_url, r.filename);

        // 4) Analyze the HTTP response.
        let analysis = match introspection_check(&r.filename) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("[-] analysis failed for {}: {}", graphql_url, e);
                continue;
            }
        };

        // 5) Send the analysis result back over the socket.
        if sock::send_message(&mut client, &analysis).is_err() {
            eprintln!("[-] socket send (analysis) failed for {}", graphql_url);
            continue;
        }
        println!(
            "[+] Sent analysis ({} bytes) for {}",
            analysis.len(),
            graphql_url
        );
    }

    // 6) Done. Dropping client/listener closes their fds automatically.
    println!("\n[+] Done. {} introspection responses analyzed.", sent_count);

    drop(client);
    drop(listener);
    let _ = fs::remove_file(SOCK_PATH);

    Ok(())
}
