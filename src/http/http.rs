use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use reqwest::blocking::{multipart, Client};

/// Mirrors the C `request` struct: response code + name of the file
/// the body was saved to.
#[derive(Debug, Default)]
pub struct Request {
    pub code: u16,
    pub filename: String,
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn next_filename() -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("curl_{}.txt", n)
}

fn detect_content_type(filename: &str) -> &'static str {
    match Path::new(filename).extension().and_then(|e| e.to_str()) {
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("txt") => "text/plain",
        Some("html") => "text/html",
        Some("css") => "text/css",
        Some("js") => "application/javascript",
        Some("xml") => "application/xml",
        Some("pdf") => "application/pdf",
        Some("zip") => "application/zip",
        _ => "application/octet-stream",
    }
}

fn build_client() -> reqwest::Result<Client> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::limited(10))
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .user_agent("minilang/1.0")
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
}

fn save_response(
    r: Option<&mut Request>,
    resp: reqwest::blocking::Response,
    filename: &str,
) -> std::io::Result<()> {
    let code = resp.status().as_u16();
    let bytes = resp
        .bytes()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    let mut fp = File::create(filename)?;
    fp.write_all(&bytes)?;

    if let Some(r) = r {
        r.code = code;
        r.filename = filename.to_string();
    }
    Ok(())
}

pub fn http_send_get(r: Option<&mut Request>, url: &str) -> bool {
    let filename = next_filename();

    let client = match build_client() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("client build failed: {}", e);
            return false;
        }
    };

    let resp = match client.get(url).send() {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("GET failed: {}", e);
            return false;
        }
    };

    match save_response(r, resp, &filename) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("failed to save response: {}", e);
            let _ = fs::remove_file(&filename);
            false
        }
    }
}

/// Mirrors `http_send_post`'s three modes: raw body, multipart file
/// upload, or an empty POST, selected the same way the C flags do.
pub fn http_send_post(
    r: Option<&mut Request>,
    url: &str,
    upload: bool,
    data: Option<&str>,
    is_raw: bool,
    raw_data: Option<&str>,
) -> bool {
    let filename = next_filename();

    let client = match build_client() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("client build failed: {}", e);
            return false;
        }
    };

    let mut req = client.post(url);

    if is_raw {
        req = req
            .header("Content-Type", "application/json")
            .body(raw_data.unwrap_or("").to_string());
    } else if upload {
        let data = match data {
            Some(d) => d,
            None => {
                eprintln!("upload requested but no file path given");
                return false;
            }
        };

        if !Path::new(data).is_file() {
            eprintln!("File does not exist: {}", data);
            return false;
        }

        let content_type = detect_content_type(data);
        let part = match multipart::Part::file(data) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("failed to read file {}: {}", data, e);
                return false;
            }
        };
        let part = match part.mime_str(content_type) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("invalid mime type: {}", e);
                return false;
            }
        };

        let form = multipart::Form::new().part("file", part);
        req = req.multipart(form);
    } else {
        req = req.body("");
    }

    let resp = match req.send() {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("POST failed: {}", e);
            return false;
        }
    };

    match save_response(r, resp, &filename) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("failed to save response: {}", e);
            let _ = fs::remove_file(&filename);
            false
        }
    }
}
