use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};

pub fn init_socket(path: &str) -> io::Result<UnixListener> {
    let _ = fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    println!("Listening on {}", path);
    Ok(listener)
}

pub fn accept_connection(listener: &UnixListener) -> io::Result<UnixStream> {
    let (stream, _addr) = listener.accept()?;
    Ok(stream)
}

pub fn send_message(client: &mut UnixStream, msg: &str) -> io::Result<()> {
    client.write_all(msg.as_bytes())
}

pub fn receive_message(client: &mut UnixStream, buf: &mut [u8]) -> io::Result<usize> {
    client.read(buf)
}
