//! Test-only HTTP mock server shared by the `github` and `sources` test
//! modules (offline tests: no real GitHub call is ever made).
//!
// Tests may unwrap, expect and panic freely: a failing assertion must
// be loud, so the zero-panic lints do not apply to this test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub(crate) fn serve_requests(
    respond: impl Fn(usize, &[String]) -> (u16, Vec<(String, String)>, String) + Send + Sync + 'static,
) -> (String, MockServer) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("test setup: bind mock server");
    let address = listener
        .local_addr()
        .expect("test setup: local addr")
        .to_string();
    let stop = Arc::new(AtomicBool::new(false));
    let handled = Arc::new(AtomicUsize::new(0));
    let last_activity = Arc::new(std::sync::Mutex::new(Instant::now()));
    let handles = Arc::new(std::sync::Mutex::new(Vec::new()));
    let respond = Arc::new(respond);

    {
        let stop = Arc::clone(&stop);
        let handled = Arc::clone(&handled);
        let last_activity = Arc::clone(&last_activity);
        let handles = Arc::clone(&handles);
        let respond = Arc::clone(&respond);
        std::thread::spawn(move || {
            listener
                .set_nonblocking(true)
                .expect("test setup: nonblocking listener");
            loop {
                // the test asked for shutdown, the client went quiet for a
                // long while (forgotten join safety net), or the hard
                // overall deadline was reached
                let quiet = handled.load(Ordering::Relaxed) > 0
                    && last_activity.lock().expect("test bookkeeping").elapsed()
                        > Duration::from_secs(10);
                if stop.load(Ordering::Relaxed)
                    || quiet
                    || last_activity.lock().expect("test bookkeeping").elapsed()
                        > Duration::from_secs(30)
                {
                    break;
                }
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => {
                        *last_activity.lock().expect("test bookkeeping") = Instant::now();
                        stream
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => break,
                };
                // Keep-alive: serve every request of this connection before
                // accepting a new one. One connection per scan instead of
                // one per request avoids the Windows loopback connection
                // aborts (10053) that rapid connect/close cycles trigger
                // under parallel test load. The read timeout keeps the
                // shutdown flags responsive while the connection idles
                // between requests. Each connection runs on its own thread
                // so a parallel worker's idle pooled connection never
                // starves another worker's requests.
                let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                let _ = stream.set_nodelay(true);
                let handled = Arc::clone(&handled);
                let last_activity = Arc::clone(&last_activity);
                let respond = Arc::clone(&respond);
                let stop = Arc::clone(&stop);
                let connection = std::thread::spawn(move || {
                    let mut reader = BufReader::new(match stream.try_clone() {
                        Ok(reader) => reader,
                        Err(_) => return,
                    });
                    loop {
                        let mut request_lines: Vec<String> = Vec::new();
                        let mut closed = false;
                        // one accumulating buffer per request: a read
                        // timeout keeps whatever partial bytes were already
                        // read, so a request line split across the timeout
                        // is never lost
                        let mut line = String::new();
                        loop {
                            match reader.read_line(&mut line) {
                                Ok(0) => {
                                    closed = true;
                                    break;
                                }
                                Err(ref err)
                                    if err.kind() == std::io::ErrorKind::WouldBlock
                                        || err.kind() == std::io::ErrorKind::TimedOut =>
                                {
                                    // idle keep-alive connection: check the
                                    // shutdown flag, then keep reading
                                    // (`line` preserves any partial request
                                    // line)
                                    if stop.load(Ordering::Relaxed) {
                                        return;
                                    }
                                    continue;
                                }
                                Err(_) => {
                                    closed = true;
                                    break;
                                }
                                Ok(_) => {
                                    if !line.ends_with('\n') {
                                        continue;
                                    }
                                    if line.trim().is_empty() {
                                        break; // end of the request headers
                                    }
                                    request_lines.push(line.trim_end().to_string());
                                    line.clear();
                                }
                            }
                        }
                        // HTTP clients may open extra idle connections that
                        // carry no request: do not count them as handled
                        // requests.
                        if !request_lines.is_empty() {
                            let index = handled.fetch_add(1, Ordering::Relaxed);
                            *last_activity.lock().expect("test bookkeeping") = Instant::now();
                            let (status, headers, body) = respond(index, &request_lines);
                            let reason = match status {
                                200 => "OK",
                                403 => "Forbidden",
                                404 => "Not Found",
                                429 => "Too Many Requests",
                                _ => "Error",
                            };
                            let mut response = format!(
                                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
                                body.len()
                            );
                            for (name, value) in &headers {
                                response.push_str(&format!("{name}: {value}\r\n"));
                            }
                            response.push_str("\r\n");
                            response.push_str(&body);
                            let _ = stream.write_all(response.as_bytes());
                        }
                        if closed || stop.load(Ordering::Relaxed) {
                            return;
                        }
                    }
                });
                handles.lock().expect("test bookkeeping").push(connection);
            }
        })
    };
    (
        format!("http://{address}"),
        MockServer {
            stop,
            handled,
            handles,
        },
    )
}

/// Handle over a running mock server: [`MockServer::join`] asks the server
/// to stop (no quiet window to wait out) and returns the number of requests
/// it handled.
pub(crate) struct MockServer {
    stop: Arc<std::sync::atomic::AtomicBool>,
    handled: Arc<AtomicUsize>,
    handles: Arc<std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>>,
}

impl MockServer {
    /// Asks the server thread to stop and returns the number of requests it
    /// handled.
    pub(crate) fn join(self) -> usize {
        self.stop.store(true, Ordering::Relaxed);
        let handles = self
            .handles
            .lock()
            .expect("test bookkeeping")
            .drain(..)
            .collect::<Vec<_>>();
        for handle in handles {
            let _ = handle.join();
        }
        self.handled.load(Ordering::Relaxed)
    }
}

/// Reads one request header from a mock request's request lines
/// (case-insensitive name match).
pub(crate) fn request_header<'a>(request_lines: &'a [String], name: &str) -> Option<&'a str> {
    let prefix = format!("{name}: ");
    request_lines
        .iter()
        .find(|line| line.to_lowercase().starts_with(&prefix.to_lowercase()))
        .map(|line| line[prefix.len()..].trim())
}

/// Extracts the `page=` query parameter of a mock request's request line
/// (0 when absent or unparsable).
pub(crate) fn request_line_page(request_lines: &[String]) -> u16 {
    request_lines
        .first()
        .and_then(|line| line.split("page=").nth(1))
        .and_then(|rest| rest.split(' ').next())
        .and_then(|page| page.parse().ok())
        .unwrap_or(0)
}
