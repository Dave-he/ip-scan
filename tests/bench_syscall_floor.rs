//! Microbenchmark for the raw syscall floor on this host.
//!
//! Runs a tight loop of `socket(2) + close(2)` and measures the
//! achievable per-syscall iteration rate. This is the theoretical
//! ceiling for the connect scanner: any connect cycle has to do at
//! least one `socket(2) + close(2) + connect(2)` triple, so the
//! floor here sets a hard upper bound on pps even with zero in-Rust
//! overhead.
//!
//! Run with:
//!   cargo test --release --test bench_syscall_floor -- --nocapture --test-threads=1

use std::time::Instant;

#[test]
fn bench_socket_close_only() {
    let iterations: u64 = 200_000;
    let start = Instant::now();
    let mut total: u64 = 0;
    unsafe {
        for _ in 0..iterations {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, libc::IPPROTO_TCP);
            if fd >= 0 {
                libc::close(fd);
                total += 1;
            }
        }
    }
    let elapsed = start.elapsed();
    let secs = elapsed.as_secs_f64();
    eprintln!(
        "[syscall-floor] iterations={} succeeded={} elapsed={:.3}s \
         per_iter={:.2} µs floor_pps={:.0}",
        iterations,
        total,
        secs,
        elapsed.as_micros() as f64 / total as f64,
        total as f64 / secs,
    );
    assert!(total > 0, "no sockets succeeded");
}

#[test]
fn bench_socket_close_with_fcntl() {
    // socket(2) + fcntl(F_SETFL, O_NONBLOCK) + close(2): the exact
    // trio the scanner does per probe (modulo the connect() call).
    let iterations: u64 = 100_000;
    let start = Instant::now();
    let mut total: u64 = 0;
    unsafe {
        for _ in 0..iterations {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, libc::IPPROTO_TCP);
            if fd >= 0 {
                libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
                libc::close(fd);
                total += 1;
            }
        }
    }
    let elapsed = start.elapsed();
    let secs = elapsed.as_secs_f64();
    eprintln!(
        "[syscall-floor-with-fcntl] iterations={} succeeded={} elapsed={:.3}s \
         per_iter={:.2} µs floor_pps={:.0}",
        iterations,
        total,
        secs,
        elapsed.as_micros() as f64 / total as f64,
        total as f64 / secs,
    );
    assert!(total > 0, "no sockets succeeded");
}

#[test]
fn bench_connect_close_only() {
    // The full per-probe cost on loopback: socket + fcntl + connect +
    // close. This is what the scanner does, with no poll() / no
    // InFlight bookkeeping. The pps this achieves is the absolute
    // upper bound for our scanner on this host.
    let iterations: u64 = 20_000;
    let addr = libc::sockaddr_in {
        sin_len: 0,
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 1u16.to_be(),
        sin_addr: libc::in_addr {
            s_addr: 0x0100007f_u32.to_be(),
        }, // 127.0.0.1
        sin_zero: [0; 8],
    };
    let start = Instant::now();
    let mut total: u64 = 0;
    unsafe {
        for _ in 0..iterations {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, libc::IPPROTO_TCP);
            if fd < 0 {
                continue;
            }
            libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
            libc::connect(
                fd,
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
            libc::close(fd);
            total += 1;
        }
    }
    let elapsed = start.elapsed();
    let secs = elapsed.as_secs_f64();
    eprintln!(
        "[syscall-floor-full-connect] iterations={} succeeded={} elapsed={:.3}s \
         per_iter={:.2} µs floor_pps={:.0}",
        iterations,
        total,
        secs,
        elapsed.as_micros() as f64 / total as f64,
        total as f64 / secs,
    );
    assert!(total > 0, "no connects succeeded");
}
