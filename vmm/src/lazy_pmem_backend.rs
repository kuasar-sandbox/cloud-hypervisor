// Copyright 2026 The Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

const PROTOCOL_VERSION: u32 = 1;
const MAX_PACKET_SIZE: usize = 64 << 10;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FetchOp {
    Fetch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchRequest {
    protocol_version: u32,
    request_id: String,
    op: FetchOp,
    // The v1 wire contract predates the generic VMM backend naming.
    #[serde(rename = "instance_id")]
    backend_id: String,
    pos: u64,
    len: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FetchRange {
    pub(crate) off: u64,
    pub(crate) len: u64,
    pub(crate) dev_off: u64,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum FetchResponse {
    FetchOk {
        protocol_version: u32,
        request_id: String,
        ranges: Vec<FetchRange>,
    },
    Error {
        protocol_version: u32,
        request_id: String,
        code: u16,
        msg: String,
    },
}

pub(crate) struct FetchResult {
    pub(crate) file: File,
    pub(crate) range: FetchRange,
}

#[derive(Debug, Clone)]
pub(crate) struct LazyPmemBackendClient {
    socket: PathBuf,
    backend_id: String,
    pmem_size: u64,
    page_size: u64,
    timeout: Duration,
}

impl LazyPmemBackendClient {
    pub(crate) fn new(socket: PathBuf, backend_id: String, pmem_size: u64) -> io::Result<Self> {
        if socket.as_os_str().is_empty() {
            return Err(invalid_input("lazy pmem backend socket must not be empty"));
        }
        if backend_id.is_empty() {
            return Err(invalid_input("lazy pmem backend_id must not be empty"));
        }
        // SAFETY: sysconf with _SC_PAGESIZE has no pointer arguments.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size <= 0 {
            return Err(io::Error::last_os_error());
        }
        let page_size = page_size as u64;
        if pmem_size == 0 || !pmem_size.is_multiple_of(page_size) {
            return Err(invalid_input(
                "lazy pmem size must be non-zero and page aligned",
            ));
        }
        Ok(Self {
            socket,
            backend_id,
            pmem_size,
            page_size,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    pub(crate) fn fetch(&self, pos: u64, len: u64) -> io::Result<FetchResult> {
        self.validate_requested_range(pos, len)?;
        let request_id = next_request_id();
        let request = FetchRequest {
            protocol_version: PROTOCOL_VERSION,
            request_id: request_id.clone(),
            op: FetchOp::Fetch,
            backend_id: self.backend_id.clone(),
            pos,
            len,
        };
        let payload = serde_json::to_vec(&request).map_err(invalid_data)?;

        let socket = Seqpacket::connect(&self.socket, self.timeout)?;
        let sent = socket
            .send_with_fds(&[payload.as_slice()], &[])
            .map_err(errno_to_io)?;
        if sent != payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short lazy pmem backend request write",
            ));
        }

        let mut response = vec![0u8; MAX_PACKET_SIZE];
        let (received, file) = socket.recv_with_fd(&mut response).map_err(errno_to_io)?;
        if received == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "lazy pmem backend closed the data socket",
            ));
        }
        response.truncate(received);
        let response: FetchResponse = serde_json::from_slice(&response).map_err(invalid_data)?;
        let range = match response {
            FetchResponse::FetchOk {
                protocol_version,
                request_id: response_id,
                ranges,
            } => {
                validate_response_identity(protocol_version, &response_id, &request_id)?;
                if ranges.len() != 1 {
                    return Err(invalid_data(format!(
                        "lazy pmem backend returned {} ranges, expected one",
                        ranges.len()
                    )));
                }
                ranges[0]
            }
            FetchResponse::Error {
                protocol_version,
                request_id: response_id,
                code,
                msg,
            } => {
                validate_response_identity(protocol_version, &response_id, &request_id)?;
                return Err(io::Error::other(format!(
                    "lazy pmem backend error {code}: {msg}"
                )));
            }
        };
        self.validate_returned_range(range, pos, len)?;
        let file =
            file.ok_or_else(|| invalid_data("lazy pmem backend response did not carry an fd"))?;
        set_close_on_exec(&file)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file() {
            return Err(invalid_data("lazy pmem backend fd is not a regular file"));
        }
        if metadata.len() != self.pmem_size {
            return Err(invalid_data(format!(
                "lazy pmem backend cache fd size is {}, expected {}",
                metadata.len(),
                self.pmem_size
            )));
        }
        Ok(FetchResult { file, range })
    }

    pub(crate) fn page_size(&self) -> u64 {
        self.page_size
    }

    fn validate_requested_range(&self, pos: u64, len: u64) -> io::Result<()> {
        if len == 0 || !pos.is_multiple_of(self.page_size) || !len.is_multiple_of(self.page_size) {
            return Err(invalid_input(
                "FETCH pos and len must be non-zero and page aligned",
            ));
        }
        let end = pos
            .checked_add(len)
            .ok_or_else(|| invalid_input("FETCH range overflows u64"))?;
        if end > self.pmem_size {
            return Err(invalid_input("FETCH range exceeds pmem size"));
        }
        Ok(())
    }

    fn validate_returned_range(
        &self,
        range: FetchRange,
        requested_pos: u64,
        requested_len: u64,
    ) -> io::Result<()> {
        if range.len == 0
            || !range.off.is_multiple_of(self.page_size)
            || !range.dev_off.is_multiple_of(self.page_size)
            || !range.len.is_multiple_of(self.page_size)
        {
            return Err(invalid_data(
                "lazy pmem backend returned a zero-length or unaligned range",
            ));
        }
        let range_end = range
            .off
            .checked_add(range.len)
            .ok_or_else(|| invalid_data("lazy pmem backend range overflows u64"))?;
        let dev_end = range
            .dev_off
            .checked_add(range.len)
            .ok_or_else(|| invalid_data("lazy pmem backend device range overflows u64"))?;
        let requested_end = requested_pos + requested_len;
        if range_end > self.pmem_size || dev_end > self.pmem_size {
            return Err(invalid_data("lazy pmem backend range exceeds pmem size"));
        }
        if range.off > requested_pos || range_end < requested_end {
            return Err(invalid_data(
                "lazy pmem backend range does not contain the requested range",
            ));
        }
        Ok(())
    }
}

struct Seqpacket {
    fd: OwnedFd,
}

impl Seqpacket {
    fn connect(path: &Path, timeout: Duration) -> io::Result<Self> {
        // SAFETY: socket is called with a supported domain, type and protocol.
        let raw =
            unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a newly returned descriptor owned by this object.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let (address, address_len) = sockaddr_un(path)?;
        // SAFETY: address points to a fully initialized sockaddr_un.
        if unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                address_len,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        set_socket_timeout(fd.as_raw_fd(), timeout)?;
        Ok(Self { fd })
    }

    #[cfg(test)]
    fn from_owned_fd(fd: OwnedFd) -> Self {
        Self { fd }
    }
}

impl ScmSocket for Seqpacket {
    fn socket_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsRawFd for Seqpacket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

fn sockaddr_un(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    let bytes = path.as_os_str().as_encoded_bytes();
    // SAFETY: zero is a valid initial representation for sockaddr_un.
    let mut address = unsafe { MaybeUninit::<libc::sockaddr_un>::zeroed().assume_init() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    if bytes.len() >= address.sun_path.len() {
        return Err(invalid_input("Unix socket path is too long"));
    }
    for (target, source) in address.sun_path.iter_mut().zip(bytes) {
        *target = *source as libc::c_char;
    }
    let len = size_of::<libc::sa_family_t>() + bytes.len() + 1;
    Ok((address, len as libc::socklen_t))
}

fn set_socket_timeout(fd: RawFd, timeout: Duration) -> io::Result<()> {
    let timeout = libc::timeval {
        tv_sec: timeout
            .as_secs()
            .try_into()
            .map_err(|_| invalid_input("backend timeout does not fit in libc::time_t"))?,
        tv_usec: timeout.subsec_micros().into(),
    };
    for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        // SAFETY: timeout is readable for the supplied size.
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&timeout as *const libc::timeval).cast(),
                size_of::<libc::timeval>() as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn set_close_on_exec(file: &File) -> io::Result<()> {
    // SAFETY: fcntl operates on a live descriptor without pointer arguments.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: flags only adds FD_CLOEXEC to the current descriptor flags.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn validate_response_identity(version: u32, response_id: &str, request_id: &str) -> io::Result<()> {
    if version != PROTOCOL_VERSION {
        return Err(invalid_data(format!(
            "lazy pmem backend returned protocol_version {version}"
        )));
    }
    if response_id != request_id {
        return Err(invalid_data(format!(
            "lazy pmem backend returned request_id {response_id}, expected {request_id}"
        )));
    }
    Ok(())
}

fn next_request_id() -> String {
    let sequence = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    format!("cloud-hypervisor-{}-{sequence}", std::process::id())
}

fn errno_to_io(error: vmm_sys_util::errno::Error) -> io::Error {
    io::Error::from_raw_os_error(error.errno())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[allow(clippy::needless_pass_by_value)]
fn invalid_data(error: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};

    use super::*;
    use crate::lazy_pmem::LazyPmemRegion;

    #[test]
    fn fetch_request_schema_matches_lazyd_v1() {
        let request = FetchRequest {
            protocol_version: PROTOCOL_VERSION,
            request_id: "req-1".to_string(),
            op: FetchOp::Fetch,
            backend_id: "erofs-sha256-content".to_string(),
            pos: 4096,
            len: 8192,
        };
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            serde_json::json!({
                "protocol_version": 1,
                "request_id": "req-1",
                "op": "fetch",
                "instance_id": "erofs-sha256-content",
                "pos": 4096,
                "len": 8192
            })
        );
    }

    #[test]
    fn fetch_receives_and_validates_cache_fd() {
        let page_size = page_size();
        let pmem_size = page_size * 2;
        let (socket_path, listener) = test_listener();
        let cache_path = socket_path.with_extension("cache");
        let mut cache = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&cache_path)
            .unwrap();
        cache.set_len(pmem_size).unwrap();
        cache.write_all(b"cache-data").unwrap();
        cache.seek(SeekFrom::Start(0)).unwrap();

        let server = thread::spawn(move || {
            let stream = listener.accept().unwrap();
            let mut request = [0u8; MAX_PACKET_SIZE];
            // SAFETY: request is writable for its complete length.
            let count = unsafe {
                libc::recv(
                    stream.as_raw_fd(),
                    request.as_mut_ptr().cast(),
                    request.len(),
                    0,
                )
            };
            assert!(count > 0);
            let request: FetchRequest = serde_json::from_slice(&request[..count as usize]).unwrap();
            let response = serde_json::to_vec(&serde_json::json!({
                "protocol_version": 1,
                "request_id": request.request_id,
                "op": "fetch_ok",
                "ranges": [{"off": 0, "len": page_size, "dev_off": 0}]
            }))
            .unwrap();
            stream
                .send_with_fd(response.as_slice(), cache.as_raw_fd())
                .unwrap();
        });

        let client =
            LazyPmemBackendClient::new(socket_path.clone(), "instance".to_string(), pmem_size)
                .unwrap();
        let mut fetched = client.fetch(0, page_size).unwrap();
        let mut data = [0u8; 10];
        fetched.file.read_exact(&mut data).unwrap();

        assert_eq!(&data, b"cache-data");
        assert_eq!(fetched.range.off, 0);
        // SAFETY: F_GETFD does not dereference a pointer and the fd is live.
        let fd_flags = unsafe { libc::fcntl(fetched.file.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(fd_flags & libc::FD_CLOEXEC, 0);
        server.join().unwrap();
        let _ = std::fs::remove_file(socket_path);
        let _ = std::fs::remove_file(cache_path);
    }

    #[test]
    fn lazy_region_fetches_data_and_zeroes_padding() {
        let page_size = page_size();
        let pmem_size = page_size * 2;
        let (socket_path, listener) = test_listener();
        let cache_path = socket_path.with_extension("cache");
        let mut cache = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&cache_path)
            .unwrap();
        cache.set_len(pmem_size).unwrap();
        cache.write_all(&vec![0x5a; page_size as usize]).unwrap();
        cache.seek(SeekFrom::Start(0)).unwrap();

        let server = thread::spawn(move || {
            let stream = listener.accept().unwrap();
            let request = receive_fetch(&stream);
            assert_eq!((request.pos, request.len), (0, page_size));
            let response = serde_json::to_vec(&serde_json::json!({
                "protocol_version": 1,
                "request_id": request.request_id,
                "op": "fetch_ok",
                "ranges": [{"off": 0, "len": page_size, "dev_off": 0}]
            }))
            .unwrap();
            stream
                .send_with_fd(response.as_slice(), cache.as_raw_fd())
                .unwrap();
        });

        let mapping = anonymous_mapping(pmem_size);
        let exit_evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let region = LazyPmemRegion::register(
            mapping as u64,
            pmem_size,
            page_size,
            "instance".to_string(),
            socket_path.clone(),
            exit_evt,
        )
        .unwrap();

        assert_eq!(read_mapping(mapping as usize), 0x5a);
        assert_eq!(read_mapping(mapping as usize + page_size as usize), 0);

        drop(region);
        server.join().unwrap();
        unmap(mapping, pmem_size);
        let _ = std::fs::remove_file(socket_path);
        let _ = std::fs::remove_file(cache_path);
    }

    #[test]
    fn lazy_region_signals_fatal_error_without_resolving_fault() {
        let page_size = page_size();
        let (socket_path, listener) = test_listener();
        let server = thread::spawn(move || {
            let stream = listener.accept().unwrap();
            let request = receive_fetch(&stream);
            let response = serde_json::to_vec(&serde_json::json!({
                "protocol_version": 1,
                "request_id": request.request_id,
                "op": "error",
                "code": 503,
                "msg": "range unavailable"
            }))
            .unwrap();
            stream.send_with_fds(&[response.as_slice()], &[]).unwrap();
        });

        let mapping = anonymous_mapping(page_size);
        let exit_evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let handler_exit_evt = exit_evt.try_clone().unwrap();
        let region = LazyPmemRegion::register(
            mapping as u64,
            page_size,
            page_size,
            "instance".to_string(),
            socket_path.clone(),
            handler_exit_evt,
        )
        .unwrap();

        let (sender, receiver) = mpsc::channel();
        let address = mapping as usize;
        let reader = thread::spawn(move || {
            // SAFETY: the mapping remains live until after the reader joins.
            let value = unsafe { std::ptr::read_volatile(address as *const u8) };
            sender.send(value).unwrap();
        });
        wait_for_fatal_event(&exit_evt);
        receiver
            .recv_timeout(Duration::from_millis(100))
            .unwrap_err();

        drop(region);
        assert_eq!(receiver.recv_timeout(Duration::from_secs(5)).unwrap(), 0);
        reader.join().unwrap();
        server.join().unwrap();
        unmap(mapping, page_size);
        let _ = std::fs::remove_file(socket_path);
    }

    fn receive_fetch(stream: &Seqpacket) -> FetchRequest {
        let mut request = [0u8; MAX_PACKET_SIZE];
        // SAFETY: request is writable for its complete length.
        let count = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                request.as_mut_ptr().cast(),
                request.len(),
                0,
            )
        };
        assert!(count > 0);
        serde_json::from_slice(&request[..count as usize]).unwrap()
    }

    fn anonymous_mapping(size: u64) -> *mut libc::c_void {
        // SAFETY: the kernel selects a page-aligned address and each caller
        // retains the mapping until its lazy handler is stopped.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        mapping
    }

    fn read_mapping(address: usize) -> u8 {
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            // SAFETY: callers retain the mapping until this read completes.
            let value = unsafe { std::ptr::read_volatile(address as *const u8) };
            sender.send(value).unwrap();
        });
        receiver.recv_timeout(Duration::from_secs(5)).unwrap()
    }

    fn wait_for_fatal_event(event: &EventFd) {
        let mut pollfd = libc::pollfd {
            fd: event.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pollfd points to one initialized pollfd entry.
        assert_eq!(unsafe { libc::poll(&mut pollfd, 1, 5_000) }, 1);
        assert!(crate::is_fatal_exit_event(event.read().unwrap()));
    }

    fn unmap(mapping: *mut libc::c_void, size: u64) {
        // SAFETY: mapping and size identify the live test-owned mapping.
        assert_eq!(unsafe { libc::munmap(mapping, size as usize) }, 0);
    }

    struct TestListener {
        fd: OwnedFd,
    }

    impl TestListener {
        fn accept(&self) -> io::Result<Seqpacket> {
            // SAFETY: accept4 receives no address and returns a new descriptor.
            let raw = unsafe {
                libc::accept4(
                    self.fd.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC,
                )
            };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: raw is a newly returned descriptor.
            Ok(Seqpacket::from_owned_fd(unsafe {
                OwnedFd::from_raw_fd(raw)
            }))
        }
    }

    fn test_listener() -> (PathBuf, TestListener) {
        let path = std::env::temp_dir().join(format!("ch-lazy-pmem-{}.sock", uuid::Uuid::new_v4()));
        let (address, address_len) = sockaddr_un(&path).unwrap();
        let socket_type = libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC;
        // SAFETY: socket is called with a supported domain, type and protocol.
        let raw = unsafe { libc::socket(libc::AF_UNIX, socket_type, 0) };
        assert!(raw >= 0);
        // SAFETY: raw is a newly returned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        assert_eq!(
            // SAFETY: address points to a fully initialized sockaddr_un.
            unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&address as *const libc::sockaddr_un).cast(),
                    address_len,
                )
            },
            0
        );
        // SAFETY: fd is a bound SOCK_SEQPACKET socket.
        assert_eq!(unsafe { libc::listen(fd.as_raw_fd(), 1) }, 0);
        (path, TestListener { fd })
    }

    fn page_size() -> u64 {
        // SAFETY: sysconf with _SC_PAGESIZE has no pointer arguments.
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 }
    }
}
