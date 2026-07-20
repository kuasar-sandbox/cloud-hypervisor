// Copyright 2026 The Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const UFFD_API: u64 = 0xaa;
const UFFDIO_API: libc::c_ulong = 0xc018_aa3f;
const UFFDIO_REGISTER: libc::c_ulong = 0xc020_aa00;
pub(crate) const UFFDIO_WAKE: libc::c_ulong = 0x8010_aa02;
pub(crate) const UFFDIO_ZEROPAGE: libc::c_ulong = 0xc020_aa04;
const UFFDIO_REGISTER_MODE_MISSING: u64 = 1;
const UFFD_EVENT_PAGEFAULT: u8 = 0x12;
const UFFD_MSG_SIZE: usize = 32;

#[repr(C)]
struct UffdioApi {
    api: u64,
    features: u64,
    ioctls: u64,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct UffdioRange {
    start: u64,
    len: u64,
}

#[repr(C)]
struct UffdioRegister {
    range: UffdioRange,
    mode: u64,
    ioctls: u64,
}

#[repr(C)]
struct UffdioZeropage {
    range: UffdioRange,
    mode: u64,
    zeropage: i64,
}

fn parse_pagefault_event(message: &[u8; UFFD_MSG_SIZE]) -> io::Result<u64> {
    if message[0] != UFFD_EVENT_PAGEFAULT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected userfaultfd event {:#x}", message[0]),
        ));
    }
    Ok(u64::from_ne_bytes(message[16..24].try_into().unwrap()))
}

pub(crate) struct Userfaultfd {
    fd: OwnedFd,
}

impl Userfaultfd {
    pub(crate) fn new(features: u64) -> io::Result<Self> {
        // SAFETY: userfaultfd is called with valid integer flags and returns a
        // new descriptor on success.
        let raw =
            unsafe { libc::syscall(libc::SYS_userfaultfd, libc::O_CLOEXEC | libc::O_NONBLOCK) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a newly returned descriptor owned by this object.
        let fd = unsafe { OwnedFd::from_raw_fd(raw as RawFd) };

        let mut request = UffdioApi {
            api: UFFD_API,
            features,
            ioctls: 0,
        };
        // SAFETY: request is writable and valid for the ioctl duration.
        if unsafe { libc::ioctl(fd.as_raw_fd(), UFFDIO_API, &mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    pub(crate) fn register_missing(&self, start: u64, len: u64) -> io::Result<()> {
        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "userfaultfd range must not be empty",
            ));
        }
        let mut request = UffdioRegister {
            range: UffdioRange { start, len },
            mode: UFFDIO_REGISTER_MODE_MISSING,
            ioctls: 0,
        };
        // SAFETY: request describes a live caller-owned mapping and remains
        // valid for the ioctl duration.
        if unsafe { libc::ioctl(self.fd.as_raw_fd(), UFFDIO_REGISTER, &mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(crate) fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub(crate) fn read_pagefault(&self) -> io::Result<u64> {
        let mut message = [0_u8; UFFD_MSG_SIZE];
        // SAFETY: message is writable for its complete length and fd is a
        // live userfaultfd descriptor.
        let count = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                message.as_mut_ptr().cast(),
                message.len(),
            )
        };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        if count != UFFD_MSG_SIZE as isize {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("short userfaultfd message: {count} bytes"),
            ));
        }
        parse_pagefault_event(&message)
    }

    pub(crate) fn wake(&self, start: u64, len: u64) -> io::Result<()> {
        let mut range = UffdioRange { start, len };
        // SAFETY: range describes a subrange of the live UFFD registration
        // and remains valid for the ioctl duration.
        if unsafe { libc::ioctl(self.fd.as_raw_fd(), UFFDIO_WAKE, &mut range) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(crate) fn zero(&self, start: u64, len: u64) -> io::Result<()> {
        let mut request = UffdioZeropage {
            range: UffdioRange { start, len },
            mode: 0,
            zeropage: 0,
        };
        // SAFETY: request describes a missing subrange of the live UFFD
        // registration and remains valid for the ioctl duration.
        if unsafe { libc::ioctl(self.fd.as_raw_fd(), UFFDIO_ZEROPAGE, &mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if request.zeropage != len as i64 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!(
                    "userfaultfd zeroed {} bytes, expected {len}",
                    request.zeropage
                ),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pagefault_event_reports_fault_address() {
        let address = 0x1234_5678_u64;
        let mut message = [0_u8; UFFD_MSG_SIZE];
        message[0] = UFFD_EVENT_PAGEFAULT;
        message[16..24].copy_from_slice(&address.to_ne_bytes());

        assert_eq!(parse_pagefault_event(&message).unwrap(), address);
    }

    #[test]
    fn non_pagefault_event_is_rejected() {
        let message = [0_u8; UFFD_MSG_SIZE];

        assert_eq!(
            parse_pagefault_event(&message).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
