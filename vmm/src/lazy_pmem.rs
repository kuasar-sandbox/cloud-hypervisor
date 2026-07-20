// Copyright 2026 The Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::thread::{self, JoinHandle};

use log::{error, info};
use vmm_sys_util::eventfd::{EFD_CLOEXEC, EFD_NONBLOCK, EventFd};

use crate::lazy_pmem_backend::LazyPmemBackendClient;
use crate::userfaultfd::Userfaultfd;

#[derive(Debug, PartialEq, Eq)]
enum FaultKind {
    Data { offset: u64 },
    Padding { offset: u64 },
}

fn classify_fault(
    base_hva: u64,
    pmem_size: u64,
    data_size: u64,
    page_size: u64,
    fault_hva: u64,
) -> io::Result<FaultKind> {
    let region_end = base_hva
        .checked_add(pmem_size)
        .ok_or_else(|| invalid_data("lazy pmem HVA range overflows u64"))?;
    if fault_hva < base_hva || fault_hva >= region_end {
        return Err(invalid_data("fault address is outside lazy pmem region"));
    }
    let offset = fault_hva - base_hva;
    let data_end = data_size
        .checked_add(page_size - 1)
        .ok_or_else(|| invalid_data("lazy pmem data size overflows u64"))?
        / page_size
        * page_size;
    if offset < data_end {
        Ok(FaultKind::Data { offset })
    } else {
        Ok(FaultKind::Padding { offset })
    }
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

pub(crate) struct LazyPmemRegion {
    pub(crate) base_hva: u64,
    pub(crate) size: u64,
    pub(crate) data_size: u64,
    pub(crate) backend_id: String,
    kill_evt: EventFd,
    handler: Option<JoinHandle<()>>,
}

impl LazyPmemRegion {
    pub(crate) fn register(
        base_hva: u64,
        size: u64,
        data_size: u64,
        backend_id: String,
        socket: PathBuf,
        exit_evt: EventFd,
    ) -> io::Result<Self> {
        let socket_display = socket.display().to_string();
        let backend = LazyPmemBackendClient::new(socket, backend_id.clone(), size)?;
        let uffd = Userfaultfd::new(0)?;
        uffd.register_missing(base_hva, size)?;
        let uffd_fd = uffd.as_raw_fd();
        let kill_evt = EventFd::new(EFD_CLOEXEC | EFD_NONBLOCK)?;
        let thread_kill_evt = kill_evt.try_clone()?;
        let thread_backend_id = backend_id.clone();
        let handler = thread::Builder::new()
            .name("lazy-pmem".to_string())
            .spawn(move || {
                if let Err(error) =
                    run_fault_loop(&uffd, &backend, base_hva, size, data_size, &thread_kill_evt)
                {
                    error!(
                        "Lazy pmem fault handler failed for backend {thread_backend_id}: {error}"
                    );
                    if let Err(signal_error) = exit_evt.write(crate::FATAL_EXIT_EVENT) {
                        error!(
                            "Failed to signal VM exit after lazy pmem fault handler error: {signal_error}"
                        );
                    }
                    // Keep the UFFD open until DeviceManager teardown. Closing
                    // it here would let the kernel resolve the anonymous fault
                    // with zeroes before the fatal VM exit is processed.
                    if let Err(shutdown_error) = wait_for_shutdown(&thread_kill_evt) {
                        error!(
                            "Failed while waiting to stop lazy pmem handler: {shutdown_error}"
                        );
                    }
                }
            })?;
        let region = Self {
            base_hva,
            size,
            data_size,
            backend_id,
            kill_evt,
            handler: Some(handler),
        };
        info!(
            "Registered lazy pmem UFFD: hva={:#x}, size={}, data_size={}, backend_id={}, socket={}, uffd={}",
            region.base_hva,
            region.size,
            region.data_size,
            region.backend_id,
            socket_display,
            uffd_fd
        );
        Ok(region)
    }
}

impl Drop for LazyPmemRegion {
    fn drop(&mut self) {
        if let Err(error) = self.kill_evt.write(1) {
            error!(
                "Failed to stop lazy pmem handler for backend {}: {}",
                self.backend_id, error
            );
        }
        if self
            .handler
            .take()
            .is_some_and(|handler| handler.join().is_err())
        {
            error!("Lazy pmem handler panicked for backend {}", self.backend_id);
        }
    }
}

fn run_fault_loop(
    uffd: &Userfaultfd,
    backend: &LazyPmemBackendClient,
    base_hva: u64,
    pmem_size: u64,
    data_size: u64,
    kill_evt: &EventFd,
) -> io::Result<()> {
    let mut pollfds = [
        libc::pollfd {
            fd: kill_evt.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: uffd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: pollfds points to two initialized pollfd entries.
        let ready = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as _, -1) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if pollfds[0].revents & libc::POLLIN != 0 {
            kill_evt.read()?;
            return Ok(());
        }
        check_poll_errors(pollfds[0].revents, "lazy pmem kill event")?;
        check_poll_errors(pollfds[1].revents, "lazy pmem userfaultfd")?;
        if pollfds[1].revents & libc::POLLIN != 0 {
            let fault_hva = uffd.read_pagefault()?;
            resolve_fault(uffd, backend, base_hva, pmem_size, data_size, fault_hva)?;
        }
    }
}

fn wait_for_shutdown(kill_evt: &EventFd) -> io::Result<()> {
    let mut pollfd = libc::pollfd {
        fd: kill_evt.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: pollfd points to one initialized pollfd entry.
        let ready = unsafe { libc::poll(&mut pollfd, 1, -1) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        check_poll_errors(pollfd.revents, "lazy pmem kill event")?;
        if pollfd.revents & libc::POLLIN != 0 {
            kill_evt.read()?;
            return Ok(());
        }
    }
}

fn check_poll_errors(events: libc::c_short, source: &str) -> io::Result<()> {
    if events & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
        return Err(io::Error::other(format!(
            "{source} reported poll events {events:#x}"
        )));
    }
    Ok(())
}

fn resolve_fault(
    uffd: &Userfaultfd,
    backend: &LazyPmemBackendClient,
    base_hva: u64,
    pmem_size: u64,
    data_size: u64,
    fault_hva: u64,
) -> io::Result<()> {
    let page_size = backend.page_size();
    let fault_page = fault_hva / page_size * page_size;
    match classify_fault(base_hva, pmem_size, data_size, page_size, fault_page)? {
        FaultKind::Data { offset } => {
            let fetched = backend.fetch(offset, page_size)?;
            let mapped_hva = base_hva
                .checked_add(fetched.range.off)
                .ok_or_else(|| invalid_data("lazy pmem mmap address overflows u64"))?;
            map_file_range(
                &fetched.file,
                mapped_hva,
                fetched.range.len,
                fetched.range.dev_off,
            )?;
            uffd.wake(mapped_hva, fetched.range.len)
        }
        FaultKind::Padding { offset } => uffd.zero(base_hva + offset, page_size),
    }
}

fn map_file_range(file: &File, hva: u64, len: u64, file_offset: u64) -> io::Result<()> {
    let address = usize::try_from(hva)
        .map_err(|_| invalid_data("lazy pmem mmap address does not fit usize"))?;
    let length = usize::try_from(len)
        .map_err(|_| invalid_data("lazy pmem mmap length does not fit usize"))?;
    let offset = libc::off_t::try_from(file_offset)
        .map_err(|_| invalid_data("lazy pmem mmap offset does not fit off_t"))?;
    // SAFETY: address and length identify a page-aligned subrange of the lazy
    // pmem reservation. MAP_FIXED intentionally replaces exactly that range
    // with the validated backend cache file range.
    let mapped = unsafe {
        libc::mmap(
            address as *mut libc::c_void,
            length,
            libc::PROT_READ,
            libc::MAP_SHARED | libc::MAP_FIXED,
            file.as_raw_fd(),
            offset,
        )
    };
    if mapped == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    if mapped as usize != address {
        return Err(io::Error::other(
            "MAP_FIXED returned a different lazy pmem address",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_data_tail_and_padding_faults() {
        let page_size = 4096;
        let base_hva = 0x10_0000;
        let data_size = page_size + 17;
        let pmem_size = page_size * 4;

        assert_eq!(
            classify_fault(base_hva, pmem_size, data_size, page_size, base_hva).unwrap(),
            FaultKind::Data { offset: 0 }
        );
        assert_eq!(
            classify_fault(
                base_hva,
                pmem_size,
                data_size,
                page_size,
                base_hva + page_size,
            )
            .unwrap(),
            FaultKind::Data { offset: page_size }
        );
        assert_eq!(
            classify_fault(
                base_hva,
                pmem_size,
                data_size,
                page_size,
                base_hva + page_size * 2,
            )
            .unwrap(),
            FaultKind::Padding {
                offset: page_size * 2
            }
        );
    }

    #[test]
    fn rejects_fault_outside_lazy_region() {
        assert_eq!(
            classify_fault(0x10_0000, 0x4000, 0x1000, 0x1000, 0x0f_f000)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
}
