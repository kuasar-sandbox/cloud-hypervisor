// Copyright 2026 The Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::path::PathBuf;

use log::info;

use crate::userfaultfd::Userfaultfd;

pub(crate) struct LazyPmemRegion {
    pub(crate) base_hva: u64,
    pub(crate) size: u64,
    pub(crate) data_size: u64,
    pub(crate) backend_id: String,
    pub(crate) socket: PathBuf,
    pub(crate) uffd: Userfaultfd,
}

impl LazyPmemRegion {
    pub(crate) fn register(
        base_hva: u64,
        size: u64,
        data_size: u64,
        backend_id: String,
        socket: PathBuf,
    ) -> io::Result<Self> {
        let uffd = Userfaultfd::new(0)?;
        uffd.register_missing(base_hva, size)?;
        let region = Self {
            base_hva,
            size,
            data_size,
            backend_id,
            socket,
            uffd,
        };
        info!(
            "Registered lazy pmem UFFD: hva={:#x}, size={}, data_size={}, backend_id={}, socket={}, uffd={}",
            region.base_hva,
            region.size,
            region.data_size,
            region.backend_id,
            region.socket.display(),
            region.uffd.as_raw_fd()
        );
        Ok(region)
    }
}
