// Copyright 2026 The Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::path::PathBuf;

use log::info;

use crate::lazy_pmem_backend::LazyPmemBackendClient;
use crate::userfaultfd::Userfaultfd;

pub(crate) struct LazyPmemRegion {
    pub(crate) base_hva: u64,
    pub(crate) size: u64,
    pub(crate) data_size: u64,
    pub(crate) backend_id: String,
    pub(crate) uffd: Userfaultfd,
    pub(crate) backend: LazyPmemBackendClient,
}

impl LazyPmemRegion {
    pub(crate) fn register(
        base_hva: u64,
        size: u64,
        data_size: u64,
        backend_id: String,
        socket: PathBuf,
    ) -> io::Result<Self> {
        let socket_display = socket.display().to_string();
        let backend = LazyPmemBackendClient::new(socket, backend_id.clone(), size)?;
        let uffd = Userfaultfd::new(0)?;
        uffd.register_missing(base_hva, size)?;
        let region = Self {
            base_hva,
            size,
            data_size,
            backend_id,
            uffd,
            backend,
        };
        info!(
            "Registered lazy pmem UFFD: hva={:#x}, size={}, data_size={}, backend_id={}, socket={}, uffd={}",
            region.base_hva,
            region.size,
            region.data_size,
            region.backend_id,
            socket_display,
            region.uffd.as_raw_fd()
        );
        Ok(region)
    }
}
