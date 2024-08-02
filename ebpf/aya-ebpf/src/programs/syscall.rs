use core::ffi::c_void;

use crate::EbpfContext;

pub struct SyscallContext {
    ctx: *mut c_void,
}

impl SyscallContext {
    pub fn new(ctx: *mut c_void) -> Self {
        Self { ctx }
    }
}

impl EbpfContext for SyscallContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx
    }
}
