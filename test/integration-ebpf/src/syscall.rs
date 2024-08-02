#![no_std]
#![no_main]

use aya_ebpf::{macros::syscall, programs::SyscallContext, EbpfContext as _};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MyData {
    value: i32,
}

#[syscall]
fn my_syscall(ctx: SyscallContext) -> i64 {
    let my_data: &mut MyData = unsafe { &mut *(ctx.as_ptr() as *mut MyData) };

    my_data.value += my_data.value;

    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
