use aya::{programs::Syscall, util::KernelVersion, Ebpf};
use test_log::test;

#[repr(C)]
#[derive(Clone, Copy)]
struct MyData {
    value: i32,
}

#[test]
fn syscall_c() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 14, 0) {
        eprintln!("skipping test on kernel {kernel_version:?}, syscall not supported yet");
        return;
    }
    let mut bpf = Ebpf::load(crate::SYSCALL_C).unwrap();
    let my_syscall: &mut Syscall = bpf.program_mut("my_syscall").unwrap().try_into().unwrap();
    my_syscall.load().unwrap();

    let mut my_data = MyData { value: 21 };
    unsafe { my_syscall.invoke_unchecked(&mut my_data) }.unwrap();

    assert_eq!(my_data.value, 42);
}

#[test]
fn syscall_rs() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 14, 0) {
        eprintln!("skipping test on kernel {kernel_version:?}, syscall not supported yet");
        return;
    }
    let mut bpf = Ebpf::load(crate::SYSCALL_RS).unwrap();
    let my_syscall: &mut Syscall = bpf.program_mut("my_syscall").unwrap().try_into().unwrap();
    my_syscall.load().unwrap();

    let mut my_data = MyData { value: 21 };
    unsafe { my_syscall.invoke_unchecked(&mut my_data) }.unwrap();

    assert_eq!(my_data.value, 42);
}
