//! syscall programs.

use std::os::fd::AsFd as _;

use crate::{
    generated::bpf_prog_type::BPF_PROG_TYPE_SYSCALL,
    programs::{load_program, Link, ProgramData, ProgramError},
    sys::bpf_prog_test_run,
};

/// A program used to invoking custom programs inside kernel space
///
/// [`Syscall`] programs can be invoked at any time, accepts data from user space program and return back result data
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is [5.14](https://github.com/torvalds/linux/commit/79a7f8bdb159d9914b58740f3d31d602a6e4aca8).
///
/// # Examples
///
/// ```no_run
/// # #[derive(Debug, thiserror::Error)]
/// # enum Error {
/// #     #[error(transparent)]
/// #     IO(#[from] std::io::Error),
/// #     #[error(transparent)]
/// #     Map(#[from] aya::maps::MapError),
/// #     #[error(transparent)]
/// #     Program(#[from] aya::programs::ProgramError),
/// #     #[error(transparent)]
/// #     Bpf(#[from] aya::BpfError)
/// # }
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use aya::programs::Syscall;
///
/// #[repr(C)]
/// #[derive(Clone, Copy)]
/// struct MyData {
///     value: i32,
/// }
///
/// let program: &mut Syscall = bpf.program_mut("my_syscall").unwrap().try_into()?;
/// program.load()?;
/// let mut my_value = MyData { value: 42 };
/// unsafe { program.invoke_unchecked(&mut my_value)? };
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_SYSCALL")]
pub struct Syscall {
    pub(crate) data: ProgramData<SyscallLinkInner>,
}

impl Syscall {
    /// Loads the program inside the kernel
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_SYSCALL, &mut self.data)
    }

    /// Invoking syscall with parameter
    ///
    /// # Safety
    ///
    /// - `Context` must be simple type without references or dynamic storages like `Box`, `String`, etc.
    ///   Kernel will simply copy data from user space to kernel space, so any references and pointers will be invalid inside kernel space.
    pub unsafe fn invoke_unchecked<Context>(
        &mut self,
        context: &mut Context,
    ) -> Result<i64, ProgramError> {
        let payload = std::slice::from_raw_parts_mut(
            context as *mut Context as *mut u8,
            std::mem::size_of_val(context),
        );
        Ok(bpf_prog_test_run(self.data.fd()?.as_fd(), payload)?)
    }

    // TODO: add trait `SafeSyscallContext` for validating passed types at compiling
    // pub fn invoke<Context: SafeSyscallContext>(
    //     &mut self,
    //     context: &mut Context,
    // ) -> Result<i64, ProgramError>;
}

/// The type never returned or used
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct SyscallLinkIdInner {}

/// The link used by [Syscall] programs.
#[derive(Debug)]
pub struct SyscallLinkInner {}

impl Link for SyscallLinkInner {
    type Id = SyscallLinkIdInner;

    fn id(&self) -> Self::Id {
        SyscallLinkIdInner {}
    }

    fn detach(self) -> Result<(), ProgramError> {
        Ok(())
    }
}
