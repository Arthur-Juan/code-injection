pub mod resolver;
pub mod stubs;
pub mod globals;

pub use resolver::{IndirectSyscall, resolve_indirect_syscalls};
pub use stubs::*;
