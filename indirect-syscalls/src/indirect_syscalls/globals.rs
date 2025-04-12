//#[no_mangle]
//pub static mut g_NtCreateSectionSSN: u32 = 0;
#[no_mangle]
pub static mut g_NtCreateSectionSyscall: *const u8 = core::ptr::null();

//#[no_mangle]
//pub static mut g_NtMapViewOfSectionSSN: u32 = 0;
#[no_mangle]
pub static mut g_NtMapViewOfSectionSyscall: *const u8 = core::ptr::null();

//#[no_mangle]
//pub static mut g_NtCreateThreadExSSN: u32 = 0;
#[no_mangle]
pub static mut g_NtCreateThreadExSyscall: *const u8 = core::ptr::null();

//#[no_mangle]
//pub static mut g_NtDelayExecutionSSN: u32 = 0;
#[no_mangle]
pub static mut g_NtDelayExecutionSyscall: *const u8 = core::ptr::null();


#[no_mangle]
pub static mut g_NtCreateSectionSSN: u32 = 0;

#[no_mangle]
pub static mut g_NtMapViewOfSectionSSN: u32 = 0;

#[no_mangle]
pub static mut g_NtCreateThreadExSSN: u32 = 0;

#[no_mangle]
pub static mut g_NtDelayExecutionSSN: u32 = 0;
