use std::ptr::null_mut;
use winapi::shared::minwindef::{BOOL, DWORD, LPVOID, TRUE};
use winapi::shared::ntdef::HANDLE;
use winapi::um::winuser::{MessageBoxA, MB_ICONEXCLAMATION, MB_OK};

// Reasons for DLL entry
const DLL_PROCESS_ATTACH: DWORD = 1;

#[no_mangle]
pub extern "system" fn DllMain(h_dll: HANDLE, dw_reason: DWORD, lp_reserved: LPVOID) -> BOOL {
    match dw_reason {
        DLL_PROCESS_ATTACH => attach(),
        _ => TRUE,
    }
}

fn attach() -> BOOL {
    unsafe {
        MessageBoxA(
            null_mut(),
            b"DLL in Rust\0".as_ptr().cast(),
            b"Hello from RUST\0".as_ptr().cast(),
            MB_ICONEXCLAMATION | MB_OK,
        );
    }
    TRUE
}
