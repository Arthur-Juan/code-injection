use std::ffi::c_void;
use std::ptr::null_mut;
use winapi::shared::ntdef::{LARGE_INTEGER, NTSTATUS};
// Supondo que nt_delay_execution_syscall esteja definido em utils
use crate::utils::nt_delay_execution_syscall;

// Delay em segundos
pub fn fake_sleep(seconds: i64) {
    unsafe {
        // Inicializa LARGE_INTEGER com zero
        let mut interval: LARGE_INTEGER = std::mem::zeroed();

        *interval.QuadPart_mut() = -(seconds * 10_000_000);

        let status: NTSTATUS = nt_delay_execution_syscall(0, &mut interval as *mut _ as *mut c_void);

        if status < 0 {
            println!("[-] NtDelayExecution falhou com status: 0x{:X}", status);
        } else {
            println!("[+] Fake sleep de {} segundos concluído", seconds);
        }
    }
}