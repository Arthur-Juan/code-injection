fn main(){
    let target = std::env::var("TARGET").unwrap();
    if target.contains("windows") {
        let mut build = cc::Build::new();
        build
            .file("syscall.asm")
            .flag("/nologo")
            .flag("/c")
            .flag("/Fo:syscall.obj")
            //.assembler("nasm")
            .compile("syscall");

        println!("cargo:rerun-if-changed=syscall.asm");
    }
}