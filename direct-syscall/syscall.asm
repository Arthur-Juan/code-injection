; syscall.asm - Stubs for direct syscall with MASM
EXTERN g_NtCreateSectionSSN:DWORD
EXTERN g_NtMapViewOfSectionSSN:DWORD
EXTERN g_NtCreateThreadExSSN:DWORD
EXTERN g_NtDelayExecutionSSN:DWORD    ; Changed from g_NtDelayExecutionSyscall
.CODE
NtCreateSection PROC
    mov     r10, rcx
    mov     eax, DWORD PTR [g_NtCreateSectionSSN]
    syscall
    ret
NtCreateSection ENDP
NtMapViewOfSection PROC
    mov     r10, rcx
    mov     eax, DWORD PTR [g_NtMapViewOfSectionSSN]
    syscall
    ret
NtMapViewOfSection ENDP
NtCreateThreadEx PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_NtCreateThreadExSSN]
    syscall
    ret
NtCreateThreadEx ENDP
NtDelayExecutionSyscall PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_NtDelayExecutionSSN]
    syscall
    ret
NtDelayExecutionSyscall ENDP
END