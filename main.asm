; Declare the 'main' procedure as public, making it the entry point for the linker.
public main

option casemap:none
include \masm64\include64\win64.inc
include \masm64\include64\advapi32.inc
;include \masm64\include64\winmm.inc

includelib \masm64\lib64\advapi32.lib
;includelib \masm64\lib64\winmm.lib

; Declare external procedures that reside in Windows DLLs (like kernel32.dll, user32.dll)
; or the C runtime library (for strcmp). The linker will resolve these addresses.
; ': proc' specifies that these are procedure labels.
extern MessageBoxA			: proc ; USER32.DLL: Displays a message box.
extern OpenProcess			: proc ; KERNEL32.DLL: Opens an existing process object.
extern VirtualAllocEx			: proc ; KERNEL32.DLL: Reserves or commits memory in another process.
extern VirtualProtect               : proc ; KERNEL32.DLL: Changes the protection on a region of committed pages in the virtual address space of the calling process.
extern CreateRemoteThread		: proc ; KERNEL32.DLL: Creates a thread that runs in another process.
extern CloseHandle			: proc ; KERNEL32.DLL: Closes an open object handle.
extern WriteProcessMemory		: proc ; KERNEL32.DLL: Writes data to memory in another process.
extern GetModuleHandleA			: proc ; KERNEL32.DLL: Retrieves a module handle for a specified module (if loaded).
extern GetProcAddress			: proc ; KERNEL32.DLL: Retrieves the address of an exported function in a DLL.
extern CreateToolhelp32Snapshot	: proc ; KERNEL32.DLL: Takes a snapshot of specified processes, heaps, modules, threads.
extern Process32First			: proc ; KERNEL32.DLL: Retrieves information about the first process in a snapshot.
extern Process32Next			: proc ; KERNEL32.DLL: Retrieves information about the next process in a snapshot.
extern strcmp				: proc ; MSVCRT.DLL (usually): Compares two C strings.

; === From Kernel32.dll ===
extern LoadLibraryA              : proc ; Loads the specified DLL into the address space of the calling process.
extern GetModuleHandleA          : proc ; Retrieves a module handle for a specified module.
extern GetProcAddress            : proc ; Retrieves the address of an exported function or variable from the specified DLL.
extern ExitThread                : proc ; Ends the calling thread and optionally returns an exit code.

; === KERNEL32.DLL Functions === ;ForDebugPrivFunction
extern GetStdHandle            : proc ; Retrieves a handle to the specified standard device (input, output, or error).
extern WriteConsoleA           : proc ; Writes a character string to a console screen buffer.
extern GetCurrentProcess       : proc ; Retrieves a pseudo handle for the current process.
extern GetLastError            : proc ; Retrieves the calling thread's last-error code value.
extern ExitProcess             : proc ; Ends the current process and returns an exit code.

; === Standard Handles ===
STD_OUTPUT_HANDLE              equ -11           ; Standard output handle for console

; === From Winmm.dll ===
extern timeGetTime               : proc ; Retrieves the system time, in milliseconds, since Windows was started.

; === Additional useful APIs you might be calling ===
extern QueryPerformanceCounter   : proc ; Retrieves the current value of the high-resolution performance counter.
extern GetTickCount              : proc ; Retrieves the number of milliseconds that have elapsed since the system was started.

.const
    Acceleration     dq 5                   ; Acceleration factor for time functions

    ; Section for initialized data.
.data
    ; Define null-terminated strings for message box titles and content.
    msg_title db "x64 dll injector",	0; Window title for message boxes.
    msg_not_found	db "Process is not running.", 0 ; Error message if target process isn't found.
    msg_cant_inject db "Injection failed.", 0   ; Error message if injection steps fail.
    msg_success		db "Injection succeded.", 0 ; Success message.

    kernel32		db "kernel32.dll", 0           ; Name of the core Windows library.
    load_library	db "LoadLibraryA", 0           ; Name of the function used to load DLLs.
    szGetProcAddress db 'GetProcAddress',0  ; GetProcAddress function name
    szGetModuleHandleA db 'GetModuleHandleA',0  ; GetProcAddress function name
    szFailed         db 'Failed', 0         ; Generic failure message
    
    ; Time function names
    szGetTickCount          db 'GetTickCount',0 
    sztimeGetTime           db 'timeGetTime',0
    szQueryPerformanceCounter db 'QueryPerformanceCounter',0
    szWinmm                 db 'winmm.dll',0
    
    ; Debug privilege constant
    SEDEBUGNAME           db 'SeDebugPrivilege',0
    
    ; DLL names
    szAdvapi32              db "Advapi32.dll", 0
    szShell32               db "Shell32.dll", 0
    
    ; Function names
    szOpenProcessToken      db "OpenProcessToken", 0
    szLookupPrivilegeValue  db "LookupPrivilegeValueA", 0
    szAdjustTokenPrivileges db "AdjustTokenPrivileges", 0
    szIsUserAnAdmin         db "IsUserAnAdmin", 0
    
    ; Messages
    szThreadCreated         db 'Thread has been created', 0
    szSuccesser             db 'Success', 0
    szElevationRequired     db 'This application requires administrator privileges',0
    szWin11Detected         db 'Windows 11 detected, using enhanced security bypass',0
    szProcessNotFound       db 'Failed to find target process',0
    szOpenProcessFailed     db 'Failed to open process handle',0
    szMemoryAllocationFailed db 'Failed to allocate memory in target process',0
    szMemoryWriteFailed     db 'Failed to write code to target process',0
    szGetProcAddressFailed  db 'Failed to get GetProcAddress function',0
    szThreadCreationFailed  db 'Failed to create remote thread',0
    szSuccess               db 'Time acceleration hooks installed successfully',0
    szWaitFailed            db 'Failed to wait for thread completion',0
    szOSVersionError        db 'Failed to get OS version',0
    szPlatformError         db 'Operating system detection failed',0
    
    szGetProcessMsg         db "Getting current process...", 0
    szOpenTokenMsg          db "Opening process token with rights: ", 0
    szLookupPrivMsg         db "Looking up privilege value...", 0
    szAdjustTokenMsg        db "Adjusting token privileges...", 0
    szErrorOpenToken        db "Error: Failed to open process token. Error code: ", 0
    szErrorLookupPriv       db "Error: Failed to lookup privilege value. Error code: ", 0
    szErrorAdjustToken      db "Error: Failed to adjust token privileges. Error code: ", 0
    szNumBuffer             db 32 dup(0)         ; Buffer for number conversion (increased size for 64-bit)
    
    ; Windows 11 detection variables
    dwMajorVersion          dd ?
    dwMinorVersion          dd ?
    dwBuildNumber           dd ?
    align 8                                      ; 64-bit alignment




;target_process	db "Notepad.exe", 0            ; The executable name of the process to inject into. CAP SENSITIVE PROCESS
target_process	db "ProcessToTarget.exe", 0
library_name	db "C:\\DllToInject.dll", 0    ; --- IMPORTANT: Full path to the DLL that will be injected. ---

; Calculate the length of the library_name string *excluding* the null terminator.
; '$' represents the current address, so '$ - library_name' gives the length.
library_len		equ $ - library_name


.data?
    hProcess                dq ?                 ; Handle to target process
    lpInjected              dq ?                 ; Address of injected code in target process
    lenInjected equ EndInjected - StartInjected                 ; Length of injected code
    hThread                 dq ?                 ; Handle to created remote thread
    JmpBuffer               db 14 dup(?)         ; Buffer for jump instruction (increased for x64)
    
    ; Original function pointers (64-bit)
    dGetTickCount           dq ?
    dtimeGetTime            dq ?
    dQueryPerformanceCounter dq ?
    dPerfCounterResult dq ? 
    
    ; Base time values
    BaseTickCount           dq ?
    BaseGetTime             dq ?
    BasePerformanceCount    dq ?
    
    hStdOut                 dq ?
    bytesWritten            dq ?
    
    ; For FindProcessByName
    hSnapshot               dq ?
    align 16                ; Ensure proper alignment for 64-bit



; Section for executable code.
.code





; Definition for IMAGE_NT_HEADERS64
IMAGE_NT_HEADERS64 STRUCT
    Signature       DWORD ?                 ; Should be IMAGE_NT_SIGNATURE ('PE\0\0')
    FileHeader      IMAGE_FILE_HEADER <>    ; Nested structure
    OptionalHeader  IMAGE_OPTIONAL_HEADER64 <> ; Nested structure (64-bit version)
IMAGE_NT_HEADERS64 ENDS

IMAGE_IMPORT_DESCRIPTOR STRUCT
    UNION
        Characteristics      DWORD ?
        OriginalFirstThunk   DWORD ? ; RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    ENDS
    TimeDateStamp            DWORD ?
    ForwarderChain           DWORD ?
    Name                     DWORD ? ; RVA to the null-terminated string name of the DLL
    FirstThunk               DWORD ? ; RVA to IAT (if bound this IAT has actual addresses)
IMAGE_IMPORT_DESCRIPTOR ENDS








StartInjected:
Injected PROC
    ; ... (prologue remains the same) ...
    push rbx
    push rsi
    push rdi
    push r12 ; <-- We will use R12 to store the EXE base address
    push r13
    push r14
    push r15
    sub rsp, 50h

    ; Save GetProcAddress (assuming it was passed in RCX)
    mov r15, rcx

     ; --- Find Kernel32 Base Address (Keep existing PEB method if it works) ---
    ; (Assuming the PEB walk to get Kernel32 base into RBX is working correctly)
    xor rax, rax
    mov rax, gs:[60h]                 ; PEB
    mov rax, [rax+18h]                ; LDR_DATA
    mov rsi, [rax+30h]                ; InInitializationOrderModuleList.Flink
    mov rsi, [rsi]                    ; -> ntdll entry
    mov rsi, [rsi]                    ; -> kernel32 entry
    mov rbx, [rsi+10h]                ; RBX = Kernel32 Base Address


    ; --- Get EXE Base Address using GetModuleHandleA(NULL) ---
    ; 1. Get address of GetModuleHandleA itself
    lea rdx, szGetModuleHandleA       ; RDX = "GetModuleHandleA"
    mov rcx, rbx                      ; RCX = Kernel32 Base Address
    call r15                          ; Call GetProcAddress(hKernel32, "GetModuleHandleA")
    test rax, rax                     ; Check if GetProcAddress succeeded
    jz SkipHooks                      ; Or some other error handling if GetModuleHandleA not found

    ; RAX now holds the address of GetModuleHandleA
    ; 2. Call GetModuleHandleA(NULL) to get EXE base
    xor rcx, rcx                      ; RCX = NULL (Argument for GetModuleHandleA)
    call rax                          ; Call GetModuleHandleA(NULL)
    test rax, rax                     ; Check if GetModuleHandleA(NULL) succeeded
    jz SkipHooks                      ; Or some other error handling if base address is NULL

    ; RAX now holds the EXE Base Address
    mov r12, rax                      ; R12 = EXE Base Address


    ; ... (GetProcAddress for GetTickCount, QPC, LoadLibraryA as before, using RBX for kernel32 base) ...
    lea rdx, szGetTickCount
    mov rcx, rbx                      ; KERNEL32 base
    call r15                          ; Call GetProcAddress
    mov [dGetTickCount], rax

    lea rdx, szQueryPerformanceCounter
    mov rcx, rbx                      ; KERNEL32 base
    call r15                          ; Call GetProcAddress
    mov [dQueryPerformanceCounter], rax

    lea rdx, load_library
    mov rcx, rbx ; kernel32 base
    call r15 ; GetProcAddress for LoadLibraryA
    ; Now RAX has LoadLibraryA address
    lea rcx, szWinmm
    call rax                          ; Call LoadLibraryA(szWinmm)
    mov r14, rax                      ; R14 = winmm.dll handle (check for NULL)
    test r14, r14
    jz SkipWinmmHooking

    ; Get timeGetTime function from winmm.dll
    lea rdx, sztimeGetTime
    mov rcx, r14                      ; winmm.dll handle
    call r15                          ; Call GetProcAddress
    mov [dtimeGetTime], rax
    test rax, rax
    jz SkipWinmmHooking

    ; ... (Initialize base time values as before) ...

SkipWinmmHooking:
    mov rax, [dQueryPerformanceCounter]
    test rax, rax
    jz SkipHooks
    lea rcx, BasePerformanceCount
    call rax

    ; === Set up hooks using SetHook function ===

    ; Hook GetTickCount (Targeting EXE's IAT)
    mov rax, [dGetTickCount]
    test rax, rax
    jz SkipHook1
    mov r8, rax               ; R8 = Original Address (GetTickCount)
    lea rdx, GetTickCountHook ; RDX = Hook Address
    mov rcx, r12              ; RCX = Module Base (EXE Base Address) <--- Correction
    call SetHook              ; SetHook(hExe, GetTickCountHook, pGetTickCount)
SkipHook1:

    ; Hook timeGetTime (Targeting WinMM's IAT - *ASSUMPTION*)
    ; This assumes you want to hook calls *originating* from winmm.dll or
    ; modules importing directly from it *after* it's loaded here.
    ; If you want to hook the EXE's calls to timeGetTime, use R12 for RCX here too.
    mov rax, [dtimeGetTime]
    test rax, rax
    jz SkipHook2
    mov r8, rax               ; R8 = Original Address (timeGetTime)
    lea rdx, timeGetTimeHook  ; RDX = Hook Address
    mov rcx, r12              ; RCX = Module Base, R12 is base of EXE, R14 is (Winmm.dll handle)
    call SetHook              ; SetHook(hWinmm, timeGetTimeHook, pTimeGetTime)
SkipHook2:

    ; Hook QueryPerformanceCounter (Targeting EXE's IAT)
    mov rax, [dQueryPerformanceCounter]
    test rax, rax
    jz SkipHook3
    mov r8, rax               ; R8 = Original Address (QueryPerformanceCounter)
    lea rdx, QueryPerformanceCounterHook ; RDX = Hook Address
    mov rcx, r12              ; RCX = Module Base (EXE Base Address) <--- Correction
    call SetHook              ; SetHook(hExe, QueryPerformanceCounterHook, pQPC)
SkipHook3:

SkipHooks:
    ; ... (epilogue remains the same) ...
    add rsp, 50h
    pop r15
    pop r14
    pop r13
    pop r12 ; <-- Restore R12
    pop rdi
    pop rsi
    pop rbx
    ret
Injected ENDP
; =====================================================================
; Hooks the specified function via IAT patching (Manual Stack Frame).
; RCX = inModule           (Base address of module containing the IAT)
; RDX = inHookProc         (Address of the hook function)
; R8  = inOriginalFunction (Address of the original function to find in IAT)
; RAX = Returns 1 on success, 0 on failure
; =====================================================================
SetHook proc 

    ; --- Manual Prologue ---
    ; Save non-volatile registers used by the function
    push rsi
    push rdi
    push rbx
    push r12
    push r13
    push r14
    ; Pushed 6 registers = 6 * 8 = 48 (30h) bytes. RSP is currently 16-byte aligned.

    ; Allocate stack space:
    ; Need 8 bytes for dwOldProtect
    ; Need 32 bytes (20h) shadow space for the upcoming 'call'
    ; Total needed = 40 bytes (28h)
    ; To maintain 16-byte alignment, must subtract a multiple of 16.
    ; Smallest multiple >= 40 bytes is 48 bytes (30h).
    sub rsp, 30h
    ; Stack layout: [rsp+20h] = dwOldProtect, [rsp+0]..[rsp+1Fh] = shadow space

    ; --- Function Body ---
    ; Move input parameters to non-volatile registers for safekeeping
    mov r12, rcx      ; r12 = inModule
    mov r13, rdx      ; r13 = inHookProc
    mov r14, r8       ; r14 = inOriginalFunction

    ; --- PE Header Parsing ---
    mov rdi, r12      ; RDI = Module base address

    ; Check DOS Header signature
    cmp word ptr [rdi + IMAGE_DOS_HEADER.e_magic], IMAGE_DOS_SIGNATURE
    jne CodeFail

    ; Get offset to NT Headers (e_lfanew is a DWORD)
    mov ebx, dword ptr [rdi + IMAGE_DOS_HEADER.e_lfanew]
    add rdi, rbx      ; RDI now points to IMAGE_NT_HEADERS64

    ; Check NT Header signature
    cmp dword ptr [rdi + IMAGE_NT_HEADERS64.Signature], IMAGE_NT_SIGNATURE
    jne CodeFail

    ; Get RVA of the Import Directory Table (DataDirectory index 1)
    mov edi, dword ptr [rdi + IMAGE_NT_HEADERS64.OptionalHeader.DataDirectory + (IMAGE_DIRECTORY_ENTRY_IMPORT * SIZEOF IMAGE_DATA_DIRECTORY) + IMAGE_DATA_DIRECTORY.VirtualAddress]
    test edi, edi     ; Check if RVA is zero (no import table)
    jz CodeFail
    ; rdi is automatically zero-extended
    add rdi, r12      ; RDI = VA of the first IMAGE_IMPORT_DESCRIPTOR

ImportLoop:
    ; Check for the end of the Import Directory Table (terminator descriptor)
    mov eax, dword ptr [rdi + 12]  ; Use numeric offset for Name (0Ch)
    or eax, dword ptr [rdi + 16]  ; Use numeric offset for FirstThunk (10h)
    jz DoneCheckingImports

    ; Get RVA of the Import Address Table (IAT) - using FirstThunk
    mov esi, dword ptr [rdi + 16] ; Use numeric offset for FirstThunk (10h)
    test esi, esi
    jz NextImportDescriptor
    ; rsi is automatically zero-extended
    add rsi, r12      ; RSI = VA of the IAT

ThunkLoop:
    ; Get the current function pointer from the IAT
    mov rax, qword ptr [rsi]
    test rax, rax     ; Check for the null terminator of this IAT list
    jz NextImportDescriptor

    ; Compare the IAT entry with the function we want to hook
    cmp rax, r14      ; r14 holds inOriginalFunction
    jne ContinueThunks

    ; --- Match Found ---
    ; Make the memory page containing the IAT entry writable
    mov rcx, rsi                  ; arg 1: lpAddress = Address of the IAT entry
    mov rdx, 8                    ; arg 2: dwSize = sizeof(QWORD)
    mov r8, PAGE_EXECUTE_READWRITE ; arg 3: flNewProtect = New protection flags

    ; Get address for dwOldProtect on stack (rsp + shadow space size)
    lea r9, [rsp + 20h]           ; arg 4: lpflOldProtect = Address on stack

    call VirtualProtect           ; Call the API function

    ; Check if VirtualProtect succeeded
    test rax, rax
    jz CodeFail                   ; Failed to change protection, abort

    ; Overwrite the IAT entry with the address of our hook function
    mov rbx, r13                  ; r13 holds inHookProc
    mov qword ptr [rsi], rbx      ; Write the hook address

    ; Hook successful
    mov eax, 1                    ; Set return value to 1 (success)
    jmp HookEnd                   ; Skip further searching

ContinueThunks:
    add rsi, 8                    ; Move to next IAT entry
    jmp ThunkLoop

NextImportDescriptor:
    add rdi, 20 ;SIZEOF IMAGE_IMPORT_DESCRIPTOR ; Move to next import descriptor
    jmp ImportLoop

DoneCheckingImports:
    ; Target function not found in any import descriptor's IAT
CodeFail:
    xor eax, eax                  ; Set return value to 0 (failure)

HookEnd:
    ; --- Manual Epilogue ---
    ; Deallocate stack space (must match the 'sub rsp' value)
    add rsp, 30h

    ; Restore non-volatile registers in reverse order
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rdi
    pop rsi

    ret                           ; Return (RAX has the result)

SetHook endp

; =====================================================================
; GetTickCountHook - Replacement for GetTickCount that accelerates time
; =====================================================================
GetTickCountHook PROC
    sub rsp, 40                     ; Shadow space + alignment
    
    call qword ptr [dGetTickCount]  ; Call original GetTickCount, this cannot work with Inline Injection
    mov rdx, rax                    ; RDX = currentTickCount
    sub rdx, qword ptr [BaseTickCount] ; RDX = currentTickCount - BaseTickCount
    imul rdx, qword ptr [Acceleration] ; RDX = (currentTickCount - BaseTickCount) * Acceleration
    add rax, rdx                    ; RAX = BaseTickCount + ((currentTickCount - BaseTickCount) * Acceleration)
    
    add rsp, 40                     ; Restore stack
    ret                             ; Return with accelerated tick count in RAX
GetTickCountHook ENDP

; =====================================================================
; timeGetTimeHook - Replacement for timeGetTime that accelerates time
; =====================================================================
timeGetTimeHook PROC
    sub rsp, 40                        ; Shadow space + alignment
    
    call qword ptr [dtimeGetTime]      ; Call original timeGetTime
    mov rdx, rax                       ; RDX = currentGetTime
    sub rdx, qword ptr [BaseGetTime]   ; RDX = currentGetTime - BaseGetTime
    imul rdx, qword ptr [Acceleration] ; RDX = (currentGetTime - BaseGetTime) * Acceleration
    add rax, rdx                       ; RAX = BaseGetTime + ((currentGetTime - BaseGetTime) * Acceleration)
    
    add rsp, 40                        ; Restore stack
    ret                                ; Return with accelerated time in RAX
timeGetTimeHook ENDP

QueryPerformanceCounterHook PROC
    ; RCX = lpPerformanceCount (original caller's pointer)

    ; --- Prologue ---
    push rcx       ; Save original lpPerformanceCount pointer onto the stack. RSP is now RSP_entry - 8 (misaligned).
    sub rsp, 28h   ; Allocate 8 bytes for local LARGE_INTEGER + 32 bytes shadow space = 40 bytes (0x28).
                   ; RSP is now RSP_entry - 8 - 0x28 = RSP_entry - 0x30 (16-byte aligned).
                   ; Stack layout:
                   ; [rsp+28h] = Saved original RCX
                   ; [rsp+20h] = Local LARGE_INTEGER variable (8 bytes)
                   ; [rsp+00h] = Shadow space (32 bytes)

    ; --- Call Original Function ---
    lea rcx, [rsp+20h] ; RCX = Address of the local variable (Correct argument register)
    call qword ptr [dQueryPerformanceCounter]
    test rax, rax      ; Check if original call succeeded
    jz QueryFailed_RestoreStack ; Jump to failure path

    ; --- Process Result (Original Call Succeeded) ---
    mov rax, qword ptr [rsp+20h] ; Load the counter value from the local variable
    sub rax, qword ptr [BasePerformanceCount] ; Calculate delta
    imul rax, qword ptr [Acceleration]        ; Apply acceleration
    add rax, qword ptr [BasePerformanceCount] ; Add base back

    ; --- Store Final Result ---
    mov rdx, [rsp+28h] ; Restore the original caller's pointer from the stack into RDX
    mov [rdx], rax     ; Write the final result to the original caller's address. (Should be safe now)

    ; --- Success Path ---
    mov rax, 1         ; Set return value to TRUE
    jmp QueryEnd_RestoreStack

QueryFailed_RestoreStack:
    ; --- Failure Path ---
    xor rax, rax       ; Set return value to FALSE

QueryEnd_RestoreStack:
    ; --- Epilogue ---
    add rsp, 28h       ; Deallocate shadow space and local variable
    pop rcx            ; Restore original RCX
    ret                ; Return (RAX holds TRUE or FALSE)

QueryPerformanceCounterHook ENDP

EndInjected:












; =====================================================================
; Inline Injection - Problem, overwrites primary function so cannot call within hook
; =====================================================================
InlineInjected PROC
    ; RCX = lpGetProcAddress
    ; Save non-volatile registers
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 80                     ; Shadow space + locals
    
    ; Save GetProcAddress
    mov r15, rcx                    ; R15 = GetProcAddress
    
    ; Find KERNEL32 base address
    xor rax, rax
    mov rax, gs:[60h]               ; PEB
    mov rax, [rax+18h]              ; LDR_DATA
    mov rsi, [rax+30h]              ; InInitializationOrderModuleList.Flink
    mov rsi, [rsi]                  ; first entry is NTdll next entry in the list (2nd module)
    mov rbx, [rsi+30h]              ; DllBase (base of kernel32.dll)
    mov rbx, [rsi+10h]              ; Base address of KERNEL32
    
    ; Get kernel32 functions
    lea rdx, szGetTickCount
    mov rcx, rbx                    ; KERNEL32 base
    call r15                        ; Call GetProcAddress
    mov [dGetTickCount], rax
    
    ; Load winmm.dll
    lea rcx, szWinmm
    call LoadLibraryA
    mov r14, rax                    ; R14 = winmm.dll handle
    
    ; Get timeGetTime function
    lea rdx, sztimeGetTime
    mov rcx, r14                    ; Wimm.dll base
    call r15                        ; Call GetProcAddress
    mov [dtimeGetTime], rax
    
    ; Get QueryPerformanceCounter function
    lea rdx, szQueryPerformanceCounter
    mov rcx, rbx                    ; KERNEL32 base
    call r15                        ; Call GetProcAddress
    mov [dQueryPerformanceCounter], rax
    
    ; Initialize base time values
    call qword ptr [dGetTickCount]
    mov [BaseTickCount], rax
    
    call qword ptr [dtimeGetTime]
    mov [BaseGetTime], rax
    
    lea rcx, BasePerformanceCount
    call qword ptr [dQueryPerformanceCounter]
    
    ; Set up hooks using helper function (defined below)
    mov rcx, qword ptr [dGetTickCount]
    lea rdx, GetTickCountHook
    call SetHook
    
    mov rcx, qword ptr [dtimeGetTime]
    lea rdx, timeGetTimeHook
    call SetHook
    
    mov rcx, qword ptr [dQueryPerformanceCounter]
    lea rdx, QueryPerformanceCounterHook
    call SetHook
    
    ; Exit thread
    xor rcx, rcx                    ; Return code 0
    ;call ExitThread
    
    ; Restore non-volatile registers
    add rsp, 80
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
InlineInjected ENDP

; =====================================================================
; Inline Injection SetHook - Used to patch the first few bytes with Jmp Address, Return
; =====================================================================
InlineSetHook PROC 
    ; RCX = Original function address
    ; RDX = Hook function address
    
    sub rsp, 56                     ; Shadow space + alignment
    
    ; Save parameters
    mov r8, rcx                     ; R8 = Original function
    mov r9, rdx                     ; R9 = Hook function
    mov r12, rcx                     ; R8 = Original function
    mov r13, rdx                     ; R9 = Hook function

    
    ; Calculate relative jump (for 64-bit, need to use indirect jump)
    ; For direct near jump: mov rax, target; jmp rax
    mov byte ptr [JmpBuffer], 48h   ; REX.W prefix
    mov byte ptr [JmpBuffer+1], 0B8h ; MOV RAX, imm64
    mov rax, r9                     ; RAX = hook address
    mov qword ptr [JmpBuffer+2], rax ; Store target address
    mov byte ptr [JmpBuffer+10], 0FFh ; JMP instruction
    mov byte ptr [JmpBuffer+11], 0E0h ; Target is RAX
    
    ; Change memory protection
    mov rcx, r8                     ; Original function address
    mov rdx, 14                     ; Size of jump instruction
    mov r8, 40h                     ; PAGE_EXECUTE_READWRITE
    lea r9, [rsp+32]                ; Old protection (use shadow space)
    call VirtualProtect
    
    ; Write the jump instruction
    mov rcx, 12                     ; 12 bytes to copy (mov rax, target + jmp rax)
    lea rsi, JmpBuffer              ; Source
    mov rdi, r12                     ; Destination (original function)
    rep movsb                       ; Copy bytes
    
    mov rax, 1                      ; Return success
    add rsp, 56                     ; Restore stack
    ret
InlineSetHook ENDP

; ============================================================================
; find_process PROC
; Purpose: Finds the Process ID (PID) of the 'target_process' by iterating
;          through a snapshot of all running processes.
; Input:   None (uses global 'target_process' variable).
; Output:  EAX = PID if found, 0 otherwise.
; Uses:    CreateToolhelp32Snapshot, Process32First, Process32Next, CloseHandle, strcmp
; Clobbers: RAX, RCX, RDX, R8-R11 (as per x64 ABI), R12, R13 (saved/restored)
; ============================================================================
find_process proc

	; Standard x64 function prologue: Save non-volatile registers that will be used.
	; R12-R15 must be preserved across function calls by the callee.
	push	r12								; Save R12 (will be used for snapshot handle).
	push	r13								; Save R13 (will be used for the found PID).
	; Save the base pointer and set up the new stack frame base.
	push	rbp
	mov		rbp, rsp

	; Allocate stack space for local variables and shadow space.
	; Needs space for PROCESSENTRY32 struct (~304 bytes = 130h) + shadow space (32 bytes = 20h).
	; 150h is allocated, providing some extra room.
	sub		rsp, 150h
	; Align the stack pointer to a 16-byte boundary. Required by the x64 ABI before making CALLs.
	and		rsp, -10h
	; Initialize the 'found PID' register (R13) to 0.
	xor		r13, r13

	; Prepare the PROCESSENTRY32 structure on the stack. Its address will be [rsp + 20h].
	; The first member (dwSize) must be set before calling Process32First/Next.
	; sizeof(PROCESSENTRY32) is 304 bytes (0x130).
	mov		qword ptr [rsp + 20h], 130h		; Set pe32.dwSize = 304. (Note: QWORD mov used, but only DWORD needed).

	; Call CreateToolhelp32Snapshot to get a snapshot of running processes.
	; Arguments (x64 ABI): RCX, RDX, R8, R9, then stack.
	mov		rcx, 2							; RCX = dwFlags = TH32CS_SNAPPROCESS (snapshot processes).
	xor		rdx, rdx						; RDX = th32ProcessID = 0 (snapshot all processes).
	call	CreateToolhelp32Snapshot		; Return value (handle or INVALID_HANDLE_VALUE) in RAX.

	mov		r12, rax						; Store the snapshot handle in R12.
	cmp		r12, -1							; Compare handle with INVALID_HANDLE_VALUE (-1).
	je		exit							; If failed (-1), jump to the exit routine.

	; Call Process32First to retrieve information about the first process.
	mov		rcx, r12						; RCX = hSnapshot (handle from CreateToolhelp32Snapshot).
	lea		rdx, [rsp + 20h]				; RDX = lpProcessEntry (pointer to our buffer on the stack).
	call	Process32First					; Returns non-zero on success, 0 on failure/end.

	cmp		rax, 0							; Check the return value in RAX.
	je		exit_cleanup					; If failed (0), jump to cleanup (no processes found or error).

; Loop through the processes in the snapshot.
process_loop:
	; Compare the current process name with our target process name.
	lea		rcx, target_process				; RCX = pointer to the target process name ("notepad.exe").
	; Calculate address of szExeFile within PROCESSENTRY32 on stack: [rsp + 20h + offset].
	; Offset(szExeFile) = 0x2C (44 bytes). See PROCESSENTRY32 structure definition.
	lea		rdx, [rsp + 20h + 2Ch]			; RDX = pointer to pe32.szExeFile on the stack.
	call	strcmp							; Call C string comparison function. Returns 0 if strings match.

	cmp		rax, 0							; Check if strcmp returned 0.
	je		found							; If strings are equal (0), jump to the 'found' routine.

	; If not found, get the next process in the snapshot.
	mov		rcx, r12						; RCX = hSnapshot.
	lea		rdx, [rsp + 20h]				; RDX = lpProcessEntry (pointer to buffer).
	call	Process32Next					; Returns non-zero on success, 0 on failure/end of list.

	cmp		rax, 0							; Check the return value.
	jne		process_loop					; If successful (non-zero), loop back to check the next process.

; If Process32Next returns 0, we've checked all processes or an error occurred.
; Now, clean up the snapshot handle.
exit_cleanup:
	mov		rcx, r12						; RCX = handle to close.
	call	CloseHandle						; Close the snapshot handle to free resources.

; Prepare to return from the function.
exit:
	mov		eax, r13d						; Move the found PID (from lower 32 bits of R13) into EAX (return value).
	; Standard x64 function epilogue: Restore stack and saved registers.
	mov		rsp, rbp						; Deallocate local stack space.
	pop		rbp								; Restore the base pointer.
	pop		r13								; Restore original R13 value.
	pop		r12								; Restore original R12 value.
	ret										; Return control to the caller.

; This code block is executed when strcmp finds a match.
found:
	; Extract the Process ID (th32ProcessID) from the PROCESSENTRY32 structure.
	; Offset(th32ProcessID) = 0x8.
	mov		r13d, dword ptr [rsp + 20h + 8h] ; Copy PID from [rsp + 20h + 8h] into R13D (lower 32 bits of R13).
	jmp		exit_cleanup					; Jump to close the snapshot handle and return the PID.

find_process endp

; ============================================================================
; pet_proc_address PROC
; Purpose: Retrieves the memory address of the GetProcAddress function from kernel32.dll.
; Input:   None.
; Output:  RAX = Address of LoadLibraryA if successful, 0 otherwise.
; Uses:    GetModuleHandleA, GetProcAddress
; Clobbers: RAX, RCX, RDX, R8-R11 (as per x64 ABI)
; ============================================================================
get_proc_address proc

	; Standard x64 function prologue.
	push	rbp
	mov		rbp, rsp

	; Allocate shadow space (32 bytes) required for calling functions.
	sub		rsp, 20h
	; Ensure stack alignment (may be redundant if RSP was already aligned).
	and		rsp, -10h

	; Get a handle to kernel32.dll (it's already loaded in almost any process).
	lea		rcx, kernel32					; RCX = lpModuleName = pointer to "kernel32.dll".
	call	GetModuleHandleA				; Returns module handle in RAX, or NULL on failure.

	; Get the address of the LoadLibraryA function within kernel32.dll.
	mov		rcx, rax						; RCX = hModule (handle from GetModuleHandleA).
	lea		rdx, szGetProcAddress				; RDX = lpProcName = pointer to "LoadLibraryA".
	call	GetProcAddress					      ; Returns function address in RAX, or NULL on failure.

	; Address of LoadLibraryA (or NULL) is now in RAX, ready to be returned.

	; Standard x64 function epilogue.
	mov		rsp, rbp						; Deallocate shadow space.
	pop		rbp								; Restore base pointer.
	ret										; Return control to the caller.

get_proc_address endp

; ============================================================================
; get_load_library PROC
; Purpose: Retrieves the memory address of the LoadLibraryA function from kernel32.dll.
; Input:   None.
; Output:  RAX = Address of LoadLibraryA if successful, 0 otherwise.
; Uses:    GetModuleHandleA, GetProcAddress
; Clobbers: RAX, RCX, RDX, R8-R11 (as per x64 ABI)
; ============================================================================
get_load_library proc

	; Standard x64 function prologue.
	push	rbp
	mov		rbp, rsp

	; Allocate shadow space (32 bytes) required for calling functions.
	sub		rsp, 20h
	; Ensure stack alignment (may be redundant if RSP was already aligned).
	and		rsp, -10h

	; Get a handle to kernel32.dll (it's already loaded in almost any process).
	lea		rcx, kernel32					; RCX = lpModuleName = pointer to "kernel32.dll".
	call	GetModuleHandleA				; Returns module handle in RAX, or NULL on failure.

	; Get the address of the LoadLibraryA function within kernel32.dll.
	mov		rcx, rax						; RCX = hModule (handle from GetModuleHandleA).
	lea		rdx, load_library				; RDX = lpProcName = pointer to "LoadLibraryA".
	call	GetProcAddress					; Returns function address in RAX, or NULL on failure.

	; Address of LoadLibraryA (or NULL) is now in RAX, ready to be returned.

	; Standard x64 function epilogue.
	mov		rsp, rbp						; Deallocate shadow space.
	pop		rbp								; Restore base pointer.
	ret										; Return control to the caller.

get_load_library endp



; =====================================================================
; WriteConsoleString - Outputs a string to the console
; =====================================================================
WriteConsoleString PROC
    ; RCX = string pointer (already set as first parameter)
    sub rsp, 56                     ; Shadow space + align stack
    
    ; Get console handle (only once)
    cmp hStdOut, 0
    jne already_have_handle
    mov rcx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov hStdOut, rax
already_have_handle:
    
    ; Calculate string length
    mov rdx, rcx                    ; RDX = string pointer
    mov r8, rdx                     ; R8 = also string pointer
    xor r9, r9                      ; R9 = 0 (counter)
    
count_loop:
    cmp byte ptr [r8], 0
    je count_done
    inc r9
    inc r8
    jmp count_loop
    
count_done:
    ; Write string to console
    ; First parameter (RCX) already has console handle
    mov rcx, hStdOut
    ; RDX already has string pointer
    ; R8 already has length
    lea r9, bytesWritten
    mov qword ptr [rsp+32], 0       ; Fifth parameter (NULL)
    call WriteConsoleA
    
    ; Return number of bytes written
    mov rax, bytesWritten
    
    add rsp, 56                     ; Restore stack
    ret
WriteConsoleString ENDP

; =====================================================================
; dwtoa - Convert QWORD to ASCII string (64-bit version)
; =====================================================================
dwtoa PROC
    ; RCX = value to convert
    ; RDX = buffer pointer
    sub rsp, 56                     ; Shadow space + alignment
    
    mov rax, rcx                    ; RAX = value
    mov r8, rdx                     ; R8 = buffer pointer
    xor r9, r9                      ; R9 = 0 (position counter)
    
    ; Handle negative numbers
    cmp rax, 0
    jge convert_loop
    neg rax
    mov byte ptr [r8], '-'
    inc r8
    inc r9
    
convert_loop:
    ; Divide by 10
    mov rcx, 10
    xor rdx, rdx                    ; Clear RDX for division
    div rcx                         ; RAX = quotient, RDX = remainder
    
    ; Convert remainder to ASCII
    add dl, '0'
    mov byte ptr [r8+r9], dl
    inc r9
    
    ; Check if done
    test rax, rax
    jnz convert_loop
    
    ; Add null terminator
    mov byte ptr [r8+r9], 0
    
    ; Reverse the string (excluding minus sign if present)
    mov rdx, r8                     ; RDX = buffer start
    add r9, rdx                     ; R9 = buffer end
    dec r9                          ; Point to last character
    
    cmp byte ptr [rdx], '-'
    jne reverse_loop
    inc rdx                         ; Skip minus sign
    
reverse_loop:
    cmp rdx, r9
    jge reverse_done
    
    ; Swap characters
    mov al, byte ptr [rdx]          ; Fixed: use AL instead of CL
    mov bl, byte ptr [r9]           ; Fixed: use BL instead of CH
    mov byte ptr [rdx], bl
    mov byte ptr [r9], al
    
    ; Move inward
    inc rdx
    dec r9
    jmp reverse_loop
    
reverse_done:
    mov rax, 1                      ; Return success
    add rsp, 56                     ; Restore stack
    ret
dwtoa ENDP


; ============================================================================
; inject_function PROC
; Purpose: Injects the function into the target process.
; Input:   RCX = Process ID (PID) of the target process.
; Output:  RAX = 1 if injection succeeded, 0 otherwise.
; Uses:    OpenProcess, VirtualAllocEx, WriteProcessMemory, get_load_library,
;          CreateRemoteThread, CloseHandle
; Clobbers: RAX, RCX, RDX, R8-R11 (as per x64 ABI), R12, R13, R14 (saved/restored)
; ============================================================================
inject_function proc

	; Standard x64 prologue: Save non-volatile registers used.
	push	r12							; Save R12 (will be used for process handle).
	push	r13							; Save R13 (will be used for allocated memory pointer).
	push	r14							; Save R14 (will be used for injection status flag).
	push	rbp
	mov		rbp, rsp

	; Allocate stack space for arguments passed on the stack to API calls
	; (e.g., 5th/6th/7th args for VirtualAllocEx/WriteProcessMemory/CreateRemoteThread)
	; Needs 3*8=24 bytes (18h) for CRT args + 32 bytes (20h) shadow space = 38h minimum.
	sub		rsp, 38h
	; Align stack to 16-byte boundary.
	and		rsp, -10h
	; Initialize injection status flag (R14) to 0 (failure). Will be set to 1 on success.
	xor		r14, r14

	; Save the target PID (passed in RCX) into a non-volatile register (R12).
	mov		r12, rcx

	; Call OpenProcess to get a handle to the target process.
	mov		rcx, 1FFFFFh				; RCX = dwDesiredAccess = PROCESS_ALL_ACCESS (request full permissions).
	xor		rdx, rdx					; RDX = bInheritHandle = FALSE (handle is not inheritable).
	mov		r8 , r12					; R8  = dwProcessId = The PID of the target process.
	call	OpenProcess					      ; Returns process handle in RAX, or NULL on failure.

	mov		r12, rax					; Store the process handle in R12 (overwriting the PID).
	; Check if OpenProcess failed. It returns NULL (0) on failure.
	; Note: Original code compared to -1, which is technically incorrect but might work
	; due to sign extension. Comparing to 0 is more robust. For commenting, we follow the code.
	cmp		r12, -1					; Check if handle is INVALID_HANDLE_VALUE (-1) or NULL.
	je		exit						; If failed, jump to the final exit.


        ;mov rbx, OFFSET EndInjected
        ;sub rbx, OFFSET StartInjected
        ;mov lenInjected, rbx

	; Allocate memory within the target process's address space for the DLL path.
	mov		rcx, r12					; RCX = hProcess (handle from OpenProcess).
	xor		rdx, rdx					; RDX = lpAddress = NULL (let the system choose the address).

      mov eax, lenInjected    ; works for 32-bit immediate
      mov r8d, eax            ; zero-extend into r8 ; R8  = dwSize = Size of function section to write

	mov		r9 , 3000h					; R9  = flAllocationType = MEM_COMMIT | MEM_RESERVE (0x1000 | 0x2000).
	mov qword ptr [rsp + 20h], 4 ; StackArg1 = flProtect = PAGE_READWRITE (0x4).	; 5th argument goes on the stack (at RSP+20h in the caller's frame).
	call	VirtualAllocEx				      ; Returns pointer to allocated memory in RAX, or NULL on failure.

	mov		r13, rax					; Store the allocated memory pointer in R13.
	cmp		r13, 0				      ; Check if VirtualAllocEx returned NULL (0).
	je		exit_cleanup				; If failed, jump to cleanup (close process handle).

	; Write the Injected into the allocated memory in the target process.
	mov		rcx, r12					; RCX = hProcess.
	mov		rdx, r13					; RDX = lpBaseAddress (pointer returned by VirtualAllocEx).
	lea		r8 , StartInjected			      ; R8  = lpBuffer (pointer to our local DLL path string).
	mov		r9d , lenInjected			      ; R9  = nSize (length of the string to write).
	                                                ; 5th argument on the stack.
	mov qword ptr [rsp + 20h], 0; StackArg1 = lpNumberOfBytesWritten = NULL (optional, don't need the value).
	call	WriteProcessMemory			      ; Returns non-zero on success, 0 on failure.

	cmp		rax, 0					; Check if WriteProcessMemory returned 0.
	je		exit_cleanup				; If failed, jump to cleanup.

      ; Get the address of LoadLibraryA. This address is the same in the target process
	; because kernel32.dll is loaded at the same base address in all processes (usually).
	call	get_proc_address			            ; Returns address in RAX.

	cmp		rax, 0					; Check if get_load_library failed (returned NULL).
	je		exit_cleanup				; If failed, jump to cleanup.


	
	; Create a new thread in the target process. This thread will start execution
	; at the address of LoadLibraryA, and will be passed the address of the DLL
	; path (which we wrote into the target process) as its parameter.
	; Effectively calls: Injected(address_of_GetProcessAddr)
	mov		rcx, r12					; Arg1: hProcess (target process handle).
	xor		rdx, rdx					; Arg2: lpThreadAttributes (NULL = default).
	xor		r8 , r8					; Arg3: dwStackSize (0 = default).
	mov		r9 , rax					; Arg4: lpStartAddress (address of WriteProcessMemory).
	                                                ; Arguments 5, 6, 7 are passed on the stack.
	mov qword ptr [rsp + 20h], r13                  ; Arg5: lpParameter (address of the allocated DLL path string).
	mov qword ptr [rsp + 28h], 0                    ; Arg6: dwCreationFlags (0 = run immediately).
	mov qword ptr [rsp + 30h], 0                    ; Arg7: lpThreadId (NULL = don't need the ID).
	call	CreateRemoteThread			      ; Returns handle to the new thread in RAX, or NULL on failure.

	; We don't usually need to interact with the remote thread further, so close its handle.
	mov		rcx, rax					  ; RCX = hHandle (the thread handle returned by CreateRemoteThread).
	call	CloseHandle					        ; Close the handle. (Check for NULL handle before calling ideally).

	; If we reached here, the remote thread was likely created successfully.
	mov		r14, 1					  ; Set the injection status flag (R14) to 1 (success).

                                                        ; Cleanup routine: Close the handle to the target process.
exit_cleanup:
	mov		rcx, r12					  ; RCX = hHandle (process handle stored in R12).
	call	CloseHandle					        ; Close the handle. (Check for NULL handle before calling ideally).

; Final exit point for the procedure.
exit:
	mov		rax, r14					  ; Move the injection status flag (R14) into RAX (return value).
	; Standard x64 function epilogue.
	mov		rsp, rbp					  ; Deallocate local stack space.
	pop		rbp							; Restore base pointer.
	pop		r14							; Restore original R14 value.
	pop		r13							; Restore original R13 value.
	pop		r12							; Restore original R12 value.
	ret									; Return control to the caller.

inject_function endp


; =====================================================================
; EnableDebugPrivilege - Enables SE_DEBUG_NAME privilege for the process
; =====================================================================
EnableDebugPrivilege PROC
    sub rsp, 160                    ; Shadow space + locals
    sub rsp, 08h ;Alignment

    ; Define local variables on stack
    ; These need to be offset-based in x64
    mov qword ptr [rsp+80], 0       ; hToken
    ; tkp at [rsp+88]  (TOKEN_PRIVILEGES size is 16 bytes)
    ; luid at [rsp+104] (LUID size is 8 bytes)
    mov qword ptr [rsp+112], 0      ; lhProcess
    mov dword ptr [rsp+120], 0      ; dwTokenRights
    mov dword ptr [rsp+124], 0      ; dwLastError
    
    ; Get standard output handle
    mov rcx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov hStdOut, rax
    
    ; Output starting message
    lea rcx, szGetProcessMsg
    call WriteConsoleString
    
    ; Get current process handle
    call GetCurrentProcess
    mov qword ptr [rsp+112], rax    ; lhProcess
    
    ; Convert process handle to string and output
    mov rcx, rax
    lea rdx, szNumBuffer
    call dwtoa
    lea rcx, szNumBuffer
    call WriteConsoleString
    
    ; Compute combined token rights
    mov dword ptr [rsp+120], TOKEN_ADJUST_PRIVILEGES
    or dword ptr [rsp+120], TOKEN_QUERY
    
    ; Output token rights message
    lea rcx, szOpenTokenMsg
    call WriteConsoleString
    
    ; Convert token rights to string and output
    mov ecx, dword ptr [rsp+120]    ; dwTokenRights
    mov rcx, rcx                    ; Zero-extend to QWORD
    lea rdx, szNumBuffer
    call dwtoa
    lea rcx, szNumBuffer
    call WriteConsoleString
    
    ; Try to open the process token
    mov rcx, qword ptr [rsp+112]    ; lhProcess
    mov edx, dword ptr [rsp+120]    ; dwTokenRights
    lea r8, qword ptr [rsp+80]      ; &hToken
    call OpenProcessToken
    test rax, rax
    jnz token_opened
    
    ; Handle error
    call GetLastError
    mov dword ptr [rsp+124], eax    ; dwLastError
    
    ; Output error message
    lea rcx, szErrorOpenToken
    call WriteConsoleString
    
    ; Convert error code to string and output
    mov rcx, rax
    lea rdx, szNumBuffer
    call dwtoa
    lea rcx, szNumBuffer
    call WriteConsoleString
    
    ; Exit with error
    mov rcx, rax
    call ExitProcess
    
token_opened:
    ; Output token handle
    mov rcx, qword ptr [rsp+80]     ; hToken
    lea rdx, szNumBuffer
    call dwtoa
    lea rcx, szNumBuffer
    call WriteConsoleString
    
    ; Output lookup privilege message
    lea rcx, szLookupPrivMsg
    call WriteConsoleString

    mov rax, rsp
    and rax, 0Fh
    test rax, rax
    jnz misaligned
    
    ; Get the LUID for the debug privilege
    xor rcx, rcx                    ; NULL for system name
    lea rdx, SEDEBUGNAME
    lea r8, qword ptr [rsp+104]     ; &luid
    call LookupPrivilegeValue
    test rax, rax
    jnz lookup_success
    
    ; Handle error
    call GetLastError
    mov dword ptr [rsp+124], eax    ; dwLastError
    
    ; Output error message
    lea rcx, szErrorLookupPriv
    call WriteConsoleString
    
    ; Convert error code to string and output
    mov rcx, rax
    lea rdx, szNumBuffer
    call dwtoa
    lea rcx, szNumBuffer
    call WriteConsoleString
    
    ; Clean up and return failure
    mov rcx, qword ptr [rsp+80]     ; hToken
    call CloseHandle
    xor rax, rax
    add rsp, 160
    ret
    
lookup_success:
    ; Output LUID values - LowPart
    mov eax, dword ptr [rsp+104]    ; luid.LowPart
    mov rcx, rax                    ; Zero extend to QWORD
    lea rdx, szNumBuffer
    call dwtoa
    lea rcx, szNumBuffer
    call WriteConsoleString
    
    ; Output LUID values - HighPart
    mov eax, dword ptr [rsp+108]    ; luid.HighPart
    mov rcx, rax                    ; Zero extend to QWORD
    lea rdx, szNumBuffer
    call dwtoa
    lea rcx, szNumBuffer
    call WriteConsoleString
    
    ; Set up the privilege structure
    mov dword ptr [rsp+88], 1       ; tkp.PrivilegeCount = 1
    mov eax, dword ptr [rsp+104]    ; luid.LowPart
    mov dword ptr [rsp+92], eax     ; tkp.Privileges[0].Luid.LowPart
    mov eax, dword ptr [rsp+108]    ; luid.HighPart
    mov dword ptr [rsp+96], eax     ; tkp.Privileges[0].Luid.HighPart
    mov dword ptr [rsp+100], SE_PRIVILEGE_ENABLED ; tkp.Privileges[0].Attributes
    
    ; Output adjust token message
    lea rcx, szAdjustTokenMsg
    call WriteConsoleString
    
    ; Adjust the token privileges
    mov rcx, qword ptr [rsp+80]     ; hToken
    xor rdx, rdx                    ; FALSE
    lea r8, qword ptr [rsp+88]      ; &tkp
    mov r9d, sizeof TOKEN_PRIVILEGES
    mov qword ptr [rsp+32], 0       ; NULL
    mov qword ptr [rsp+40], 0       ; NULL
    call AdjustTokenPrivileges
    test rax, rax
    jnz adjust_success
    
    ; Handle error
    call GetLastError
    mov dword ptr [rsp+124], eax    ; dwLastError
    
    ; Output error message
    lea rcx, szErrorAdjustToken
    call WriteConsoleString
    
    ; Convert error code to string and output
    mov rcx, rax
    lea rdx, szNumBuffer
    call dwtoa
    lea rcx, szNumBuffer
    call WriteConsoleString
    
    ; Clean up and return failure
    mov rcx, qword ptr [rsp+80]     ; hToken
    call CloseHandle
    xor rax, rax
    add rsp, 160
    ret
    
adjust_success:
    ; Clean up
    mov rcx, qword ptr [rsp+80]     ; hToken
    call CloseHandle
    
    ; Return success
    mov rax, 1
misaligned:
    add rsp, 160
    add rsp, 08h ;Remove the alignment
    ret
EnableDebugPrivilege ENDP

; ============================================================================
; inject_image PROC
; Purpose: Injects the specified DLL ('library_name') into the target process.
; Input:   RCX = Process ID (PID) of the target process.
; Output:  RAX = 1 if injection succeeded, 0 otherwise.
; Uses:    OpenProcess, VirtualAllocEx, WriteProcessMemory, get_load_library,
;          CreateRemoteThread, CloseHandle
; Clobbers: RAX, RCX, RDX, R8-R11 (as per x64 ABI), R12, R13, R14 (saved/restored)
; ============================================================================
inject_image proc

	; Standard x64 prologue: Save non-volatile registers used.
	push	r12							; Save R12 (will be used for process handle).
	push	r13							; Save R13 (will be used for allocated memory pointer).
	push	r14							; Save R14 (will be used for injection status flag).
	push	rbp
	mov		rbp, rsp

	; Allocate stack space for arguments passed on the stack to API calls
	; (e.g., 5th/6th/7th args for VirtualAllocEx/WriteProcessMemory/CreateRemoteThread)
	; Needs 3*8=24 bytes (18h) for CRT args + 32 bytes (20h) shadow space = 38h minimum.
	sub		rsp, 38h
	; Align stack to 16-byte boundary.
	and		rsp, -10h
	; Initialize injection status flag (R14) to 0 (failure). Will be set to 1 on success.
	xor		r14, r14

	; Save the target PID (passed in RCX) into a non-volatile register (R12).
	mov		r12, rcx

	; Call OpenProcess to get a handle to the target process.
	mov		rcx, 1FFFFFh				; RCX = dwDesiredAccess = PROCESS_ALL_ACCESS (request full permissions).
	xor		rdx, rdx					; RDX = bInheritHandle = FALSE (handle is not inheritable).
	mov		r8 , r12					; R8  = dwProcessId = The PID of the target process.
	call	OpenProcess					      ; Returns process handle in RAX, or NULL on failure.

	mov		r12, rax					; Store the process handle in R12 (overwriting the PID).
	; Check if OpenProcess failed. It returns NULL (0) on failure.
	; Note: Original code compared to -1, which is technically incorrect but might work
	; due to sign extension. Comparing to 0 is more robust. For commenting, we follow the code.
	cmp		r12, -1					; Check if handle is INVALID_HANDLE_VALUE (-1) or NULL.
	je		exit						; If failed, jump to the final exit.

	; Allocate memory within the target process's address space for the DLL path.
	mov		rcx, r12					; RCX = hProcess (handle from OpenProcess).
	xor		rdx, rdx					; RDX = lpAddress = NULL (let the system choose the address).
   	mov		r8 , library_len			      ; R8  = dwSize = Size needed for the DLL path string.
	mov		r9 , 3000h					; R9  = flAllocationType = MEM_COMMIT | MEM_RESERVE (0x1000 | 0x2000).
	; 5th argument goes on the stack (at RSP+20h in the caller's frame).
	mov qword ptr [rsp + 20h], 4 ; StackArg1 = flProtect = PAGE_READWRITE (0x4).
	call	VirtualAllocEx				      ; Returns pointer to allocated memory in RAX, or NULL on failure.

	mov		r13, rax					; Store the allocated memory pointer in R13.
	cmp		r13, 0				      ; Check if VirtualAllocEx returned NULL (0).
	je		exit_cleanup				; If failed, jump to cleanup (close process handle).

	; Write the DLL path string into the allocated memory in the target process.
	mov		rcx, r12					; RCX = hProcess.
	mov		rdx, r13					; RDX = lpBaseAddress (pointer returned by VirtualAllocEx).
	lea		r8 , library_name			      ; R8  = lpBuffer (pointer to our local DLL path string).
	mov		r9 , library_len			      ; R9  = nSize (length of the string to write).
	; 5th argument on the stack.
	mov qword ptr [rsp + 20h], 0; StackArg1 = lpNumberOfBytesWritten = NULL (optional, don't need the value).
	call	WriteProcessMemory			      ; Returns non-zero on success, 0 on failure.

	cmp		rax, 0					; Check if WriteProcessMemory returned 0.
	je		exit_cleanup				; If failed, jump to cleanup.

	; Get the address of LoadLibraryA. This address is the same in the target process
	; because kernel32.dll is loaded at the same base address in all processes (usually).
	call	get_load_library			            ; Returns address in RAX.

	cmp		rax, 0					; Check if get_load_library failed (returned NULL).
	je		exit_cleanup				; If failed, jump to cleanup.

	; Create a new thread in the target process. This thread will start execution
	; at the address of LoadLibraryA, and will be passed the address of the DLL
	; path (which we wrote into the target process) as its parameter.
	; Effectively calls: LoadLibraryA(address_of_dll_path_in_target_process)
	mov		rcx, r12					; Arg1: hProcess (target process handle).
	xor		rdx, rdx					; Arg2: lpThreadAttributes (NULL = default).
	xor		r8 , r8					; Arg3: dwStackSize (0 = default).
	mov		r9 , rax					; Arg4: lpStartAddress (address of LoadLibraryA).
	; Arguments 5, 6, 7 are passed on the stack.
	mov qword ptr [rsp + 20h], r13 ; Arg5: lpParameter (address of the allocated DLL path string).
	mov qword ptr [rsp + 28h], 0 ; Arg6: dwCreationFlags (0 = run immediately).
	mov qword ptr [rsp + 30h], 0 ; Arg7: lpThreadId (NULL = don't need the ID).
	call	CreateRemoteThread			      ; Returns handle to the new thread in RAX, or NULL on failure.

	; We don't usually need to interact with the remote thread further, so close its handle.
	mov		rcx, rax					; RCX = hHandle (the thread handle returned by CreateRemoteThread).
	call	CloseHandle					      ; Close the handle. (Check for NULL handle before calling ideally).

	; If we reached here, the remote thread was likely created successfully.
	mov		r14, 1					; Set the injection status flag (R14) to 1 (success).

; Cleanup routine: Close the handle to the target process.
exit_cleanup:
	mov		rcx, r12					; RCX = hHandle (process handle stored in R12).
	call	CloseHandle					      ; Close the handle. (Check for NULL handle before calling ideally).

; Final exit point for the procedure.
exit:
	mov		rax, r14					; Move the injection status flag (R14) into RAX (return value).
	; Standard x64 function epilogue.
	mov		rsp, rbp					; Deallocate local stack space.
	pop		rbp							; Restore base pointer.
	pop		r14							; Restore original R14 value.
	pop		r13							; Restore original R13 value.
	pop		r12							; Restore original R12 value.
	ret									; Return control to the caller.

inject_image endp


; ============================================================================
; main PROC
; Purpose: Main entry point of the injector program.
;          Coordinates finding the process and injecting the DLL.
;          Displays success or failure messages.
; Input:   None (standard program entry).
; Output:  None (exits program, returns 0 via RET implicitly if needed).
; Uses:    find_process, inject_image, MessageBoxA
; Clobbers: RAX, RCX, RDX, R8-R11 (as per x64 ABI)
; ============================================================================
main proc

	; Standard x64 function prologue.
	push	rbp
	mov		rbp, rsp

	; Allocate shadow space for function calls within main.
	sub rsp, 20h
	; Align stack.
	and		rsp, -10h

      call EnableDebugPrivilege ;

	; Call the find_process function to get the target process PID.
	call	find_process					; Returns PID or 0 in EAX.
	cmp		rax, 0					; Check if the PID is 0.
	je		process_not_found				; If 0, jump to the 'process_not_found' error handling.

	; Process found, PID is in RAX. Prepare to call inject_image.
	mov		rcx, rax					; Move PID from RAX into RCX (first argument for inject_image).
	

        ;For Testing

    IF FALSE
      call	get_proc_address			            ; Returns address in RAX.
	cmp		rax, 0					; Check if get_load_library failed (returned NULL).
	je		exit				            ; If failed, jump to cleanup.
      mov rcx, rax
      call Injected
      call GetTickCount
      call timeGetTime
      lea rcx, dPerfCounterResult
      call QueryPerformanceCounter
    ELSE
        ;Prod Call
        ;call	inject_image			      ; Call the DLL injection function. Returns 1 (success) or 0 (fail) in RAX.
        call inject_function                          ; Call the inject_function. Returns 1 (success) or 0 (fail) in RAX.
        cmp		rax, 0					; Check if injection failed (returned 0).
        je		injection_fail				; If 0, jump to the 'injection_fail' error handling.
    ENDIF

	; If inject_image returned non-zero (1), injection succeeded. Show success message.
	xor		rcx, rcx					; RCX = hWnd = NULL (no owner window).
	lea		rdx, msg_success				; RDX = lpText = pointer to success message string.
	lea		r8 , msg_title				; R8  = lpCaption = pointer to title string.
	mov		r9 , 40h					; R9  = uType = MB_OK | MB_ICONINFORMATION (0x40).
	call	MessageBoxA						; Display the message box.
	jmp		exit						; Jump to the end of the main function.

; Error handling block: Target process was not found.
process_not_found:
	xor		rcx, rcx					; RCX = hWnd = NULL.
	lea		rdx, msg_not_found			; RDX = lpText = pointer to "not found" message.
	lea		r8 , msg_title				; R8  = lpCaption = pointer to title string.
	; Note: 30h is MB_OK | MB_ICONWARNING. Could use MB_ICONERROR (10h) instead.
	mov		r9 , 30h					; R9  = uType = MB_OK | MB_ICONWARNING (0x30).
	call	MessageBoxA						; Display the message box.
	jmp		exit						; Jump to the end of the main function.

; Error handling block: DLL injection failed at some step.
injection_fail:
	xor		rcx, rcx					; RCX = hWnd = NULL.
	lea		rdx, msg_cant_inject			; RDX = lpText = pointer to "injection failed" message.
	lea		r8 , msg_title				; R8  = lpCaption = pointer to title string.
	mov		r9 , 30h					; R9  = uType = MB_OK | MB_ICONWARNING (0x30).
	call	MessageBoxA						; Display the message box.

; Exit point for the main function.
exit:
	; Standard x64 function epilogue.
	mov		rsp, rbp					; Deallocate local stack space.
	pop		rbp						; Restore the base pointer.
	ret								; Return (effectively exits the program).

main endp

; Directive indicating the end of the assembly source file.
end
