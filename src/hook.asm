includelib kernel32.lib
includelib user32.lib

extern VirtualProtect : proc
extern EnterCriticalSection : proc
extern LeaveCriticalSection : proc
extern InitializeCriticalSection : proc
extern DeleteCriticalSection     : proc
extern VirtualAlloc : proc
extern VirtualFree  : proc
extern hde64_disasm : proc

hde64s struct 8
    len_              db 0
    p_rep             db 0
    p_lock            db 0
    p_seg             db 0
    p_66              db 0
    p_67              db 0
    p_rex             db 0
    rex               db 0
    rex_w             db 0
    rex_r             db 0
    rex_x             db 0
    rex_b             db 0
    opcode            db 0
    opcode2           db 0
    modrm             db 0
    modrm_mod         db 0
    modrm_reg         db 0
    modrm_rm          db 0
    sib               db 0
    sib_scale         db 0
    sib_index         db 0
    sib_base          db 0
    imm8              db 0
    imm16             dw 0
    imm32             dd 0
    imm64             dq 0
    disp8             db 0
    disp16            dw 0
    disp32            dd 0
    flags             dd 0
hde64s ends

HOOK_ENTRY struct 8
    target            dq 0
    detour            dq 0
    trampoline        dq 0
    backup            db 24 DUP(0)
    patch_len         db 0
    enabled           db 0
    queue_enable      db 0
    padding           db 5 DUP(0) 
HOOK_ENTRY ends

.data

	MAX_HOOKS          equ 64

    g_critical_section db 40 DUP(0)
	g_hooks            HOOK_ENTRY MAX_HOOKS DUP(<>)
	g_hooks_count      dd 0
    g_buf              dq 0
    g_buf_offset       dd 0

.code

FindHookEntry proc

    xor eax, eax
    mov edx, g_hooks_count
    test edx, edx
    jz _not_found

	lea r8, g_hooks

_loop_start:
    cmp rcx, qword ptr [r8].HOOK_ENTRY.target
    je _found

    add r8, sizeof HOOK_ENTRY
    dec edx
    jnz _loop_start

    jmp _not_found

_found:
    mov rax, r8

_not_found:
    ret

FindHookEntry endp

LockLibrary proc frame

    sub rsp, 40
    .allocstack 40
    .endprolog

    lea rcx, g_critical_section
    call EnterCriticalSection

    add rsp, 40
    ret

LockLibrary endp

UnlockLibrary proc frame

    sub rsp, 40
    .allocstack 40
    .endprolog

    lea rcx, g_critical_section
    call LeaveCriticalSection

    add rsp, 40
    ret

UnlockLibrary endp

MH_CreateHook proc frame

    sub rsp, 128
    .allocstack 128
    mov [rsp + 32], r12
    mov [rsp + 40], r13
    mov [rsp + 48], r14
    mov [rsp + 56], rbx
    mov [rsp + 64], rsi
    mov [rsp + 72], rdi
    .endprolog

    mov r12, rcx                ; r12 = pTarget
    mov r13, rdx                ; r13 = pDetour
    mov r14, r8                 ; r14 = ppOriginal

    mov rax, qword ptr [g_critical_section]
    test rax, rax
    jz _err_not_init

    call LockLibrary

    mov rcx, r12
    call FindHookEntry
    test rax, rax
    jnz _err_already_created

    mov eax, g_hooks_count
    cmp eax, MAX_HOOKS
    jae _err_no_memory

    mov rax, g_buf
    test rax, rax
    jnz _buffer_exists

    xor ecx, ecx                ; lpAddress = NULL
    mov rdx, 4096               ; dwSize = 4096
    mov r8d, 3000h              ; flAllocationType = MEM_COMMIT | MEM_RESERVE
    mov r9d, 40h                ; flProtect = PAGE_EXECUTE_READWRITE
    call VirtualAlloc
    test rax, rax
    jz _err_no_memory
    mov g_buf, rax
    mov g_buf_offset, 0

_buffer_exists:
    mov eax, g_buf_offset
    add eax, 40
    cmp eax, 4096
    ja _err_no_memory

    mov ecx, g_hooks_count
    imul ecx, ecx, sizeof HOOK_ENTRY
    lea rbx, g_hooks
    add rbx, rcx

    mov qword ptr [rbx].HOOK_ENTRY.target, r12
    mov qword ptr [rbx].HOOK_ENTRY.detour, r13
    mov byte ptr [rbx].HOOK_ENTRY.enabled, 0
    mov byte ptr [rbx].HOOK_ENTRY.queue_enable, 0

    xor esi, esi
    mov rdi, r12
    
_disasm_loop:
    cmp esi, 14
    jae _disasm_done

    mov rcx, rdi
    lea rdx, [rsp + 80]
    call hde64_disasm
    
    movzx eax, byte ptr [rsp + 80]
    test eax, eax
    jz _err_disasm_failed

    add esi, eax
    add rdi, rax
    jmp _disasm_loop

_disasm_done:
    cmp esi, 24
    ja _err_no_memory
    
    mov byte ptr [rbx].HOOK_ENTRY.patch_len, sil

    mov rax, g_buf
    mov edx, g_buf_offset
    add rax, rdx
    mov qword ptr [rbx].HOOK_ENTRY.trampoline, rax
    
    add edx, 40
    mov g_buf_offset, edx

    cld
    mov rdi, qword ptr [rbx].HOOK_ENTRY.trampoline
    mov rsi, r12
    movzx ecx, byte ptr [rbx].HOOK_ENTRY.patch_len
    rep movsb

    mov word ptr [rdi], 25FFh
    mov dword ptr [rdi + 2], 0
    mov rax, r12
    movzx ecx, byte ptr [rbx].HOOK_ENTRY.patch_len
    add rax, rcx
    mov qword ptr [rdi + 6], rax

    mov rax, qword ptr [rbx].HOOK_ENTRY.trampoline
    test r14, r14
    jz _skip_original_ptr
    mov qword ptr [r14], rax

_skip_original_ptr:
    inc g_hooks_count
    call UnlockLibrary
    xor eax, eax
    jmp _exit

_err_disasm_failed:
    call UnlockLibrary
    mov eax, 11 ; MH_ERROR_DISASM_FAILED = 11
    jmp _exit

_err_not_init:
    mov eax, 3 ; MH_ERROR_NOT_INITIALIZED = 3
    jmp _exit

_err_already_created:
    call UnlockLibrary
    mov eax, 4 ; MH_ERROR_ALREADY_CREATED = 4
    jmp _exit

_err_no_memory:
    call UnlockLibrary
    mov eax, 9 ; MH_ERROR_MEMORY_ALLOC = 9
    jmp _exit

_exit:
    mov r12, [rsp + 32]
    mov r13, [rsp + 40]
    mov r14, [rsp + 48]
    mov rbx, [rsp + 56]
    mov rsi, [rsp + 64]
    mov rdi, [rsp + 72]
    add rsp, 128
    ret

MH_CreateHook endp

MH_EnableHook proc frame

    sub rsp, 72
    .allocstack 72
    mov [rsp + 32], r12
    mov [rsp + 40], r13
    mov [rsp + 48], rsi
    mov [rsp + 56], rdi
    .endprolog

    mov r12, rcx
    mov rax, qword ptr [g_critical_section]
    test rax, rax
    jz _err_not_init

    call LockLibrary

    mov rcx, r12
    call FindHookEntry
    test rax, rax
    jz _err_not_created
    
    mov r13, rax

    cmp byte ptr [r13].HOOK_ENTRY.enabled, 1
    je _err_already_enabled

    mov rcx, qword ptr [r13].HOOK_ENTRY.target
    movzx rdx, byte ptr [r13].HOOK_ENTRY.patch_len
    mov r8d, 40h
    lea r9, [rsp + 64]
    call VirtualProtect
    test rax, rax
    jz _err_memory_protect

    cld
    mov rsi, qword ptr [r13].HOOK_ENTRY.target
    lea rdi, [r13].HOOK_ENTRY.backup
    movzx ecx, byte ptr [r13].HOOK_ENTRY.patch_len
    rep movsb

    mov rdi, qword ptr [r13].HOOK_ENTRY.target
    mov word ptr [rdi], 25FFh
    mov dword ptr [rdi + 2], 0
    mov rax, qword ptr [r13].HOOK_ENTRY.detour
    mov qword ptr [rdi + 6], rax

    movzx eax, byte ptr [r13].HOOK_ENTRY.patch_len
    sub eax, 14
    jz _skip_nop_fill
    mov ecx, eax
    add rdi, 14
    mov al, 90h
    rep stosb

_skip_nop_fill:
    mov rcx, qword ptr [r13].HOOK_ENTRY.target
    movzx rdx, byte ptr [r13].HOOK_ENTRY.patch_len
    mov r8d, dword ptr [rsp + 64]
    lea r9, [rsp + 64]
    call VirtualProtect

    mov byte ptr [r13].HOOK_ENTRY.enabled, 1

    call UnlockLibrary
    xor eax, eax
    jmp _exit

_err_not_init:
    mov eax, 3 ; MH_ERROR_NOT_INITIALIZED = 3
    jmp _exit

_err_not_created:
    call UnlockLibrary
    mov eax, 5 ; MH_ERROR_NOT_CREATED = 5
    jmp _exit

_err_already_enabled:
    call UnlockLibrary
    mov eax, 6 ; MH_ERROR_ENABLED = 6
    jmp _exit

_err_memory_protect:
    call UnlockLibrary
    mov eax, 10 ; MH_ERROR_MEMORY_PROTECT = 10
    jmp _exit

_exit:
    mov r12, [rsp + 32]
    mov r13, [rsp + 40]
    mov rsi, [rsp + 48]
    mov rdi, [rsp + 56]
    add rsp, 72
    ret

MH_EnableHook endp

MH_DisableHook proc frame

    sub rsp, 72
    .allocstack 72
    mov [rsp + 32], r12
    mov [rsp + 40], r13
    mov [rsp + 48], rsi
    mov [rsp + 56], rdi
    .endprolog

    mov r12, rcx
    mov rax, qword ptr [g_critical_section]
    test rax, rax
    jz _err_not_init

    call LockLibrary

    mov rcx, r12
    call FindHookEntry
    test rax, rax
    jz _err_not_created
    
    mov r13, rax

    cmp byte ptr [r13].HOOK_ENTRY.enabled, 0
    je _err_already_disabled

    mov rcx, qword ptr [r13].HOOK_ENTRY.target
    movzx rdx, byte ptr [r13].HOOK_ENTRY.patch_len
    mov r8d, 40h
    lea r9, [rsp + 64]
    call VirtualProtect
    test rax, rax
    jz _err_memory_protect

    cld
    mov rdi, qword ptr [r13].HOOK_ENTRY.target
    lea rsi, [r13].HOOK_ENTRY.backup
    movzx ecx, byte ptr [r13].HOOK_ENTRY.patch_len
    rep movsb

    mov rcx, qword ptr [r13].HOOK_ENTRY.target
    movzx rdx, byte ptr [r13].HOOK_ENTRY.patch_len
    mov r8d, dword ptr [rsp + 64]
    lea r9, [rsp + 64]
    call VirtualProtect

    mov byte ptr [r13].HOOK_ENTRY.enabled, 0

    call UnlockLibrary
    xor eax, eax
    jmp _exit

_err_not_init:
    mov eax, 3 ; MH_ERROR_NOT_INITIALIZED = 3
    jmp _exit

_err_not_created:
    call UnlockLibrary
    mov eax, 5 ; MH_ERROR_NOT_CREATED = 5
    jmp _exit

_err_already_disabled:
    call UnlockLibrary
    mov eax, 7 ; MH_ERROR_DISABLED = 7
    jmp _exit

_err_memory_protect:
    call UnlockLibrary
    mov eax, 10 ; MH_ERROR_MEMORY_PROTECT = 10
    jmp _exit

_exit:
    mov r12, [rsp + 32]
    mov r13, [rsp + 40]
    mov rsi, [rsp + 48]
    mov rdi, [rsp + 56]
    add rsp, 72
    ret

MH_DisableHook endp

MH_Initialize proc frame

	sub rsp, 40
	.allocstack 40
	.endprolog

	mov rax, qword ptr [g_critical_section]
	test rax, rax
	jnz _already_initialized

    lea rcx, g_critical_section
    call InitializeCriticalSection

    xor eax, eax
    jmp _exit

_already_initialized:
    mov eax, 1 ; MH_ERROR_ALREADY_INITIALIZED = 1

_exit:
    add rsp, 40
    ret

MH_Initialize endp

MH_Uninitialize proc frame

    sub rsp, 48
    .allocstack 48
    mov [rsp + 32], r12
    mov [rsp + 40], r13
    .endprolog

    mov rax, qword ptr [g_critical_section]
    test rax, rax
    jz _not_init

    call LockLibrary

    mov edx, g_hooks_count
    test edx, edx
    jz _skip_disable_all

    lea r12, g_hooks

_disable_loop:
    cmp byte ptr [r12].HOOK_ENTRY.enabled, 1
    jne _next_hook

    mov r13d, edx

    mov rcx, qword ptr [r12].HOOK_ENTRY.target
    call MH_DisableHook

    mov edx, r13d

_next_hook:
    add r12, sizeof HOOK_ENTRY
    dec edx
    jnz _disable_loop

_skip_disable_all:
    mov g_hooks_count, 0

    mov rcx, g_buf
    test rcx, rcx
    jz _skip_free_buffer
    xor rdx, rdx
    mov r8d, 8000h
    call VirtualFree
    mov g_buf, 0
    mov g_buf_offset, 0

_skip_free_buffer:
    call UnlockLibrary

    lea rcx, g_critical_section
    call DeleteCriticalSection

    mov qword ptr [g_critical_section], 0

    xor eax, eax
    jmp _exit

_not_init:
    mov eax, 3 ; MH_ERROR_NOT_INITIALIZED = 3

_exit:
    mov r12, [rsp + 32]
    mov r13, [rsp + 40]
    add rsp, 48
    ret

MH_Uninitialize endp

end