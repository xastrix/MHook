option casemap:none

includelib kernel32.lib
includelib user32.lib

extern MH_Initialize   : proc
extern MH_Uninitialize : proc
extern MH_CreateHook  : proc
extern MH_EnableHook  : proc
extern MH_DisableHook : proc
extern MessageBoxA : proc
extern ExitProcess : proc

.data

    szTitle        DB "MHook Test", 0
    szTextOrig     DB "Target function returned original value", 0
    szTextHooked   DB "Target function was HOOKED successfully", 0
    fpTargetFunc   DQ 0

.code

TargetFunction proc frame

	sub rsp, 40
	.allocstack 40
	.endprolog

	mov eax, 100
	xor edx, edx
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
    
	add rsp, 40
	ret

TargetFunction endp

Detour_TargetFunction proc frame

    sub rsp, 40
    .allocstack 40
    .endprolog

    mov rax, fpTargetFunc
    call rax
    
    cmp eax, 100
    jne _bad_trampoline

    mov eax, 200
    jmp _exit

_bad_trampoline:
    mov eax, 999

_exit:
    add rsp, 40
    ret

Detour_TargetFunction endp

main proc frame

    sub rsp, 40
    .allocstack 40
    .endprolog

    call MH_Initialize
    test eax, eax
    jnz _exit_proc

    lea rcx, TargetFunction
    lea rdx, Detour_TargetFunction
    lea r8, fpTargetFunc
    call MH_CreateHook
    test eax, eax
    jnz _uninit

    lea rcx, TargetFunction
    call MH_EnableHook
    test eax, eax
    jnz _uninit

    call TargetFunction
    
    cmp eax, 200
    jne _show_orig_msg

    mov rcx, 0
    lea rdx, szTextHooked
    lea r8, szTitle
    mov r9d, 0h
    call MessageBoxA
    jmp _disable

_show_orig_msg:
    mov rcx, 0
    lea rdx, szTextOrig
    lea r8, szTitle
    mov r9d, 0h
    call MessageBoxA

_disable:
    lea rcx, TargetFunction
    call MH_DisableHook

_uninit:
    call MH_Uninitialize

_exit_proc:
    xor ecx, ecx
    call ExitProcess

main endp

end