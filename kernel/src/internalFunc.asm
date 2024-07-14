public GetHookFunAsmSize, GetHookFunctionAddress, GetHookFunctionJmpDataOffset
.code

HookFuncAsmBegin:
	push rax
HookPoint:
	mov rax, 0123456789ABCDEFh
	xchg rax, qword ptr [rsp]
	ret
HookFuncAsmEnd:

HookFuncAsmSize equ (offset HookFuncAsmEnd - offset HookFuncAsmBegin)

GetHookFunAsmSize:
	mov rax, HookFuncAsmSize
	ret

GetHookFunctionAddress:
	lea rax, HookFuncAsmBegin
	ret

GetHookFunctionJmpDataOffset:
	lea rax, HookPoint
	add rax, 2
	push rbx
	lea rbx, HookFuncAsmBegin
	sub rax, rbx
	pop rbx
	ret

end