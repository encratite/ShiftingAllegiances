includelib ws2_32.lib
connect proto stdcall :dword, :dword, :dword

.data
	public connect_indirect 

	connect_indirect dq 0

.code
	public connect_patch
	public connect_original

	connect_patch:
		push rcx
		push rdx
		push r8
		mov rax, 0123456789abcdefh
		call rax
		pop r8
		pop rdx
		pop rcx
		ret
		nop

	connect_original:
		mov rax, rsp
		mov qword ptr [rax + 8], rbx
		mov qword ptr [rax + 10], rbp
		mov qword ptr [rax + 18], rsi
		push rdi
		push r12
		push r13
		push r14
		push rbx
		push rcx
		mov rax, connect
		mov rbx, connect_original
		mov rcx, connect_patch
		sub rbx, rcx
		add rax, rbx
		pop rcx
		pop rbx
		jmp rax
end