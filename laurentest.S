[BITS 32]
section .text
	;This section checks the eax, imm32
beginning:
	mov eax, 0x41424344
	
	;This section checks push imm32
	push 0x41424344
	
	;This section checks the r/m32, imm32
	mov edi, 0x41424344
	mov dword [eax], 0x41424344
	mov dword [eax + 0x4], 0x41424344
	mov dword [0x31323334], 0x41424344
	mov dword [eax + 0x31323334], 0x41424344
	
	;This section checks the r/m32, r32
	mov dword eax, ecx
	mov dword [eax], ecx
	mov dword [eax + 0x4], ecx
	mov dword [0x31323334], ecx
	mov dword [eax + 0x31323334], ecx
	
	;This section checks the r32, r/m32
	imul eax, dword ecx
	imul ecx, dword [eax]
	imul ecx, dword [eax + 0x4]
	imul ecx, dword [0x31323334]
	imul ecx, dword [eax + 0x31323334]
	
	;This section checks r/m32
	push dword eax
	push dword [eax]
	push dword [eax + 0x4]
	push dword [0x31323334]
	push dword [eax + 0x31323334]
	nop
	
	;This section checks r32
	push ecx
	push edi
	
	;This section checks imul r32, r/m32, imm32
	imul eax, dword ecx, 0x41424344
	imul ecx, dword [eax], 0x41424344
	imul ecx, dword [eax + 0x4], 0x41424344
	imul ecx, dword [0x31323334], 0x41424344
	imul ecx, dword [eax + 0x31323334], 0x41424344
	
	;This section checks returns
	retf
jump1:
	retn
	retf 0x4142
	retn 0x4142 
	
	;This section checks out
	out 0x04, eax
	
	;This section tries movsd
	movsd
	
	;This section tries shr, shr, shr
jump2:
	shr eax, 1
	shr dword [eax], 1
	shr dword [eax + 0x4], 1
	shr dword [eax + 0x31323334], 1
	shr dword [0x31323334], 1
	
	;This section tests repne
	repne cmpsd	
	;This section checks lea
label2:
	lea esi, [ecx]
	lea esi, [0x41424344]
	lea esi, [ecx + 0x04]
	lea esi, [ecx + 0x41424344]
	
	;This section checks clflush
	clflush [eax]
	clflush [eax + 0x8]
	clflush [eax + 0x31323334]
	clflush [0x11223344]
	
	;This section tries call
	call label
	call label2
	mov eax, ecx
label:
	push eax
	
	;This section is practicing some jumps
	jmp label
	jz jump1
	jnz jump2
	
	;This is just padding to get address greater than 1 byte
	imul eax, dword ecx, 0x41424344
	imul ecx, dword [eax], 0x41424344
	imul ecx, dword [eax + 0x4], 0x41424344
	imul ecx, dword [0x31323334], 0x41424344
	imul ecx, dword [eax + 0x31323334], 0x41424344
	imul eax, dword ecx, 0x41424344
	imul ecx, dword [eax], 0x41424344
	imul ecx, dword [eax + 0x4], 0x41424344
	imul ecx, dword [0x31323334], 0x41424344
	imul ecx, dword [eax + 0x31323334], 0x41424344
labelbig:
	imul eax, dword ecx, 0x41424344
	imul ecx, dword [eax], 0x41424344
	imul ecx, dword [eax + 0x4], 0x41424344
	imul ecx, dword [0x31323334], 0x41424344
	imul ecx, dword [eax + 0x31323334], 0x41424344
	jz beginning
	jmp beginning
	jnz beginning
	
	;Tests all the variations of calls and jmps r/m32
	call dword eax
	call dword [eax]
	call dword [eax + 0x4]
	call dword [0x31323334]
	call dword [eax + 0x31323334]
	
	jmp dword eax
	jmp dword [eax]
	jmp [byte eax + 0x4]
	jmp dword [0x31323334]
	jmp	dword [eax + 0x31323334]
	