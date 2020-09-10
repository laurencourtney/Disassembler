import argparse
import binascii
import logging
import sys

logging.basicConfig()
log = logging.getLogger('disasm')
log.setLevel(logging.ERROR)     # enable CRITICAL and ERROR messages by default


def format_line(hexbytes, text):
    '''
    hexbytes: A bytearray of the instructions
    text: A string, the opcode
    This function takes in the instructions and opcode and returns
    a string.  Format will be:
    31c0                    mov eax, eax (not the correct instruction)
    '''
    hexstr = ''.join(['{:02x}'.format(x) for x in hexbytes])
    return '{:<24}{}'.format(hexstr, text)


def format_unknown(hexbyte):
    '''
    hexbyte: A single byte for an unknown instruction
    This functions takes in an unknown instruction and returns
    a string. Format will be:
    31                      db 0x31
    '''
    return format_line([hexbyte], 'db 0x{:02x}'.format(hexbyte))


def format_label(address):
    '''
    address: What is the type?
    This function returns the string label for a jump's address.
    '''
    return 'offset_{:08x}h:\n'.format(address)

def format_little_endian(hexbytes) :
    '''
    hexbytes: A bytearray - usually an immediate or displacement. 
    This function will convert it into a little endian string. 
    '''
    imm = '0x' + ''.join(['{:02x}'.format(x) for x in hexbytes[::-1]])
    return imm

def format_instr(hexbytes, mnemonic, op1=None, op2=None, op3=None):
    '''
    hexbytes: A bytearray of instructions
    mnemonic: A string, the opcode
    op1: A string, optional operand
    op2: A string, optional operand
    op3 A string, optional operand
    This function takes in the instruction and the text of the assembly
    opcode and operands to format the return string that will be printed.
    Format will be:
    31c0                    mov eax, eax (not the correct instruction)
    '''
    line = format_line(hexbytes, mnemonic)
    if op1:
        line = '{} {}'.format(line, op1)
        if op2:
            line = '{}, {}'.format(line, op2)
            if op3:
                line = '{}, {}'.format(line, op3)

    return line

def additive_check(instr, byte):
    '''
    instr: A bytearray of length 1 with the byte to match
    byte: A bytes object of the opcode (one byte long)
    This function does a quick check for those instructions where
    the opcode is additive, i.e. mov eax, imm32 -- 0xb8+rd id. It 
    checks if the given instruction is within one byte of the opcode
    and returns a string indicating the register that corresponds 
    to that offest if true and None otherwise. 
    '''
    instruction = int.from_bytes(instr, "big")
    opcode = int.from_bytes(byte, "big")
    net = instruction - opcode
    if 0 <= net < 8 :
        return parse_register(net)
    return None


def parse_modrm(byte):
    '''
    byte: An integer that represents the single MODR/m byte
    Returns the three parts of the MODR/M byte as integers:
    [00 000 000] = [MOD REG RM]
    '''
    mod = byte >> 6 # shift over by 6 for just the first 2 bits
    reg = (byte >> 3) & 0x7 #shift over by 3 and keep 0x7 = 0111 3 bits
    rm = byte & 0x7 #keep only the last 3 bits
    return mod, reg, rm

def parse_register(reg):
    '''
    reg: An integer representing an x86 register - between 0 and 7
    Returns the register name as a string
    '''
    if reg == 0 :
        return 'eax'
    if reg == 1 :
        return 'ecx'
    if reg == 2 :
        return 'edx'
    if reg == 3 :
        return 'ebx'
    if reg == 4 :
        return 'esp'
    if reg == 5 :
        return 'ebp'
    if reg == 6 :
        return 'esi'
    if reg == 7 :
        return 'edi'
    return None

def rm32immediate(instr, mod, reg, rm, op):
    '''
    instr: A bytearray with the instructions
    mod: An integer representing the mod bits
    reg: An integer representing the reg bits
    rm: An interger representing the rm bits
    op:  A string indicated the instruction/mnemonic (i.e. 'add')
    This function parses out the different modes for instructions with
    format 'add r/m32 imm32'. It returns assembly language strings. 
    '''
    #first check for shorter instructions with just an immediate
    if 6 == len(instr) :
        if mod == 0 and rm != 5:
            register = parse_register(rm)
            immediate = format_little_endian(instr[2:])
            log.info('Found {} r/m32, imm32'.format(op))
            return format_instr(instr, op, '[{}]'.format(register), immediate)

        if mod == 3 :
            register = parse_register(rm)
            immediate = format_little_endian(instr[2:])
            log.info('Found {} r/m32, imm32'.format(op))
            return format_instr(instr, op, register, immediate)
            
    #check for instructions with an immediate and an 8 bit displacent
    if 7 == len(instr) :
        if mod == 1 :
            register = parse_register(rm)
            disp = '0x{:02x}'.format(instr[2])
            immediate = format_little_endian(instr[3:])
            log.info('Found {} r/m32, imm32'.format(op))
            return format_instr(instr, op, '[{} + {}]'.format(register, disp), immediate)

    #now check for longer instructions with a 32 bit displacement
    if 10 == len(instr) :
        if mod == 0 and rm == 5 :
            disp = format_little_endian(instr[2:6])
            immediate = format_little_endian(instr[6:10])
            log.info('Found {} r/m32, imm32'.format(op))
            return format_instr(instr, op, '[{}]'.format(disp), immediate)
        if mod == 2 :
            register = parse_register(rm)
            disp = format_little_endian(instr[2:6])
            immediate = format_little_endian(instr[6:10])
            log.info('Found {} r/m32, imm32'.format(op))
            return format_instr(instr, op, '[{} + {}]'.format(register, disp), immediate)
    
    return None

def rm32r32(instr, mod, reg, rm, op) :
    '''
    instr: A bytearray with the instructions
    mod: An integer representing the mod bits
    reg: An integer representing the reg bits
    rm: An interger representing the rm bits
    op:  A string indicated the instruction/mnemonic (i.e. 'add')
    This function parses out the different modes for instructions with 
    format 'add r/m32, r32'. It returns assembly language strings.
    '''
    #first check for shorter instructions with just a register
    if 2 == len(instr) :
        if mod == 0 and rm != 5:
            reg_str = parse_register(reg)
            rm_str = parse_register(rm)
            log.info('Found {} r/m32, r32'.format(op))
            return format_instr(instr, op, '[{}]'.format(rm_str), reg_str)

        if mod == 3 :
            reg_str = parse_register(reg)
            rm_str = parse_register(rm)
            log.info('Found {} r/m32, r32'.format(op))
            return format_instr(instr, op, rm_str, reg_str)
            
    #check for instructions with an 8 bit displacent
    if 3 == len(instr) :
        if mod == 1 :
            reg_str = parse_register(reg)
            rm_str = parse_register(rm)
            disp = '0x{:02x}'.format(instr[2])
            log.info('Found {} r/m32, r32'.format(op))
            return format_instr(instr, op, '[{} + {}]'.format(rm_str, disp), reg_str)
            
    #now check for longer instructions with a 32 bit displacement
    if 6 == len(instr) :
        if mod == 0 and rm == 5 :
            disp = format_little_endian(instr[2:6])
            reg_str = parse_register(reg)
            log.info('Found {} r/m32, r32'.format(op))
            return format_instr(instr, op, '[{}]'.format(disp), reg_str)

        if mod == 2 :
            reg_str = parse_register(reg)
            disp = format_little_endian(instr[2:6])
            rm_str = parse_register(rm)
            log.info('Found {} r/m32, r32'.format(op))
            return format_instr(instr, op, '[{} + {}]'.format(rm_str, disp), reg_str)

def r32rm32(instr, mod, reg, rm, op) :
    '''
    instr: A bytearray with the instructions
    mod: An integer representing the mod bits
    reg: An integer representing the reg bits
    rm: An interger representing the rm bits
    op:  A string indicated the instruction/mnemonic (i.e. 'add')
    This function parses out the different modes for instructions with 
    format 'add r32, r/m32'. It returns assembly language strings.
    '''
    #first check for shorter instructions with just a register
    if 2 == len(instr) :
        if mod == 0 and rm != 5:
            reg_str = parse_register(reg)
            rm_str = parse_register(rm)
            log.info('Found {} r32, r/m32'.format(op))
            return format_instr(instr, op, reg_str, '[{}]'.format(rm_str))

        if mod == 3 :
            reg_str = parse_register(reg)
            rm_str = parse_register(rm)
            log.info('Found {} r32, r/m32'.format(op))
            return format_instr(instr, op, reg_str, rm_str)
            
    #check for instructions with an 8 bit displacent
    if 3 == len(instr) :
        if mod == 1 :
            reg_str = parse_register(reg)
            rm_str = parse_register(rm)
            disp = '0x{:02x}'.format(instr[2])
            log.info('Found {} r32, r/m32'.format(op))
            return format_instr(instr, op, reg_str, '[{} + {}]'.format(rm_str, disp))
            
    #now check for longer instructions with a 32 bit displacement
    if 6 == len(instr) :
        if mod == 0 and rm == 5 :
            disp = format_little_endian(instr[2:6])
            reg_str = parse_register(reg)
            log.info('Found {} r32, r/m32'.format(op))
            return format_instr(instr, op, reg_str, '[{}]'.format(disp))

        if mod == 2 :
            reg_str = parse_register(reg)
            disp = format_little_endian(instr[2:6])
            rm_str = parse_register(rm)
            log.info('Found {} r32, r/m32'.format(op))
            return format_instr(instr, op, reg_str, '[{} + {}]'.format(rm_str, disp))

def rm32(instr, mod, rm, op) :
    '''
    instr: A bytearray with the instructions
    mod: An integer representing the mod bits
    rm: An interger representing the rm bits
    op:  A string indicated the instruction/mnemonic (i.e. 'add')
    This function parses out the different modes for instructions with 
    format 'pop r/m32'. It returns assembly language strings.
    '''
    #first check for shorter instructions with just a register
    if 2 == len(instr) :
        if mod == 0 and rm != 5:
            rm_str = parse_register(rm)
            log.info('Found {} r/m32'.format(op))
            return format_instr(instr, op, '[{}]'.format(rm_str))

        if mod == 3 :
            rm_str = parse_register(rm)
            log.info('Found {} r/m32'.format(op))
            return format_instr(instr, op, rm_str)
            
    #check for instructions with an 8 bit displacent
    if 3 == len(instr) :
        if mod == 1 :
            rm_str = parse_register(rm)
            disp = '0x{:02x}'.format(instr[2])
            log.info('Found {} r/m32'.format(op))
            return format_instr(instr, op, '[{} + {}]'.format(rm_str, disp))
            
    #now check for longer instructions with a 32 bit displacement
    if 6 == len(instr) :
        if mod == 0 and rm == 5 :
            disp = format_little_endian(instr[2:6])
            log.info('Found {} r/m32'.format(op))
            return format_instr(instr, op, '[{}]'.format(disp))

        if mod == 2 :
            disp = format_little_endian(instr[2:6])
            rm_str = parse_register(rm)
            log.info('Found {} r/m32'.format(op))
            return format_instr(instr, op, '[{} + {}]'.format(rm_str, disp))


def parse_int3(instr):
    '''
    instr: A bytearray for the instruction
    This function determines if the instruction is int3
    and formats a line to be printed:
    cc                      int3
    '''
    if 1 == len(instr) and b'\xcc' == instr:
        log.info('Found int3!')
        return format_line(instr, 'int3')
    return None


def parse_cpuid(instr):
    '''
    instr: A bytearray for the instruction
    This function determines if the instruction is cpuid
    and formats a line to be printed:
    0f31                    cpuid
    '''
    if 2 == len(instr) and b'\x0f\x31' == instr:
        log.info('Found cpuid!')
        return format_line(instr, 'cpuid')
    return None

'''
# This is not really "mov eax, eax", only an example of a formatted instruction
def parse_fake_mov(instr):
    if 2 == len(instr) and b'\xff\xc0' == instr:
        log.info('Found fake mov!')
        return format_instr(instr, 'mov', 'eax', 'eax')
'''

def parse_add(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is add
    and formats a line to be printed.
    '''
    #add eax, imm32 --- 0x05 id, no MODR/M
    if 5 == len(instr) and b'\x05' == instr[0:1]:
        log.info("Found add eax, immediate")
        immediate = format_little_endian(instr[1:])
        return format_instr(instr, 'add', 'eax', immediate)
    
    #add r/m32, imm32 --- 0x81 /0 id
    if b'\x81' == instr[0:1] and len(instr) > 2:
        mod, reg, rm = parse_modrm(instr[1])
        if reg == 0 :
            result = rm32immediate(instr, mod, reg, rm, 'add')
            if result :
                return result
    
    #add r/m32, r32 --- 0x01 /r
    if b'\x01' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        result = rm32r32(instr, mod, reg, rm, 'add')
        if result :
            return result

    #add r32, r/m32 --- 0x03 /r
    if b'\x03' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        result = r32rm32(instr, mod, reg, rm, 'add')
        if result :
            return result

    return None

def parse_and(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is and
    and formats a line to be printed.
    '''
    #and eax, imm32 --- 0x25 id, no MODR/M
    if 5 == len(instr) and b'\x25' == instr[0:1]:
        log.info("Found and eax, immediate")
        immediate = format_little_endian(instr[1:])
        return format_instr(instr, 'and', 'eax', immediate)

    #and r/m32, imm32 --- 0x81 /4 id
    if b'\x81' == instr[0:1] and len(instr) > 2:
        mod, reg, rm = parse_modrm(instr[1])
        if reg == 4 :
            result = rm32immediate(instr, mod, reg, rm, 'and')
            if result :
                return result

    #and r/m32, r32 --- 0x21 /r
    if b'\x21' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        result = rm32r32(instr, mod, reg, rm, 'and')
        if result :
            return result

    #and r32, r/m32 --- 0x23 /r
    if b'\x23' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        result = r32rm32(instr, mod, reg, rm, 'and')
        if result :
            return result

    return None

def parse_call(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is call
    and formats a line to be printed.
    '''
    #call rel32 --- 0xe8 cd (note, treat cd as id)

    #call r/m32 --- 0xff /2
    return None

def parse_clflush(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is cflush
    and formats a line to be printed.
    '''
    #clflush m8 --- 0x0f 0xae /7 note: addressing mode 11 is illegal
    return None

def parse_cmp(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is cmp
    and formats a line to be printed.
    '''
    #cmp eax, imm32 --- 0x3d id, no MODR/M
    if 5 == len(instr) and b'\x3d' == instr[0:1]:
        log.info("Found cmp eax, immediate")
        immediate = format_little_endian(instr[1:])
        return format_instr(instr, 'cmp', 'eax', immediate)

    #cmp r/m32, imm32 --- 0x81 /7 id
    if b'\x81' == instr[0:1] and len(instr) > 2:
        mod, reg, rm = parse_modrm(instr[1])
        if reg == 7 :
            result = rm32immediate(instr, mod, reg, rm, 'cmp')
            if result :
                return result
    
    #cmp r/m32, r32 --- 0x39 /r
    if b'\x39' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        result = rm32r32(instr, mod, reg, rm, 'cmp')
        if result :
            return result

    #cmp r32, r/m32 --- 0x3b /r
    if b'\x3b' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        result = r32rm32(instr, mod, reg, rm, 'cmp')
        if result :
            return result

    return None

def parse_dec(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is dec
    and formats a line to be printed.
    '''
    #dec r/m32 --- 0xff /1
    if b'\xff' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        if reg == 1 :
            result = rm32(instr, mod, rm, 'dec')
            if result :
                return result

    #dec r32 --- 0x48 + rd
    if 1 == len(instr) :
        register = additive_check(instr[0:1], b'\x48')
        if register != None :
            log.info("Found dec r32")
            return format_instr(instr, 'dec', register)

    return None

def parse_idiv(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is idiv
    and formats a line to be printed.
    '''
    #idiv r/m32 --- 0xf7 /7
    if b'\xf7' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        if reg == 7 :
            result = rm32(instr, mod, rm, 'idiv')
            if result :
                return result

    return None

def parse_imul(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is imul
    and formats a line to be printed.
    '''
    #imul r/m32 --- 0xf7 /5
    if b'\xf7' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        if reg == 5 :
            result = rm32(instr, mod, rm, 'imul')
            if result :
                return result

    #imul r32, r/m32 --- 0x0f 0xaf /r
    if len(instr) > 2 :
        if b'\x0f' == instr[0:1] and b'\xaf' == instr[1:2]:
            mod, reg, rm = parse_modrm(instr[2])
            result = r32rm32(instr[1:], mod, reg, rm, 'imul')
            if result :
                #TODO formatting hack to account for the longer opcode, rethink
                return '0f' + result[:20] + result[22:]

    #imul r32, r/m32, imm32 --- 0x69 /r id
    if b'\x69' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        result = r32rm32(instr[:-4], mod, reg, rm, 'imul')
        immediate = format_little_endian(instr[-4:])
        if result :
            #TODO formatting hack to account for the third opcode, revisit
            imm_part = ''.join(['{:02x}'.format(x) for x in instr[-4:]])
            return result[:len(instr)*2-8] + imm_part + result[len(instr)*2:] + ", " + immediate

    return None

def parse_inc(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is inc
    and formats a line to be printed.
    '''
    #inc r/m32 --- 0xff /0
    if b'\xff' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        if reg == 0 :
            result = rm32(instr, mod, rm, 'inc')
            if result :
                return result

    #inc r32, --- 0x40 + rd
    if 1 == len(instr) :
        register = additive_check(instr[0:1], b'\x40')
        if register != None :
            log.info("Found inc r32")
            return format_instr(instr, 'inc', register)

    return None

def parse_jmp(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is jmp
    and formats a line to be printed.
    '''
    #jmp rel8 --- 0xeb cb (note: treat cb as ib)

    #jmp rel32 --- 0xe9 cd (Note: treat cd as id)

    #jmp r/m32 --- 0xff /4 

    return None

def parse_jzjnz(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is jz/jnz
    and formats a line to be printed.
    '''
    #jz rel8 --- 0x74 cb (note: treat cb as ib)

    #jz rel32 --- 0x0f 0x84 cd cd (Note: treat cd as id)

    #jnz rel8 --- 0x75 cb (note: treat cb as ib)
    
    #jnz rel32 --- 0x0f 0x85 cd (Note: treat cd as id)

    return None

def parse_lea(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is lea
    and formats a line to be printed.
    '''
    #lea r32, m --- 0x8d /r (note: addressing mode 11 is illegal)

    return None

def parse_mov(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is mov
    and formats a line to be printed.
    '''
    #mov eax, imm32 --- 0xB8 + rd id, no MODR/M
    if 5 == len(instr) :
        register = additive_check(instr[0:1], b'\xb8')
        if register != None :
            log.info("Found mov r32, immediate")
            immediate = format_little_endian(instr[1:])
            return format_instr(instr, 'mov', register, immediate)

    #mov r/m32, imm32 --- 0xc7 /0 id
    if b'\xc7' == instr[0:1] and len(instr) > 2:
        mod, reg, rm = parse_modrm(instr[1])
        if reg == 0 :
            result = rm32immediate(instr, mod, reg, rm, 'mov')
            if result :
                return result

    #mov r/m32, r32 --- 0x89 /r
    if b'\x89' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        result = rm32r32(instr, mod, reg, rm, 'mov')
        if result :
            return result

    #mov r32, r/m32 --- 0x8b /r
    if b'\x8b' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        result = r32rm32(instr, mod, reg, rm, 'mov')
        if result :
            return result

    return None


def parse_movsd(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is movsd
    and formats a line to be printed.
    '''
    #movsd --- 0xa5
    if b'\xa5' == instr[0:1] :
        log.info('Found movsd')
        return format_instr(instr, 'movsd')

    return None

def parse_mul(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is mul
    and formats a line to be printed.
    '''
    #mul r/m32 --- 0xf7 /4
    if b'\xf7' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        if reg == 4 :
            result = rm32(instr, mod, rm, 'mul')
            if result :
                return result

    return None

def parse_neg(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is neg
    and formats a line to be printed.
    '''
    #neg r/m32 --- 0xf7 /3
    if b'\xf7' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        if reg == 3 :
            result = rm32(instr, mod, rm, 'neg')
            if result :
                return result

    return None

def parse_nop(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is nop
    and formats a line to be printed.
    '''
    #nop --- 0x90
    if b'\x90' == instr[0:1] :
        log.info('Found nop')
        return format_instr(instr, 'nop')

    return None

def parse_not(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is not
    and formats a line to be printed.
    '''
    #not r/m32 --- 0xf7 /2
    if b'\xf7' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        if reg == 2 :
            result = rm32(instr, mod, rm, 'not')
            if result :
                return result

    return None

def parse_or(instr) :
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is or
    and formats a line to be printed.
    '''
    #or eax, imm32 --- 0x0d id, no MODR/M
    if 5 == len(instr) and b'\x0d' == instr[0:1]:
        log.info("Found or eax, immediate")
        immediate = format_little_endian(instr[1:])
        return format_instr(instr, 'or', 'eax', immediate)

    #or r/m32, imm32 --- 0x81 /1 id
    if b'\x81' == instr[0:1] and len(instr) > 2:
        mod, reg, rm = parse_modrm(instr[1])
        if reg == 1 :
            result = rm32immediate(instr, mod, reg, rm, 'or')
            if result :
                return result

    #or r/m32, r32 --- 0x09 /r
    if b'\x09' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        result = rm32r32(instr, mod, reg, rm, 'or')
        if result :
            return result

    #or r32, r/m32 --- 0x0b /r
    if b'\x0b' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        result = r32rm32(instr, mod, reg, rm, 'or')
        if result :
            return result

    return None

def parse_out(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is out
    and formats a line to be printed.
    '''
    #out imm8, eax --- 0xe7 ib
    if b'\xe7' == instr[0:1] and len(instr) == 2 :
        log.info('Found out imm8, eax')
        imm = format_little_endian(instr[1:2])
        return format_instr(instr, 'out', imm, 'eax')

    return None

def parse_pop(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is pop
    and formats a line to be printed.
    '''
    #pop r/m32 --- 0x8f /0
    if b'\x8f' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        if reg == 0 :
            result = rm32(instr, mod, rm, 'pop')
            if result :
                return result

    #pop r32 --- 0x58 + rd
    if 1 == len(instr) :
        register = additive_check(instr[0:1], b'\x58')
        if register != None :
            log.info("Found pop r32")
            return format_instr(instr, 'pop', register)

    return None

def parse_push(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is push
    and formats a line to be printed.
    '''
    #push r/m32 --- 0xff /6
    if b'\xff' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        if reg == 6 :
            result = rm32(instr, mod, rm, 'push')
            if result :
                return result

    #push r32 --- 0x50 + rd
    if 1 == len(instr) :
        register = additive_check(instr[0:1], b'\x50')
        if register != None :
            log.info("Found push r32")
            return format_instr(instr, 'push', register)

    #push imm32 --- 0x68 id
    if 5 == len(instr) and b'\x68' == instr[0:1]:
        log.info('Found push imm32')
        immediate = format_little_endian(instr[1:])
        return format_instr(instr, 'push', immediate)

    return None

def parse_repne(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is repne
    and formats a line to be printed.
    '''
    #repne cmpsd --- 0xf2 0xa7 (Note: 0xf2 is the repne prefix)
    if b'\xf2' == instr[0:1] and len(instr) == 2 and b'\xa7' == instr[1:2]:
        log.info('Found repne cmpsd')
        return format_instr(instr, 'repne cmpsd')

    return None

def parse_ret(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is retf/retn
    and formats a line to be printed.
    '''
    #retf --- 0xcb
    if b'\xcb' == instr[0:1] :
        log.info('Found retf')
        return format_instr(instr, 'retf')

    #retf imm16 --- 0xca iw (note: iw is a 16-bit immediate)
    if b'\xca' == instr[0:1] and len(instr) == 3 :
        log.info('Found retf imm16')
        imm = format_little_endian(instr[1:])
        return format_instr(instr, 'retf', imm)

    #retn --- 0xc3
    if b'\xc3' == instr[0:1] :
        log.info('Found retn')
        return format_instr(instr, 'retn')

    #retn imm16 --- 0xc2 iw (note: iw is a 16-bit immediate)
    if b'\xc2' == instr[0:1] and len(instr) == 3 :
        log.info('Found retn imm16')
        imm = format_little_endian(instr[1:])
        return format_instr(instr, 'retn', imm)

    return None

def parse_salsarshr(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is sal/sar/shr
    and formats a line to be printed.
    '''
    if b'\xd1' == instr[0:1] and len(instr) > 1 :
        mod, reg, rm = parse_modrm(instr[1])
        #sal r/m32, 1 --- 0xd1 /4
        if reg == 4 :
            result = rm32(instr, mod, rm, 'sal')
            if result :
                log.info('Found sal r/m32, 1')
                return result + ', 1'
    
        #sar r/m32, 1 --- 0xd1 /7
        if reg == 7 :
            result = rm32(instr, mod, rm, 'sar')
            if result :
                log.info('Found sar r/m32, 1')
                return result + ', 1'

        #shr r/m32, 1 --- 0xd1 /5
        if reg == 5 :
            result = rm32(instr, mod, rm, 'shr')
            if result :
                log.info('Found shr r/m32, 1')
                return result + ', 1'

    return None

def parse_sbb(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is sbb
    and formats a line to be printed.
    '''
    #sbb eax, imm32 --- 0x1d id, no MODR/M
    if 5 == len(instr) and b'\x1d' == instr[0:1]:
        log.info("Found sbb eax, immediate")
        immediate = format_little_endian(instr[1:])
        return format_instr(instr, 'sbb', 'eax', immediate)

    #sbb r/m32, imm32 --- 0x81 /3 id
    if b'\x81' == instr[0:1] and len(instr) > 2:
        mod, reg, rm = parse_modrm(instr[1])
        if reg == 3 :
            result = rm32immediate(instr, mod, reg, rm, 'sbb')
            if result :
                return result
    
    #sbb r/m32, r32 --- 0x19 /r
    if b'\x19' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        result = rm32r32(instr, mod, reg, rm, 'sbb')
        if result :
            return result

    #sbb r32, r/m32 --- 0x1b /r
    if b'\x1b' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        result = r32rm32(instr, mod, reg, rm, 'sbb')
        if result :
            return result

    return None

def parse_sub(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is sub
    and formats a line to be printed.
    '''
    #sub eax, imm32 --- 0x2d id, no MODR/M
    if 5 == len(instr) and b'\x2d' == instr[0:1]:
        log.info("Found sub eax, immediate")
        immediate = format_little_endian(instr[1:])
        return format_instr(instr, 'sub', 'eax', immediate)

    #sub r/m32, imm32 --- 0x81 /5 id
    if b'\x81' == instr[0:1] and len(instr) > 2:
        mod, reg, rm = parse_modrm(instr[1])
        if reg == 5 :
            result = rm32immediate(instr, mod, reg, rm, 'sub')
            if result :
                return result

    #sub r/m32, r32 --- 0x29 /r
    if b'\x29' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        result = rm32r32(instr, mod, reg, rm, 'sub')
        if result :
            return result

    #sub r32, r/m32 --- 0x2b /r
    if b'\x2b' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        result = r32rm32(instr, mod, reg, rm, 'sub')
        if result :
            return result

    return None

def parse_test(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is test
    and formats a line to be printed.
    '''
    #test eax, imm32 --- 0xa9 id, no MODR/M
    if 5 == len(instr) and b'\xa9' == instr[0:1]:
        log.info("Found test eax, immediate")
        immediate = format_little_endian(instr[1:])
        return format_instr(instr, 'test', 'eax', immediate)
    
    #test r/m32, imm32 --- 0xf7 /0 id
    if b'\xf7' == instr[0:1] and len(instr) > 2:
        mod, reg, rm = parse_modrm(instr[1])
        if reg == 0 :
            result = rm32immediate(instr, mod, reg, rm, 'test')
            if result :
                return result

    #test r/m32, r32 --- 0x85 /r
    if b'\x85' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        result = rm32r32(instr, mod, reg, rm, 'test')
        if result :
            return result

    return None

def parse_xor(instr):
    '''
    instr: A bytearray of instructions
    This function determines if the instruction is xor
    and formats a line to be printed.
    '''
    #xor eax, imm32 --- 0x35 id, no MODR/M
    if 5 == len(instr) and b'\x35' == instr[0:1]:
        log.info("Found xor eax, immediate")
        immediate = format_little_endian(instr[1:])
        return format_instr(instr, 'xor', 'eax', immediate)

    #xor r/m32, imm32 --- 0x81 /6 id
    if b'\x81' == instr[0:1] and len(instr) > 2:
        mod, reg, rm = parse_modrm(instr[1])
        if reg == 6 :
            result = rm32immediate(instr, mod, reg, rm, 'xor')
            if result :
                return result

    #xor r/m32, r32 --- 0x31 /r
    if b'\x31' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        result = rm32r32(instr, mod, reg, rm, 'xor')
        if result :
            return result

    #xor r32, r/m32 --- 0x33 /r
    if b'\x33' == instr[0:1] and len(instr) > 1:
        mod, reg, rm = parse_modrm(instr[1])
        result = r32rm32(instr, mod, reg, rm, 'xor')
        if result :
            return result

    return None

def parse(instruction):
    '''
    instruction: A bytearray of instructions
    This function attempts to parse instructions into known assembly.
    It will return the assembly string that should be printed or None.
    '''
    #first do a check against known prefixes and opcodes to eliminate unknown
    known_starts = [b'\xcc', b'\x0f', b'\x05', b'\x25', b'\x3d', \
        b'\x0d', b'\x1d', b'\x2d', b'\xa9', b'\x35', b'\x81', b'\xc7', \
        b'\xf7', b'\x01', b'\x21', b'\x39', b'\x89', b'\x09', b'\x19', \
        b'\x29', b'\x85', b'\x31', b'\x03', b'\x23', b'\x3b', b'\x8b', \
        b'\x0b', b'\x1b', b'\x2b', b'\x33', b'\xb8', b'\xb9', b'\xba', \
        b'\xbb', b'\xbc', b'\xbd', b'\xbe', b'\xbf', b'\xff', b'\x48', \
        b'\x49', b'\x4a', b'\x4b', b'\x4c', b'\x4d', b'\x4e', b'\x4f', \
        b'\x40', b'\x41', b'\x42', b'\x43', b'\x44', b'\x45', b'\x46', \
        b'\x47', b'\xf7', b'\x8f', b'\x50', b'\x51', b'\x52', b'\x53', \
        b'\x54', b'\x55', b'\x56', b'\x57', b'\x58', b'\x59', b'\x5a', \
        b'\x5b', b'\x5c', b'\x5d', b'\x5e', b'\x5f', b'\x68', b'\x90', \
        b'\x69', b'\xc2', b'\xc3', b'\xca', b'\xcb', b'\xe7', b'\xa5', \
        b'\xd1', b'\xf2']
    if instruction[0:1] not in known_starts :
        log.info("Found an unknown instruction.")
        result = format_unknown(instruction[0])
        return result

    #now run through each of the parsers to find assembly 
    parsers = [parse_int3, parse_cpuid, parse_add, parse_and, parse_cmp, \
         parse_dec, parse_idiv, parse_imul, parse_inc, parse_mov, parse_movsd, \
         parse_mul, parse_neg, parse_nop, parse_not, parse_or, parse_out, \
         parse_pop, parse_push, parse_repne, parse_ret, parse_salsarshr, \
         parse_sbb, parse_sub, parse_test, parse_xor]
    for p in parsers:
        result = p(instruction)
        if result:
            return result

    return None

def disassemble(new_instr, instructions, offset) :
    '''
    instr: A bytearray of instructions
    instructions: An array of tuples [(offset, string).. where
        string is the assembly language string to print
    offset: Integer, the offset into the file to start at
    This function tests each instruction in the array against possible 
    assembly opcodes and returns any leftover instructions that were not
    parsed, the array of values that needs to be printed, and the offset
    '''
    instr = bytearray()
    for b in new_instr :
        instr.append(b)
        log.debug('Testing instruction: {}'.format(binascii.hexlify(instr)))
        result = parse(instr)
        if result:
            instr_offset = offset + 1 - len(instr)
            log.info('Adding instruction for offset {}'.format(instr_offset))
            instructions.append((instr_offset, result))
            instr = bytearray()
        offset += 1
    
    return instr, instructions, offset

if '__main__' == __name__:
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', help='Input file', dest='infile',
                        required=True)
    parser.add_argument('-v', '--verbose', help='Enable verbose output',
                        action='store_true', default=False)
    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    log.debug('Attempting to read input file')
    try:
        with open(args.infile, 'rb') as fd:
            inbytes = bytearray(fd.read())
            if not inbytes:
                log.error('Input file was empty')
                sys.exit(-1)
    except (IOError, OSError) as e:
        log.error('Failed to open {}'.format(args.infile))
        sys.exit(-1)

    log.debug('Parsing instructions')
    offset = 0
    instr = bytearray()
    instructions = []
    
    instr, instructions, offset = disassemble(inbytes, instructions, offset)
    while len(instr) != 0 :
        instructions.append((offset, format_unknown(instr[0])))
        offset+=1
        instr, instructions, offset = disassemble(instr[1:], instructions, offset)
    '''
    The old way of doing things, the thing above seems to work but 
    I should test some more edge cases. 
    for b in inbytes:
        instr.append(b)
        log.debug('Testing instruction: {}'.format(binascii.hexlify(instr)))
        result = parse(instr)
        if result:
            instr_offset = offset + 1 - len(instr)
            log.info('Adding instruction for offset {}'.format(instr_offset))
            instructions.append((instr_offset, result))
            instr = bytearray()
        offset += 1
    #one way to tell if there was a known instruction that didn't parse
    #would be if I get to the end of this for loop and len(instr) != 0
    #i want to turn this into a function and pass in instr[1:] to the
    #function to run again, while first parsing the first thing in
    #instructions as something i dont know how to do, the function will 
    #need to return instr, instructions, and offset. 
    '''
    log.debug('Creating output data')
    output = ''
    for (offset, text) in instructions:
        output += '{:08x}:   {}\n'.format(offset, text)

    log.debug('Attempting to write output')
    print(output)
