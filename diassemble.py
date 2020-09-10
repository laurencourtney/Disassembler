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
    hexbytes: A bytearray - 4 bytes long, usually an immediate or 
    displacement. This function will convert it into a little endian 
    string. 
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
    print(instruction)
    opcode = int.from_bytes(byte, "big")
    print(opcode)
    net = instruction - opcode
    print(net)
    if abs(net) < 8 :
        return parse_register(abs(net))
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
    reg: An integer representing an x86 register
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
            return format_instr(instr, op, '[{}]'.format(register), immediate)

        if mod == 3 :
            register = parse_register(rm)
            immediate = format_little_endian(instr[2:])
            return format_instr(instr, op, register, immediate)
            
    #check for instructions with an immediate and an 8 bit displacent
    if 7 == len(instr) :
        if mod == 1 :
            register = parse_register(rm)
            disp = '0x{:02x}'.format(instr[2])
            immediate = format_little_endian(instr[3:])
            return format_instr(instr, op, '[{} + {}]'.format(register, disp), immediate)

    #now check for longer instructions with a 32 bit displacement
    if 10 == len(instr) :
        if mod == 0 and rm == 5 :
            disp = format_little_endian(instr[2:6])
            immediate = format_little_endian(instr[6:10])
            return format_instr(instr, op, '[{}]'.format(disp), immediate)
        if mod == 2 :
            register = parse_register(rm)
            disp = format_little_endian(instr[2:6])
            immediate = format_little_endian(instr[6:10])
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
            return format_instr(instr, op, '[{}]'.format(rm_str), reg_str)

        if mod == 3 :
            reg_str = parse_register(reg)
            rm_str = parse_register(rm)
            return format_instr(instr, op, rm_str, reg_str)
            
    #check for instructions with an 8 bit displacent
    if 3 == len(instr) :
        if mod == 1 :
            reg_str = parse_register(reg)
            rm_str = parse_register(rm)
            disp = '0x{:02x}'.format(instr[2])
            return format_instr(instr, op, '[{} + {}]'.format(rm_str, disp), reg_str)
            
    #now check for longer instructions with a 32 bit displacement
    if 6 == len(instr) :
        if mod == 0 and rm == 5 :
            disp = format_little_endian(instr[2:6])
            reg_str = parse_register(reg)
            return format_instr(instr, op, '[{}]'.format(disp), reg_str)
        if mod == 2 :
            reg_str = parse_register(reg)
            disp = format_little_endian(instr[2:6])
            rm_str = parse_register(rm)
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
            return format_instr(instr, op, reg_str, '[{}]'.format(rm_str))

        if mod == 3 :
            reg_str = parse_register(reg)
            rm_str = parse_register(rm)
            return format_instr(instr, op, reg_str, rm_str)
            
    #check for instructions with an 8 bit displacent
    if 3 == len(instr) :
        if mod == 1 :
            reg_str = parse_register(reg)
            rm_str = parse_register(rm)
            disp = '0x{:02x}'.format(instr[2])
            return format_instr(instr, op, reg_str, '[{} + {}]'.format(rm_str, disp))
            
    #now check for longer instructions with a 32 bit displacement
    if 6 == len(instr) :
        if mod == 0 and rm == 5 :
            disp = format_little_endian(instr[2:6])
            reg_str = parse_register(reg)
            return format_instr(instr, op, reg_str, '[{}]'.format(disp))
        if mod == 2 :
            reg_str = parse_register(reg)
            disp = format_little_endian(instr[2:6])
            rm_str = parse_register(rm)
            return format_instr(instr, op, reg_str, '[{} + {}]'.format(rm_str, disp))


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
            log.info("Found add r/m32, immediate")
            result = rm32immediate(instr, mod, reg, rm, 'add')
            if result :
                return result
    
    #add r/m32, r32 --- 0x01 /r
    if b'\x01' == instr[0:1] and len(instr) > 1:
        log.info('Found add r/m32, r32')
        mod, reg, rm = parse_modrm(instr[1])
        result = rm32r32(instr, mod, reg, rm, 'add')
        if result :
            return result

    #add r32, r/m32 --- 0x03 /r
    if b'\x03' == instr[0:1] and len(instr) > 1:
        log.info('Found add r32, r/m32')
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
            log.info("Found and r/m32, immediate")
            result = rm32immediate(instr, mod, reg, rm, 'and')
            if result :
                return result

    #and r/m32, r32 --- 0x21 /r
    if b'\x21' == instr[0:1] and len(instr) > 1:
        log.info('Found and r/m32, r32')
        mod, reg, rm = parse_modrm(instr[1])
        result = rm32r32(instr, mod, reg, rm, 'and')
        if result :
            return result

    #and r32, r/m32 --- 0x23 /r
    if b'\x23' == instr[0:1] and len(instr) > 1:
        log.info('Found and r32, r/m32')
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
            log.info("Found cmp r/m32, immediate")
            result = rm32immediate(instr, mod, reg, rm, 'cmp')
            if result :
                return result
    
    #cmp r/m32, r32 --- 0x39 /r
    if b'\x39' == instr[0:1] and len(instr) > 1:
        log.info('Found cmp r/m32, r32')
        mod, reg, rm = parse_modrm(instr[1])
        result = rm32r32(instr, mod, reg, rm, 'cmp')
        if result :
            return result

    #cmp r32, r/m32 --- 0x3b /r
    if b'\x3b' == instr[0:1] and len(instr) > 1:
        log.info('Found cmp r32, r/m32')
        mod, reg, rm = parse_modrm(instr[1])
        result = r32rm32(instr, mod, reg, rm, 'cmp')
        if result :
            return result

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
            log.info("Found mov r/m32, immediate")
            result = rm32immediate(instr, mod, reg, rm, 'mov')
            if result :
                return result

    #mov r/m32, r32 --- 0x89 /r
    if b'\x89' == instr[0:1] and len(instr) > 1:
        log.info('Found mov r/m32, r32')
        mod, reg, rm = parse_modrm(instr[1])
        result = rm32r32(instr, mod, reg, rm, 'mov')
        if result :
            return result

    #mov r32, r/m32 --- 0x8b /r
    if b'\x8b' == instr[0:1] and len(instr) > 1:
        log.info('Found mov r32, r/m32')
        mod, reg, rm = parse_modrm(instr[1])
        result = r32rm32(instr, mod, reg, rm, 'mov')
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
            log.info("Found or r/m32, immediate")
            result = rm32immediate(instr, mod, reg, rm, 'or')
            if result :
                return result

    #or r/m32, r32 --- 0x09 /r
    if b'\x09' == instr[0:1] and len(instr) > 1:
        log.info('Found or r/m32, r32')
        mod, reg, rm = parse_modrm(instr[1])
        result = rm32r32(instr, mod, reg, rm, 'or')
        if result :
            return result

    #or r32, r/m32 --- 0x0b /r
    if b'\x0b' == instr[0:1] and len(instr) > 1:
        log.info('Found or r32, r/m32')
        mod, reg, rm = parse_modrm(instr[1])
        result = r32rm32(instr, mod, reg, rm, 'or')
        if result :
            return result

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
            log.info("Found sbb r/m32, immediate")
            result = rm32immediate(instr, mod, reg, rm, 'sbb')
            if result :
                return result
    
    #sbb r/m32, r32 --- 0x19 /r
    if b'\x19' == instr[0:1] and len(instr) > 1:
        log.info('Found sbb r/m32, r32')
        mod, reg, rm = parse_modrm(instr[1])
        result = rm32r32(instr, mod, reg, rm, 'sbb')
        if result :
            return result

    #sbb r32, r/m32 --- 0x1b /r
    if b'\x1b' == instr[0:1] and len(instr) > 1:
        log.info('Found sbb r32, r/m32')
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
            log.info("Found sub r/m32, immediate")
            result = rm32immediate(instr, mod, reg, rm, 'sub')
            if result :
                return result

    #sub r/m32, r32 --- 0x29 /r
    if b'\x29' == instr[0:1] and len(instr) > 1:
        log.info('Found sub r/m32, r32')
        mod, reg, rm = parse_modrm(instr[1])
        result = rm32r32(instr, mod, reg, rm, 'sub')
        if result :
            return result

    #sub r32, r/m32 --- 0x2b /r
    if b'\x2b' == instr[0:1] and len(instr) > 1:
        log.info('Found sub r32, r/m32')
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
            log.info("Found test r/m32, immediate")
            result = rm32immediate(instr, mod, reg, rm, 'test')
            if result :
                return result

    #test r/m32, r32 --- 0x85 /r
    if b'\x85' == instr[0:1] and len(instr) > 1:
        log.info('Found test r/m32, r32')
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
            log.info("Found xor r/m32, immediate")
            result = rm32immediate(instr, mod, reg, rm, 'xor')
            if result :
                return result

    #xor r/m32, r32 --- 0x31 /r
    if b'\x31' == instr[0:1] and len(instr) > 1:
        log.info('Found xor r/m32, r32')
        mod, reg, rm = parse_modrm(instr[1])
        result = rm32r32(instr, mod, reg, rm, 'xor')
        if result :
            return result

    #xor r32, r/m32 --- 0x33 /r
    if b'\x33' == instr[0:1] and len(instr) > 1:
        log.info('Found xor r32, r/m32')
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
        b'\xbb', b'\xbc', b'\xbd', b'\xbe', b'\xbf']
    if instruction[0:1] not in known_starts :
        log.info("Found an unknown instruction.")
        result = format_unknown(instruction[0])
        return result

    #now run through each of the parsers to find assembly 
    parsers = [parse_int3, parse_cpuid, parse_add, parse_and, parse_cmp, \
         parse_mov, parse_or, parse_sbb, parse_sub, parse_test, parse_xor]
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
