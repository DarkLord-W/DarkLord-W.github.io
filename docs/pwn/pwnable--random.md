---
title: pwnable--random
updated: 2022-09-06 08:11:32Z
created: 2022-04-17 15:48:04Z
---

**Tips:**

**rand()函数请查看Security下相关文档**

* * *

```
Daddy, teach me how to use random value in programming!

ssh random@pwnable.kr -p2222 (pw:guest)
```

```c
#include <stdio.h>

int main(){
    unsigned int random;
    random = rand();	// random value!

    unsigned int key=0;
    scanf("%d", &key);

    if( (key ^ random) == 0xdeadbeef ){
        printf("Good!\n");
        system("/bin/cat flag");
        return 0;
    }

    printf("Wrong, maybe you should try 2^32 cases.\n");
    return 0;
}
```

* * *

**经过查阅得知：**

`rand()` 的内部实现是用线性同余法做的，它不是真的随机数，因其周期特别长，故在一定的范围里可看成是随机的。

`rand()`返回一随机数值的范围在 `0 至 RAND_MAX`间。

`RAND_MAX`的范围最少是在 `32767` 之间`(int)`。

用`unsigned int` 双字节是 `65535`，四字节是 `4294967295`的整数范围。

`0~RAND_MAX` 每个数字被选中的机率是相同的。

用户未设定随机数种子时，系统默认的随机数种子为`1`。

`rand()`产生的是伪随机数字，每次执行时是相同的; 若要不同, 用函数`srand()`初始化它

* * *

在本题目中并没有使用srand()函数,故而rand()生成的随机数实际上是固定的

**适用gdb分析**

```sh
└─# objdump -t -j .text random                                                                                                                                  127 ⨯

random:     file format elf64-x86-64

SYMBOL TABLE:
0000000000400510 l    d  .text	0000000000000000              .text
000000000040053c l     F .text	0000000000000000              call_gmon_start
0000000000400560 l     F .text	0000000000000000              __do_global_dtors_aux
00000000004005d0 l     F .text	0000000000000000              frame_dummy
0000000000400710 l     F .text	0000000000000000              __do_global_ctors_aux
0000000000400700 g     F .text	0000000000000002              __libc_csu_fini
0000000000400670 g     F .text	0000000000000089              __libc_csu_init
0000000000400510 g     F .text	0000000000000000              _start
00000000004005f4 g     F .text	0000000000000073              main
```

```sh
pwndbg> disass main
Dump of assembler code for function main:
   0x00000000004005f4 <+0>:	push   rbp
   0x00000000004005f5 <+1>:	mov    rbp,rsp
   0x00000000004005f8 <+4>:	sub    rsp,0x10
   0x00000000004005fc <+8>:	mov    eax,0x0
   0x0000000000400601 <+13>:	call   0x400500 <rand@plt>
   0x0000000000400606 <+18>:	mov    DWORD PTR [rbp-0x4],eax
   0x0000000000400609 <+21>:	mov    DWORD PTR [rbp-0x8],0x0
   0x0000000000400610 <+28>:	mov    eax,0x400760
   0x0000000000400615 <+33>:	lea    rdx,[rbp-0x8]
   0x0000000000400619 <+37>:	mov    rsi,rdx
   0x000000000040061c <+40>:	mov    rdi,rax
   0x000000000040061f <+43>:	mov    eax,0x0
   0x0000000000400624 <+48>:	call   0x4004f0 <__isoc99_scanf@plt>
   0x0000000000400629 <+53>:	mov    eax,DWORD PTR [rbp-0x8]
   0x000000000040062c <+56>:	xor    eax,DWORD PTR [rbp-0x4]
   0x000000000040062f <+59>:	cmp    eax,0xdeadbeef
   0x0000000000400634 <+64>:	jne    0x400656 <main+98>
   0x0000000000400636 <+66>:	mov    edi,0x400763
   0x000000000040063b <+71>:	call   0x4004c0 <puts@plt>
   0x0000000000400640 <+76>:	mov    edi,0x400769
   0x0000000000400645 <+81>:	mov    eax,0x0
   0x000000000040064a <+86>:	call   0x4004d0 <system@plt>
   0x000000000040064f <+91>:	mov    eax,0x0
   0x0000000000400654 <+96>:	jmp    0x400665 <main+113>
   0x0000000000400656 <+98>:	mov    edi,0x400778
   0x000000000040065b <+103>:	call   0x4004c0 <puts@plt>
   0x0000000000400660 <+108>:	mov    eax,0x0
   0x0000000000400665 <+113>:	leave  
   0x0000000000400666 <+114>:	ret    
End of assembler dump.
```

![d074505f4564200ab4741f1b8d1807de.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/d074505f4564200ab4741f1b8d1807de.png)

在rand@plt后设置断点然后运行，可以得到random随机数RAX为0x6b8b4567

**由于^(异或)运算是可逆的，可以得到key:**

key =0x6b8b4567^0xdeadbeef = 3039230856(可以用python shell计算得出)

* * *

**本地运行：**

```sh
┌──(root💀kali)-[~/pwnable/random]
└─# ./random
3039230856
Good!
/bin/cat: flag: No such file or directory
```

**pwnable.kr运行：**

```python
# -*- coding:utf-8 -*-

from pwn import *

try:
    s = ssh(host='pwnable.kr',user='random',password='guest',port=2222)
    p = s.process('./random')
    p.sendline('3039230856\n')
    p.interactive()
except:
    print('error')
```

**<img src="https://raw.githubusercontent.com/DarkLord-W/CloudImages/main/images/dadebc0086407133f8d23be98637b8ea.png" alt="dadebc0086407133f8d23be98637b8ea.png" width="1077" height="301">**