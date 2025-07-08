---
title: pwnable--fd -- (File descriptor)
updated: 2022-09-06 08:11:22Z
created: 2022-04-01 10:21:50Z
---

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/63c93ec7d8e30f0017d628cf6d998227.png" alt="63c93ec7d8e30f0017d628cf6d998227.png" width="668" height="439" class="jop-noMdConv">

==**ssh fd@pwnable.kr -p2222 (pw:guest)**==

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/e7214056bbe241c8dfd6dbc0cf05a9a3.png" alt="e7214056bbe241c8dfd6dbc0cf05a9a3.png" width="617" height="621" class="jop-noMdConv">

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
    if(argc<2){
        printf("pass argv[1] a number\n");
        return 0;
    }
    int fd = atoi( argv[1] ) - 0x1234;
    int len = 0;
    len = read(fd, buf, 32);
    if(!strcmp("LETMEWIN\n", buf)){
        printf("good job :)\n");
        system("/bin/cat flag");
        exit(0);
    }
    printf("learn about Linux file IO\n");
    return 0;

}
```

==这里要注意linux相关函数的具体使用技巧==

```
atoi() — Convert Character String to Integer
```

```
Linux standard IO streams

A Linux shell, such as Bash, receives input and sends output as sequences or streams of characters. Each character is independent of the one before it and the one after it. The characters are not organized into structured records or fixed-size blocks. Streams are accessed using file IO techniques, whether or not the actual stream of characters comes from or goes to a file, a keyboard, a window on a display, or some other IO device. Linux shells use three standard I/O streams, each of which is associated with a well-known file descriptor:

stdout is the standard output stream, which displays output from commands. It has file descriptor 1.
stderr is the standard error stream, which displays error output from commands. It has file descriptor 2.
stdin is the standard input stream, which provides input to commands. It has file descriptor 0.

Input streams provide input to programs, usually from terminal keystrokes. Output streams print text characters, usually to the terminal. The terminal was originally an ASCII typewriter or display terminal, but now, it is more often a text window on a graphical desktop.
```

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/fe5c3756554e25860ac52dcefe8b8e29.png" alt="fe5c3756554e25860ac52dcefe8b8e29.png" width="793" height="218" class="jop-noMdConv">

分析：fd.c需要传入一个参数，然后将传入的字符串参数通过atoi参数转换为整形并减去 0x1234

由上已知，如果fd为0的话，则程序将从stdin读入数据至buff

故而传入参数为0x1234的十进制4660

```shell
└─# echo $((num=0x1234))
4660
```

然后再匹配strcmp中的字符串"LETMEWIN\\n"，即可得到flag

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/792b0d9b56f414147ba53f4e48902456.png" alt="792b0d9b56f414147ba53f4e48902456.png" width="634" height="238">