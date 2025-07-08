---
title: pwnable--input
updated: 2022-09-06 08:11:28Z
created: 2022-06-14 08:39:12Z
---

ssh input2@pwnable.kr -p2222 (pw:guest)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(int argc, char* argv[], char* envp[]){
        printf("Welcome to pwnable.kr\n");
        printf("Let's see if you know how to give input to program\n");
        printf("Just give me correct inputs then you will get the flag :)\n");

        // argv
        if(argc != 100) return 0;
        if(strcmp(argv['A'],"\x00")) return 0;
        if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
        printf("Stage 1 clear!\n");

        // stdio
        char buf[4];
        read(0, buf, 4);
        if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
        read(2, buf, 4);
        if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
        printf("Stage 2 clear!\n");

        // env
        if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
        printf("Stage 3 clear!\n");

        // file
        FILE* fp = fopen("\x0a", "r");
        if(!fp) return 0;
        if( fread(buf, 4, 1, fp)!=1 ) return 0;
        if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
        fclose(fp);
        printf("Stage 4 clear!\n");

        // network
        int sd, cd;
        struct sockaddr_in saddr, caddr;
        sd = socket(AF_INET, SOCK_STREAM, 0);
        if(sd == -1){
                printf("socket error, tell admin\n");
                return 0;
        }
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = INADDR_ANY;
        saddr.sin_port = htons( atoi(argv['C']) );
        if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
                printf("bind error, use another port\n");
                return 1;
        }
        listen(sd, 1);
        int c = sizeof(struct sockaddr_in);
        cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c);
        if(cd < 0){
                printf("accept error, tell admin\n");
                return 0;
        }
        if( recv(cd, buf, 4, 0) != 4 ) return 0;
        if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;
        printf("Stage 5 clear!\n");

        // here's your flag
        system("/bin/cat flag");
        return 0;
}
```

可以看到，该题目分为五个阶段，分别是 argv、stdio、env、file、network，接下来逐个及进行分析：

## 第一阶段：argv

```c
        // argv
        if(argc != 100) return 0;
        if(strcmp(argv['A'],"\x00")) return 0;
        if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
        printf("Stage 1 clear!\n");
```

要求输入参数100个，且第A=65个参数为"\\x00" 第B=66个参数为"\\x20\\x0a\\x0d"

对应的writeup如下

```python
# -*- coding:utf-8 -*-
from pwn import *

#argv
args = ['a']*100
args[65] = '\x00'
args[66] = '\x20\x0a\x0d'
p = process(executable='./input',argv=args) 
p.interactive()
```

## 第二阶段：stdio

```c
        // stdio
        char buf[4];
        read(0, buf, 4);  //输入流0-Stdin
        if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
        read(2, buf, 4); //错误输出流2-stderr
        if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
        printf("Stage 2 clear!\n");
```

**Linux把所有的东西看做文件，其中0,1,2比较特殊，分别代表输入流0-Stdin，输出流1-stdout和错误输出流2-stderr**

**`memcmp(buf, "\x00\x0a\x00\xff", 4)`这个命令，作用是从给定的两个内存地址开始，比较指定的字节个数。这里就是比较`buf`开始的4个字节和`"\x00\x0a\x00\xff"`**

**buf是通过`read(0, buf, 4)`写入的。之前的题目中也有遇见过`read`函数**

**fd = 0，也对应了程序中的标准化输入,可以修改程序的标准化输入（stdin）来实现输入不可见字符**

**fd = 2，对应了程序中的标准化错误;标准化错误无法通过命令行输入来修改，需要通过创建通道的方式重定向程序的标准化错误信息**

```python
    stdin = “\x00\x0a\x00\xff”
    stderr = “\x00\x0a\x02\xff”

```

## 第三阶段：env

```c
        // env
        if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
        printf("Stage 3 clear!\n");
```

**char *getenv(const char *name) 搜索 name 所指向的环境字符串，并返回相关的值给字符串,环境变量的格式为name＝value**

```python
env = {"\xde\xad\xbe\xef":"\xca\xfe\xba\xbe"}
```

## 第四阶段：file

```c
        // file
        FILE* fp = fopen("\x0a", "r");
        if(!fp) return 0;
        if( fread(buf, 4, 1, fp)!=1 ) return 0;
        if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
        fclose(fp);
        printf("Stage 4 clear!\n");
```

**fread函数：**

**`size_t fread(void *buffer, size_t size, size_t count FILE *stream)`

```python
#file
with open("\x0a","w+") as f:
    f.write("\x00\x00\x00\x00")

```

## 第五阶段：network

```c
        // network
        int sd, cd;
        struct sockaddr_in saddr, caddr;
        sd = socket(AF_INET, SOCK_STREAM, 0);
        if(sd == -1){
                printf("socket error, tell admin\n");
                return 0;
        }
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = INADDR_ANY;
        saddr.sin_port = htons( atoi(argv['C']) );
        if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
                printf("bind error, use another port\n");
                return 1;
        }
        listen(sd, 1);
        int c = sizeof(struct sockaddr_in);
        cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c);
        if(cd < 0){
                printf("accept error, tell admin\n");
                return 0;
        }
        if( recv(cd, buf, 4, 0) != 4 ) return 0;
        if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;
        printf("Stage 5 clear!\n");
```

```python
args[67] = '8888'
conn = connect('127.0.0.1',8888)
conn.send(b'\xde\xad\xbe\xef')
conn.close()
```

## 完整的writeup如下

```python
from pwn import *
import os
import socket

#argv
args = ['a']*100
args[65] = '\x00'
args[66] = '\x20\x0a\x0d'
args[67] = '8888' #for network -- set port to args['C']


#stdio
stdinr, stdinw = os.pipe()
stderrr, stderrw = os.pipe()
os.write(stdinw,b"\x00\x0a\x00\xff")
os.write(stderrw,b"\x00\x0a\x02\xff")

#env
env = {"\xde\xad\xbe\xef":"\xca\xfe\xba\xbe"}

#file
with open("\x0a","w+") as f:
    f.write("\x00\x00\x00\x00")


p = process(executable='./input',argv=args,stdin=stdinr,stderr=stderrr,env=env) 

#network
conn = connect('127.0.0.1',8888)
conn.send(b'\xde\xad\xbe\xef')
conn.close()

p.interactive()
nv=env) 
p.interactive()
ve()

p.interactive()
```