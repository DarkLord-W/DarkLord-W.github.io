---
title: pwnable--collision
updated: 2023-05-17 07:23:57Z
created: 2022-04-01 13:29:36Z
---

#include &lt;stdlib.h&gt;

#include &lt;unistd.h&gt;

#include &lt;stdio.h&gt;

#include &lt;string.h&gt;

void win()

{

printf("code flow successfully changed\\n");

}

int main(int argc, char **argv)

{

volatile int (*fp)();

char buffer\[64\];

fp = 0;

gets(buffer);

if(fp) {

printf("calling function pointer, jumping to 0x%08x\\n", fp);

fp();

}

}

**参考：**[pwnable-Col](https://cloud.tencent.com/developer/article/1516391)

**涉及知识点：**

1.指针类型转换

2.大小端序

3.字符串转换ASCII码

4.哈希碰撞

* * *

<img src="https://gcore.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/ff2797e2e0b0d1f6edbc067daf78e56f.png" alt="ff2797e2e0b0d1f6edbc067daf78e56f.png" width="681" height="452" class="jop-noMdConv">

==ssh col@pwnable.kr -p2222 (pw:guest)==

==<img src="https://gcore.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/8cb20b43c6286a8f14c934b62488c749.png" alt="8cb20b43c6286a8f14c934b62488c749.png" width="765" height="763" class="jop-noMdConv">==

查看文件：![](/home/darklord/.config/marktext/images/2022-04-12-18-35-19-image.png)

```c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
    int* ip = (int*)p;

    int i;
    int res=0;
    for(i=0; i<5; i++){
        res += ip[i];
    }
    return res;
}

int main(int argc, char* argv[]){
    if(argc<2){
        printf("usage : %s [passcode]\n", argv[0]);
        return 0;
    }
    if(strlen(argv[1]) != 20){
        printf("passcode length should be 20 bytes\n");
        return 0;
    }

    if(hashcode == check_password( argv[1] )){
        system("/bin/cat flag");
        return 0;
    }
    else
        printf("wrong passcode.\n");
    return 0;
}
```

可以在col.c中看到这句提示：passcode length should be 20 bytes–>密码长度应该为20个字节

传入check_password的是一个不可变字符串指针，然后将其强制转变为整数型指针；

之后进行一共循环5次的for循环累加；

p长度为20个字节，转换后ip长度依然是20个字节，结合前面查看文件类型，可以推出一共ip有5个整数，每个整数长度为4个字节

hashcode的结构应该是：`hashcode = A + B + C + D + E=0x21DD09EC`；

答案可以有很多种，只要满足五个相加结果为0x21DD09EC即可

```shell
┌──(root💀kali)-[~]
└─# echo 'obase=10; ibase=16; 21DD09EC' | bc
568134124
```

```shell
└─# bc
568134124/5
113626824
113626824*5
568134120
```

```shell
└─# echo 'obase=16; ibase=10; 113626824' | bc
6C5CEC8
```

可以看到，0x21DD09EC整除5余数为4,则五个整数可以为0x6C5CEC8×4 + (0x6C5CEC8+4=0x6C5CECC)=0x6C5CEC8×4 + 0x6C5CECC

**结果如下：**

```shell
'\xC8\xCE\xC5\x06' * 4 + '\xCC\xCE\xC5\x06'
```

![155363ff93ce9ee4dbc41f990441f004.png](https://gcore.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/155363ff93ce9ee4dbc41f990441f004.png)

\*\*PS:\*\*这里要注意\\xC8\\xCE\\xC5\\x06及\\xCC\\xCE\\xC5\\x06都是小端序格式