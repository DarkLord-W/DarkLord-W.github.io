---
title: Protostar_stack0
updated: 2024-02-18 08:46:56Z
created: 2023-06-21 08:07:44Z
---

运行程序，如下

**<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/83700502108d559cffdad6d2ce4fe38b.png" alt="83700502108d559cffdad6d2ce4fe38b.png" width="452" height="117" class="jop-noMdConv">**

查看反编译代码

```
void main(void)
{
    undefined auStack84 [64];
    int32_t iStack20;
    
    iStack20 = 0;
    gets(auStack84);
    if (iStack20 == 0) {
        puts("Try again?");
    } else {
        puts("you have changed the \'modified\' variable");
    }
    return;
}
```

本题目逻辑很简单，获取输入，输入数组长度为64,只需要输出长度超过64溢出修改iStack20就OK，如下

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/16d3ca07733170a42997a21dc383b46e.png" alt="16d3ca07733170a42997a21dc383b46e.png" width="952" height="245" class="jop-noMdConv">