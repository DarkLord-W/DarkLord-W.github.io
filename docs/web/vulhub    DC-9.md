---
title: vulhub    DC-9
updated: 2022-10-26 06:05:01Z
created: 2022-10-19 07:20:41Z
---

Download **link：https://www.vulnhub.com/entry/dc-9,412/**

**扫描主机，靶机ip为192.168.56.11**

**<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/de32b30940077a1ff349d8d083c2ac07.png" alt="de32b30940077a1ff349d8d083c2ac07.png" width="872" height="471" class="jop-noMdConv">**

**靶机开放22和80端口**

**访问80端口web服务**

**<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/40ff85d50fa1e8c7b7f4fd17d54d474c.png" alt="40ff85d50fa1e8c7b7f4fd17d54d474c.png" width="873" height="293" class="jop-noMdConv">**

**扫描站点目录**

**<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/2ba7373b7d450c69a5632cac13c4f19e.png" alt="2ba7373b7d450c69a5632cac13c4f19e.png" width="703" height="567" class="jop-noMdConv">**

**访问站点各个页面**

**<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/29f5270580d0770da7666ac47593b839.png" alt="29f5270580d0770da7666ac47593b839.png" width="987" height="539" class="jop-noMdConv">**

**通过测试可以发现search.php页面存在sql注入**

**保存请求数据使用sqlmap进行自动化注入**

**![24beee23f2ef9dbf24973684a9b76e45.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/24beee23f2ef9dbf24973684a9b76e45.png)**

**逐个dbs,tables,columns,最后dump数据**

**先dump users![46745c3c408ad0403d933d0e308b9f29.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/46745c3c408ad0403d933d0e308b9f29.png)**

**用users库中的表登录web，全部失败**

**那么dump Staff库中的数据，发现存在账户密码`admin/transorbital1`，使用该账户密码成功登录后台**

**![002281c44433ced3fde8a62bc1e69f0a.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/002281c44433ced3fde8a62bc1e69f0a.png)**

**![2723765b3e9246acf81b39238f180a48.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/2723765b3e9246acf81b39238f180a48.png)**

**注意到登录后台后页面下方存在`File does not exist`的提示，尝试在页面后添加`?file=路径`，多次尝试，成功读取出/etc/passwd文件**

**![2f9fded0ffdbeda79a0de2eb3718c0d3.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/2f9fded0ffdbeda79a0de2eb3718c0d3.png)**

**接下来对文件进行fuzz遍历，查看linux系统中任务调度情况`/proc/sched_debug`**

**![6e0b82f42e3608944dd783a41d3973a3.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/6e0b82f42e3608944dd783a41d3973a3.png)**

**发现存在knockd服务，查询得知**

```
敲门（knock）指的是我们从自己的客户端设备（pc、笔记本或者手机）向服务器IP发送一系列实现约好的暗号，而服务器上需要相应的安装接收暗号的服务knockd，它在接收到正确的暗号的时候，会临时性的为敲门者开一段时间的门并随后关上（当然也能够配置成一直开着），我们要在这几秒钟里面登录成功并且保持连接，如果不小心断了连接就要重新敲门。

knock动作的实质就是连续的向指定的ip的约定的端口连续的发送多个tcp或者udp包，比如我们可以通过*telnet 服务器地址 端口号* 命令来发送tcp包，也可以直接在浏览器地址栏里面用 http://服务器地址:端口号 的方式来让浏览器发出与服务器指定端口tcp握手的SYN包。但是最好用的还是直接下载knock工具（windows版、mac版），用 knock 服务器地址 端口号 的方式来实现敲门
```

读取knockd的配置文件`/etc/knockd.conf`，得到ssh开门密码 `9842,8475,7469(倒序)`

![f60d4061adf2528161960102aa32b089.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/f60d4061adf2528161960102aa32b089.png)

安装knockd并对靶机实行ssh开门

**<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/6dde7d80df886d0c60e9d4aed8f0d727.png" alt="6dde7d80df886d0c60e9d4aed8f0d727.png" width="818" height="584" class="jop-noMdConv">**

**使用之前sql注入爆破出来的用户名和密码进行ssh爆破**

**<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/4167d487643ae3c6d4b405bbecebe702.png" alt="4167d487643ae3c6d4b405bbecebe702.png" width="998" height="341" class="jop-noMdConv">**

**爆破出来三组用户名密码**

**其他两个用户都没有什么文件也没有sudo权限，ssh登录janitor发现一个密码txt文件![cf446e52f4a142edc9228ec54639ca1f.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/cf446e52f4a142edc9228ec54639ca1f.png)**

**使用上面的密码继续进行ssh爆破**

**<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/4f470bf9838244a77c2c1c8e358413ab.png" alt="4f470bf9838244a77c2c1c8e358413ab.png" width="973" height="413" class="jop-noMdConv">**

**得到一个新用户名密码**`login: fredf password: B4-Tru3-001`

**ssh登录该用户，查看sudo权限如下**

![d72ad33134960e3d15b62224208516a9.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/d72ad33134960e3d15b62224208516a9.png)

**该用户有一个不用root密码就可以执行的文件`/opt/devstuff/dist/test/test`**

**执行该test文件，显示test.py**

```sh
fredf@dc-9:~$ /opt/devstuff/dist/test/test 
Usage: python test.py read append
```

切换到`/opt/devstuff`目录下，找到该test.py文件，如下图

**![5c87c1c5abf888ceea5df1337ea66968.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/5c87c1c5abf888ceea5df1337ea66968.png)**

**发现这个python脚本的功能是打开一个文件读取信息，追加写入另一个文件中**

**那我们构造一个具有root权限的用户并写入passwd文件中，就可以提权**

```sh
fredf@dc-9:~$ openssl passwd -1 -salt sob 123
$1$sob$BmJLmGFTRiB9Pzlip0Dpa0
```

构造用户`sob:$1$sob$BmJLmGFTRiB9Pzlip0Dpa0:0:0::/root:/bin/bash`

```sh
fredf@dc-9:~$ echo 'sob:$1$sob$BmJLmGFTRiB9Pzlip0Dpa0:0:0::/root:/bin/bash' > ./hack.txt
fredf@dc-9:~$ cat hack.txt 
sob:$1$sob$BmJLmGFTRiB9Pzlip0Dpa0:0:0::/root:/bin/bash
```

然后写入用户至`/etc/passwd`

![d42114243c149d1706798394f7701f6e.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/d42114243c149d1706798394f7701f6e.png)

![6a482ad83707bcd13f7f73accfee1bd1.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/6a482ad83707bcd13f7f73accfee1bd1.png)

切换至sob用户,成功获得root权限

![590dc0f8c2673aa2c3db9245496e176f.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/590dc0f8c2673aa2c3db9245496e176f.png)