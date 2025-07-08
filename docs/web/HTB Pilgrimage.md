---
title: HTB Pilgrimage
updated: 2023-07-23 15:10:29Z
created: 2023-07-23 12:05:30Z
---

```sh
└─$ sudo nmap -sS -sV -sC -Pn -T4 -A 10.10.11.219
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-23 20:04 CST
Nmap scan report for 10.10.11.219
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 20be60d295f628c1b7e9e81706f168f3 (RSA)
|   256 0eb6a6a8c99b4173746e70180d5fe0af (ECDSA)
|_  256 d14e293c708669b4d72cc80b486e9804 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://pilgrimage.htb/
|_http-server-header: nginx/1.18.0
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=7/23%OT=22%CT=1%CU=38038%PV=Y%DS=2%DC=T%G=Y%TM=64BD176
OS:D%P=x86_64-pc-linux-gnu)SEQ(SP=FD%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST11
OS:NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3389/tcp)
HOP RTT       ADDRESS
1   110.99 ms 10.10.16.1
2   110.99 ms 10.10.11.219

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.49 seconds
```

添加相应的hosts记录

```
10.10.11.219	pilgrimage.htb
```

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/f9f76307d28ff3ea260cf5cbf54816f2.png" alt="f9f76307d28ff3ea260cf5cbf54816f2.png" width="586" height="381" class="jop-noMdConv">

扫描web目录

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/e2efee00571e384bfef90939e26ed1c8.png" alt="e2efee00571e384bfef90939e26ed1c8.png" width="589" height="247" class="jop-noMdConv">

使用githack导出站点源码

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/0fea32b86d507fac48243631a4075cf1.png" alt="0fea32b86d507fac48243631a4075cf1.png" width="623" height="125" class="jop-noMdConv">

查看其中二进制程序

```sh
└─$ ./magick -version
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype jbig jng jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (7.5)
```

发现是ImageMagick 7.1.0-49，查找发现存在CVE-2022-44268漏洞，如下

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/36dc8986711e3295a9497a725d8f9419.png" alt="36dc8986711e3295a9497a725d8f9419.png" width="486" height="65" class="jop-noMdConv">

尝试利用该漏洞，`https://github.com/Sybil-Scan/imagemagick-lfi-poc`

生成一个带恶意命令的图片并上传，等到存在漏洞的ImageMagick程序执行命令后，再下载被转换后包含有命令执行结果的图片到本地进行解析

审计代码可以发现在登录成功跳转首页后会连接数据库`$db = new PDO('sqlite:/var/db/pilgrimage');`

则生成如下命令图片

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/0b9312969c539780200c355ae79bf0b0.png" alt="0b9312969c539780200c355ae79bf0b0.png" width="588" height="191" class="jop-noMdConv">

接下来开始利用漏洞

读取下载的文件

`identify -verbose 64bd24f347fd2.png`

使用CyberChef解码读取的数据`https://gchq.github.io/CyberChef`

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/81d9b8149e9fedbf5482b9457c882fbc.png" alt="81d9b8149e9fedbf5482b9457c882fbc.png" width="628" height="289" class="jop-noMdConv">

发现一个帐号密码，还是使用xxd转换一下sqlite数据库格式

将图片文件中二进制段的数据单独保存为一个txt文件`b.txt`

再使用xxd将其转换为.sqlite文件

`xxd -r -p b.txt data.sqlite`

使用sqlite3读取文件并`.dump`

![4cc11a27023942444367b65ad08527e9.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/4cc11a27023942444367b65ad08527e9.png)

得到`emily/abigchonkyboi123`

ssh使用该账号密码成功连接

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/848985a97478c7f3ae0084ae2d0f17cb.png" alt="848985a97478c7f3ae0084ae2d0f17cb.png" width="587" height="247" class="jop-noMdConv">

得到user flag

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/542f6938637a458610702eeb4c6ee0af.png" alt="542f6938637a458610702eeb4c6ee0af.png" width="390" height="86" class="jop-noMdConv">

接下来尝试提权得到root flag

sudo不可用

```sh
emily@pilgrimage:/$ sudo -l
[sudo] password for emily: 
Sorry, user emily may not run sudo on pilgrimage.
```

`ps -aux`查看后台进程发现一个shell脚本在以root身份运行

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/411472798f3d50774ce993dd9c20a85a.png" alt="411472798f3d50774ce993dd9c20a85a.png" width="700" height="123" class="jop-noMdConv">

查看该shell脚本

```sh
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
        filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
        binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
                if [[ "$binout" == *"$banned"* ]]; then
                        /usr/bin/rm "$filename"
                        break
                fi
        done
done
```

发现该shell脚本中有两个bin文件执行，依次查看

`/usr/bin/inotifywait` 没发现啥有价值的

`/usr/local/bin/binwalk`

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/8f2898bc92fa3b13df7a04f1c8d40640.png" alt="8f2898bc92fa3b13df7a04f1c8d40640.png" width="552" height="131" class="jop-noMdConv">

发现binwalk 为V2.3.2的版本，查找发现有(CVE-2022-4510)RCE漏洞

执行exp脚本会生成一个图片马，将其上传复制到`/var/www/pilgrimage.htb/shrunk/`目录下

`https://www.exploit-db.com/exploits/51249`

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/ee64040402b0899ac6baad5454a677c6.png" alt="ee64040402b0899ac6baad5454a677c6.png" width="665" height="318" class="jop-noMdConv">

![db07c1912730ada6140a78d5f7951b41.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/db07c1912730ada6140a78d5f7951b41.png)

![20d48b52fdb12b80a5bcf9db08953f0d.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/20d48b52fdb12b80a5bcf9db08953f0d.png)

本地开启对应端口监听

![c3e6277f89258a141aba8ceecab8726d.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/c3e6277f89258a141aba8ceecab8726d.png)

成功获得反弹shell及root flag