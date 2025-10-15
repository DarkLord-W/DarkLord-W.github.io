**启动靶机，访问目标地址：**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251015163616772.png)

**显示只能本地访问，尝试添加`X-Forwarded-For: 127.0.0.1`:**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251015164255487.png)

**失败，经过搜索，发现还有一个参数：`X-real-ip`**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251015164416025.png)

**可以看到成功绕过限制了，此时将添加了参数的数据包放过，跳转到登陆页面，点击登陆并再次抓包添加参数**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251015164554726.png)

**成功获取flag**
