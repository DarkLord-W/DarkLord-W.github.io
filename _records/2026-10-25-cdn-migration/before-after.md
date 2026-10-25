# 替换前后对照（抽样）

三类写法各取一例，均为 `git diff` 原文。

## 1. Markdown 图片语法 + gitmirror 旧域

`docs/BUUCTF/Web/HCTF 2018WarmUp.md`

```diff
-![image.png](https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/20251020163225299.png)
+![image.png](https://gcore.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/20251020163225299.png)
```

## 2. 嵌在标题里的图片（Joplin 导出特征）

`docs/web/ATTCK红队评估01.md`

```diff
-### ![71844d4b6f701996110fbfee4665d6fc.png](https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/71844d4b6f701996110fbfee4665d6fc.png)
+### ![71844d4b6f701996110fbfee4665d6fc.png](https://gcore.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/71844d4b6f701996110fbfee4665d6fc.png)
```

## 3. HTML img 标签（带 width/height/class）

`docs/pwn/Protostar_stack4.md`

```diff
-<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/ccb9efc32f7aa26df31421d720649538.png" alt="ccb9efc32f7aa26df31421d720649538.png" width="554" height="89" class="jop-noMdConv">
+<img src="https://gcore.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/ccb9efc32f7aa26df31421d720649538.png" alt="ccb9efc32f7aa26df31421d720649538.png" width="554" height="89" class="jop-noMdConv">
```

## 收尾核对

```
$ grep -rlE 'cdn\.jsdelivr\.net|raw\.gitmirror\.com|fastly\.jsdelivr|jsd\.onmicrosoft' docs --include=*.md | wc -l
0

$ grep -roE 'https://gcore\.jsdelivr\.net/gh/DarkLord-W/CloudImages@main/images/[^)"]+' docs --include=*.md | wc -l
241
```
