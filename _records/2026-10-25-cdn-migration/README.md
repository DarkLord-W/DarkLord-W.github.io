# 图床加速域名迁移（2026-10-25）

## 为什么要动

博客正文图片托管在 GitHub 仓库 `DarkLord-W/CloudImages`，文档里用第三方加速域引用。到 2026-10，
原来用的两个域都已经不能用：

- `raw.gitmirror.com` 直接 **NXDOMAIN**（阿里 DNS DoH 返回 Status=3），服务已停
- `cdn.jsdelivr.net` 在国内出口被 **TCP reset**，连不上

也就是说不迁移的话，有一半以上的文章是裂图。

## 实测记录

测试机出口：中国移动 陕西西安（111.18.40.3），2026-10-25。

| 加速域 | 解析 | 实测结果 | 判定 |
|---|---|---|---|
| `cdn.jsdelivr.net` | 151.101.1.229 (Fastly) | Connection reset，HTTP 000 | 不通 |
| `gcore.jsdelivr.net` | Cloudflare 104.17.x | HTTP 200，image/png，0.4s | **采用** |
| `testingcf.jsdelivr.net` | Cloudflare | HTTP 200，image/png | 备用 |
| `fastly.jsdelivr.net` | 151.101.193.229 | 301 → `raw.githubusercontent.com` | 不通 |
| `jsd.onmicrosoft.cn` | 183.230.68.100 | 301 → `raw.githubusercontent.com` | 不通 |
| `raw.gitmirror.com` | 无解析 | — | 服务已停 |
| `raw.githubusercontent.com` | 185.199.111.133 | Connection reset | 不通 |
| `gh-proxy.com/<原始 raw 地址>` | — | HTTP 200，1.4s | 兜底 |
| `ghproxy.net/<原始 raw 地址>` | — | HTTP 200，12.3s | 太慢，不用 |
| `cdn.statically.io` / `ghfast.top` / `hub.gitmirror.com` | — | 不通 / 超时 | 不用 |

补充两点：

1. `fastly.jsdelivr.net` 的 301 不是本地网络问题——同一域名取 npm 资源（`/npm/jquery@3.7.1/...`）返回 200，
   只有 `/gh/` 路径被回源到 `raw.githubusercontent.com`。这是 jsDelivr 自己的策略。
2. 图片本身没有丢失：用 GitHub Tree API 拉 `CloudImages` 全仓，`images/` 下 977 个文件，与文档引用的
   241 个文件名逐一比对，**缺失 0 个**。裂图纯粹是域名问题。

## 改了什么

- 范围：`docs/` 下 **45 个 markdown 文件、241 处图片链接**
- 旧形式（两套语法并存）：
  - `https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/<文件名>`
  - `https://raw.gitmirror.com/DarkLord-W/CloudImages/main/images/<文件名>`
- 新形式（统一）：
  `https://gcore.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/<文件名>`
- 覆盖了两种写法：Markdown `![alt](url)` 和 HTML `<img src="...">`（Joplin 导出会混用，有些图甚至
  嵌在 `###` 标题里）

逐条明细见 `changes.csv`（241 行），校验结果见 `verify.csv` / `verify.md`。

## 怎么改的

`tools/fix_image_cdn.py`，默认 dry-run，只有加 `--apply` 才写盘：

```
python3 tools/fix_image_cdn.py                                  # 只扫描
python3 tools/fix_image_cdn.py --apply                          # 写盘
python3 tools/fix_image_cdn.py --verify --workers 6             # 逐条 HEAD 校验
python3 tools/fix_image_cdn.py --host testingcf.jsdelivr.net --apply   # 换主域
python3 tools/fix_image_cdn.py --legacy --apply                 # 顺带处理 ../_resources/
```

脚本是幂等的：已经是 `gcore` 的链接不会被重复处理。

## 运行时兜底

`docs/javascripts/image-fallback.js` 监听图片 `error`，按
`gcore → testingcf → gh-proxy.com` 三级降级。以后再遇到某个加速域抽风，页面自己救回来，
不需要再全仓替换一次。

## 回滚

```bash
git revert <本阶段 commit>
# 或回到改造前的整体状态
git checkout pre-overhaul-2026-10-25 -- docs
```

## 勘误

规划阶段曾按抽样统计说「29 个文件」，实测为 **45 个文件**（`grep -rl` 与脚本输出一致）。
以本目录的 `changes.csv` 为准。
