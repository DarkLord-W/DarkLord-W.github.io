# 迁移后图片可达性校验

校验方式：对文档里出现的每个图床 URL 发起 HTTP HEAD（并发 6，最多重试 3 次），
目标域为 `gcore.jsdelivr.net`。

## 结果

| 项 | 值 |
|---|---|
| 校验 URL 总数 | 242 |
| HTTP 200 | 242 |
| 非 200 | 0 |
| 平均体积 | 244 KB |
| 体量合计 | 57.7 MB |

全部通过，无失败项。

逐条明细见 `verify.csv`（含 status / bytes / url / 引用该 URL 的文件）。

## 复现命令

```bash
python3 tools/fix_image_cdn.py --verify --workers 6 --retries 3 \
  --report _records/2026-10-25-cdn-migration/verify.csv
```
