#!/usr/bin/env python3
"""统一博客文档里的图床加速域名。

背景（2026-10 实测，国内出口）：
  cdn.jsdelivr.net       Connection reset                        -> 不通
  fastly.jsdelivr.net    301 回源 raw.githubusercontent.com     -> 不通
  jsd.onmicrosoft.cn     同上                                   -> 不通
  raw.gitmirror.com      域名 NXDOMAIN                          -> 服务已停
  gcore.jsdelivr.net     200 + 真实图片                         -> 可用
  testingcf.jsdelivr.net 200 + 真实图片                         -> 可用（备用）

用法：
    python3 tools/fix_image_cdn.py                 # 只扫描（dry-run）
    python3 tools/fix_image_cdn.py --apply         # 落盘替换
    python3 tools/fix_image_cdn.py --verify        # 逐个 HEAD 校验
    python3 tools/fix_image_cdn.py --host testingcf.jsdelivr.net --apply
    python3 tools/fix_image_cdn.py --legacy --apply   # 额外处理 ../_resources/
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs"

DEFAULT_HOST = "gcore.jsdelivr.net"
REPO_SLUG = "DarkLord-W/CloudImages"

# 注意：raw.githubusercontent.com 只匹配本仓库自己的图床路径，
# 文档里还有 wget 别人仓库脚本的 raw 链接，不能动。
OLD_HOST_PATTERN = (
    r"(?:"
    r"(?:cdn|fastly|testingcf|gcore)\.jsdelivr\.net/gh"
    r"|jsd\.onmicrosoft\.cn/gh"
    r"|raw\.gitmirror\.com"
    r"|raw\.githubusercontent\.com"
    r")"
)

OLD_CDN_RE = re.compile(
    r"https://" + OLD_HOST_PATTERN + r"/" + re.escape(REPO_SLUG) + r"(?:@main|/main)/images/"
)

OLD_RELATIVE_RE = re.compile(r"\.\./_resources/")

ANY_CDN_RE = re.compile(
    r"https://[^\s)\"'<>]*?/" + re.escape(REPO_SLUG) + r"(?:@main|/main)/images/[^\s)\"'<>]+"
)

BAD_HOST_RE = re.compile(OLD_HOST_PATTERN)


def new_prefix(host: str) -> str:
    return "https://" + host + "/gh/" + REPO_SLUG + "@main/images/"


def iter_markdown(root: Path, only):
    base = root
    if only:
        candidate = (REPO_ROOT / only) if not Path(only).is_absolute() else Path(only)
        if candidate.is_dir():
            base = candidate
        else:
            raise SystemExit("--only 指向的目录不存在: %s" % candidate)
    for path in sorted(base.rglob("*.md")):
        if any(part.startswith(".") for part in path.relative_to(root).parts):
            continue
        yield path


def rewrite_file(path: Path, host: str, legacy: bool, apply: bool):
    original = path.read_text(encoding="utf-8")
    changes = []
    out_lines = []

    for lineno, line in enumerate(original.splitlines(keepends=True), start=1):
        for m in OLD_CDN_RE.finditer(line):
            # 已经是目标前缀的不算变更，保证脚本幂等
            if m.group(0) != new_prefix(host):
                changes.append((lineno, m.group(0), new_prefix(host)))

        new_line = OLD_CDN_RE.sub(new_prefix(host), line)

        if legacy and OLD_RELATIVE_RE.search(new_line):
            changes.append((lineno, "../_resources/", new_prefix(host)))
            new_line = OLD_RELATIVE_RE.sub(new_prefix(host), new_line)

        out_lines.append(new_line)

    updated = "".join(out_lines)
    if apply and updated != original:
        path.write_text(updated, encoding="utf-8")

    return changes


def collect_urls(root: Path, only=None):
    urls = {}
    for path in iter_markdown(root, only):
        for m in ANY_CDN_RE.finditer(path.read_text(encoding="utf-8")):
            urls.setdefault(m.group(0), []).append(str(path.relative_to(REPO_ROOT)))
    return urls


def head_once(url: str, timeout: int = 25):
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "fix-image-cdn/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, int(resp.headers.get("Content-Length") or 0)
    except urllib.error.HTTPError as exc:
        return exc.code, 0
    except Exception:
        return 0, 0


def _check_with_retry(url: str, retries: int):
    status, size = 0, 0
    for attempt in range(retries):
        status, size = head_once(url)
        if status == 200:
            return status, size
        time.sleep(1 + attempt)
    return status, size


def verify(root: Path, only, retries: int, workers: int, report):
    urls = collect_urls(root, only)
    print("待校验 URL：%d 条\n" % len(urls))

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_check_with_retry, u, retries): u for u in urls}
        for fut in concurrent.futures.as_completed(futures):
            url = futures[fut]
            status, size = fut.result()
            results.append((status, size, url))

    results.sort(key=lambda r: (r[0] != 200, r[2]))
    ok = sum(1 for s, _, _ in results if s == 200)
    print("200 OK: %d / %d" % (ok, len(results)))
    bad = [r for r in results if r[0] != 200]
    if bad:
        print("\n非 200 清单：")
        for status, size, url in bad:
            print("  %6s  %s" % (status or "ERR", url))

    if report:
        report.parent.mkdir(parents=True, exist_ok=True)
        with report.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["status", "bytes", "url", "files"])
            for status, size, url in results:
                writer.writerow([status, size, url, ";".join(urls[url])])
        print("\n明细已写入 %s" % report)

    return 0 if not bad else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="博客图床加速域名统一工具")
    parser.add_argument("--apply", action="store_true", help="真正写盘（默认只扫描）")
    parser.add_argument("--verify", action="store_true", help="校验现有 URL 是否可访问")
    parser.add_argument("--host", default=DEFAULT_HOST, help="目标加速域（默认 %s）" % DEFAULT_HOST)
    parser.add_argument("--only", default=None, help="只处理某个子目录，如 docs/pwn")
    parser.add_argument("--legacy", action="store_true", help="同时处理 ../_resources/ 相对路径")
    parser.add_argument("--report", default=None, help="把变更明细写成 CSV")
    parser.add_argument("--retries", type=int, default=3, help="--verify 的重试次数")
    parser.add_argument("--workers", type=int, default=8, help="--verify 的并发数")
    args = parser.parse_args(argv)

    root = DOCS_DIR
    if not root.is_dir():
        raise SystemExit("找不到 docs 目录: %s" % root)

    if args.verify:
        report = Path(args.report) if args.report else None
        return verify(root, args.only, args.retries, args.workers, report)

    all_changes = []
    for path in iter_markdown(root, args.only):
        for lineno, old, new in rewrite_file(path, args.host, args.legacy, args.apply):
            all_changes.append((str(path.relative_to(REPO_ROOT)), lineno, old, new))

    if not all_changes:
        print("没有需要替换的链接。")
        return 0

    files = sorted({c[0] for c in all_changes})
    print("命中 %d 处，分布在 %d 个文件：\n" % (len(all_changes), len(files)))
    for name in files:
        count = sum(1 for c in all_changes if c[0] == name)
        print("  %3d  %s" % (count, name))

    print("\n目标前缀：%s" % new_prefix(args.host))
    print("模式：" + ("已写盘" if args.apply else "dry-run（加 --apply 才写盘）"))

    if args.report:
        report = Path(args.report)
        report.parent.mkdir(parents=True, exist_ok=True)
        with report.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["file", "line", "old_url", "new_url"])
            writer.writerows(all_changes)
        print("明细已写入 %s" % report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
