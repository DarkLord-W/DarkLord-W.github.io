"""构建期统计钩子。

Markdown 里写 {{stats:KEY}}，构建时替换成按 docs/ 实际文件算出来的值，
避免「50 篇」「12 个仓库」这类数字写死后过期。

支持的 KEY：
  total              全站文章数（不含各目录的 index.md）
  groups             笔记分区数（有 index.md 的栏目目录，排除 notes/projects/about）
  repo               项目卡片数（数 projects/index.md 里的 `-   __名字__` 卡片）
  notes-line         「50 篇 · Pwn 29 / BUUCTF 10 / …」，分区名取各 index.md 的一级标题
  repos-line         「12 个仓库：dwm、cicflowmeter-mg、appimage-manager、IoT-Pwn-Setup 等。」
  <路径>              docs 下该目录的文章数，如 {{stats:pwn}}、{{stats:BUUCTF/Web}}
"""

from __future__ import annotations

import re
from pathlib import Path

DOCS = Path(__file__).resolve().parent / "docs"
PLACEHOLDER = re.compile(r"\{\{\s*stats:([A-Za-z0-9_/\-:]+)\s*\}\}")
CARD_RE = re.compile(r"^- {3}__(.+?)__\s*$", re.M)

# 栏目目录（不计入笔记分区）
NON_SECTIONS = {"notes", "projects", "about"}

_cache: dict[str, object] = {}


# 这些目录下的 md 是站点自身的辅助页面，不算文章
NON_CONTENT_DIRS = {"assets", "javascripts", "stylesheets"}


def _articles(directory: Path) -> list[Path]:
    root = DOCS
    out = []
    for p in directory.rglob("*.md"):
        if p.name == "index.md":
            continue
        parts = p.relative_to(root).parts
        if parts and parts[0] in NON_CONTENT_DIRS:
            continue
        out.append(p)
    return out


def _count(rel: str) -> int:
    target = DOCS if rel in ("", ".") else DOCS / rel
    if not target.is_dir():
        return 0
    return len(_articles(target))


def _heading(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return path.parent.name


def _sections() -> list[tuple[str, int]]:
    if "sections" not in _cache:
        groups = []
        for idx in sorted(DOCS.glob("*/index.md")):
            name = idx.parent.name
            if name in NON_SECTIONS:
                continue
            groups.append((_heading(idx), _count(name)))
        groups.sort(key=lambda item: (-item[1], item[0]))
        _cache["sections"] = groups
    return _cache["sections"]  # type: ignore[return-value]


def _repos() -> list[str]:
    path = DOCS / "projects" / "index.md"
    if not path.is_file():
        return []
    return CARD_RE.findall(path.read_text(encoding="utf-8"))


def _nav_sections() -> dict[str, list[str]]:
    """从 nav 里解析每个分区目录下的子分组名（或页面标题）。"""
    if "nav_sections" in _cache:
        return _cache["nav_sections"]  # type: ignore[return-value]

    result: dict[str, list[str]] = {}
    nav = _cache.get("nav") or []

    def walk(node) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item)
            return
        if not isinstance(node, dict):
            return
        for _title, value in node.items():
            if isinstance(value, list):
                first = value[0] if value else None
                if isinstance(first, str) and first.endswith("/index.md"):
                    section_dir = first[: -len("/index.md")]
                    groups: list[str] = []
                    for child in value[1:]:
                        if isinstance(child, dict):
                            groups.append(next(iter(child)))
                        elif isinstance(child, str):
                            groups.append(Path(child).stem)
                    result[section_dir] = groups
                walk(value)

    walk(nav)
    _cache["nav_sections"] = result
    return result


def _summary(rel: str) -> str:
    """「N 篇 · 子分组名」——分组名取自 nav，篇数取自实际文件数。"""
    groups = list(_nav_sections().get(rel, []))
    n = _count(rel)
    if len(groups) > 4:
        return "%d 篇 · %s 等" % (n, "、".join(groups[:3]))
    return "%d 篇 · %s" % (n, "、".join(groups)) if groups else "%d 篇" % n


def _values() -> dict[str, str]:
    if "values" in _cache:
        return _cache["values"]  # type: ignore[return-value]

    groups = _sections()
    repos = _repos()
    total = _count("")

    values = {
        "total": str(total),
        "groups": str(len(groups)),
        "repo": str(len(repos)),
        # 分组名列全，数字只给总数与组数，避免卡片里堆一串 / 分隔的数字
        "notes-line": "%d 篇，按 %s 分 %d 组。" % (
            total,
            "、".join(title for title, _ in groups),
            len(groups),
        ),
        "notes-detail": "%d 篇 · %s" % (
            total,
            " / ".join("%s %d" % (title, n) for title, n in groups),
        ),
        "repos-line": "%d 个仓库：%s%s" % (
            len(repos),
            "、".join(repos[:4]),
            " 等。" if len(repos) > 4 else "。",
        ),
    }
    _cache["values"] = values
    return values


def _replace(markdown: str) -> str:
    values = _values()

    def repl(match: re.Match[str]) -> str:
        key = match.group(1)
        if key in values:
            return values[key]
        if key.startswith("summary:"):
            return _summary(key[len("summary:"):])
        # 目录路径形式：{{stats:pwn}} / {{stats:BUUCTF/Web}}
        return str(_count(key))

    return PLACEHOLDER.sub(repl, markdown)


def on_pre_build(config) -> None:
    # mkdocs serve 会在同进程反复构建，每次构建前清缓存
    _cache.clear()
    _cache["nav"] = config.get("nav") or []


def on_page_markdown(markdown: str, page, config, files) -> str:
    return _replace(markdown)
