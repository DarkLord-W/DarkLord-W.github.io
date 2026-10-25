#!/usr/bin/env bash
#
# 提交并推送本站点。
#
# 默认走 SSH（本机到 github.com 的 HTTPS 是断的，见 _records 里的实测）；
# 需要走 HTTPS + token 时加 --https。SSH 22 端口不通时可加 --ssh443。
#
# 用法：
#   ./auto_push.sh                  # SSH，交互确认
#   ./auto_push.sh --yes            # 跳过确认
#   ./auto_push.sh --ssh443         # SSH over 443（github.com:22 被挡时）
#   ./auto_push.sh --https          # HTTPS + Personal Access Token
#   ./auto_push.sh --tags           # 同时推标签
#   ./auto_push.sh --dry-run        # 只显示将要提交的内容，不提交不推送
#
set -euo pipefail

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; NC=$'\033[0m'

MODE="ssh"
ASSUME_YES=0
PUSH_TAGS=0
DRY_RUN=0
ALLOW_LARGE=0
BRANCH=""
MAX_FILE_MB=5

while [ $# -gt 0 ]; do
  case "$1" in
    --https)     MODE="https" ;;
    --ssh443)    MODE="ssh443" ;;
    --yes|-y)    ASSUME_YES=1 ;;
    --tags)      PUSH_TAGS=1 ;;
    --dry-run)   DRY_RUN=1 ;;
    --allow-large) ALLOW_LARGE=1 ;;
    --branch)    shift; BRANCH="${1:?--branch 需要参数}" ;;
    -h|--help)   sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "${RED}未知参数：$1${NC}"; exit 2 ;;
  esac
  shift
done

say()  { echo "${GREEN}$*${NC}"; }
warn() { echo "${YELLOW}$*${NC}"; }
die()  { echo "${RED}$*${NC}" >&2; exit 1; }

# ---------- 1. 基本检查 ----------
git rev-parse --git-dir > /dev/null 2>&1 || die "当前目录不是 git 仓库"

if [ -z "$(git config user.name)" ]; then
  read -r -p "请输入 git 用户名: " name; git config user.name "$name"
fi
if [ -z "$(git config user.email)" ]; then
  read -r -p "请输入 git 邮箱: " mail; git config user.email "$mail"
fi

REMOTE_URL=$(git remote get-url origin 2>/dev/null) || die "未找到远程仓库 origin"
[[ $REMOTE_URL =~ github\.com[:/]([^/]+)/([^/]+)$ ]] || die "无法解析 GitHub 仓库地址：$REMOTE_URL"
OWNER="${BASH_REMATCH[1]}"
REPO="${BASH_REMATCH[2]%.git}"

BRANCH="${BRANCH:-$(git rev-parse --abbrev-ref HEAD)}"
[ "$BRANCH" = "HEAD" ] && die "当前处于分离头指针状态，请先切到分支"

echo "仓库   $OWNER/$REPO"
echo "分支   $BRANCH"
echo "推送   $MODE"
echo

# ---------- 2. 传输方式与超时 ----------
# 本机到 github.com 的 HTTPS 会挂死，SSH 无密钥时会弹密码——统一关掉交互并设超时
export GIT_TERMINAL_PROMPT=0
FETCH_TIMEOUT=${FETCH_TIMEOUT:-20}
PUSH_TIMEOUT=${PUSH_TIMEOUT:-180}

PUSH_URL=$(
  case "$MODE" in
    ssh)    echo "git@github.com:$OWNER/$REPO.git" ;;
    ssh443) echo "ssh://git@ssh.github.com:443/$OWNER/$REPO.git" ;;
    https)  echo "https://github.com/$OWNER/$REPO.git" ;;
  esac
)

case "$MODE" in
  ssh|ssh443)
    export GIT_SSH_COMMAND="ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new"
    ;;
esac

# ---------- 3. 先 fetch（走和 push 相同的传输），判断远端是否领先 ----------
say "拉取远端状态…"
if timeout "$FETCH_TIMEOUT" git fetch --prune "$PUSH_URL" \
     "+refs/heads/$BRANCH:refs/remotes/origin/$BRANCH" > /dev/null 2>&1; then
  say "远端状态已更新"
else
  warn "fetch 失败或超时（${FETCH_TIMEOUT}s），跳过「远端是否领先」检查"
fi

# ---------- 4. 暂存 ----------
if [ -z "$(git status --porcelain)" ]; then
  warn "没有检测到任何更改，退出。"
  exit 0
fi

say "检测到以下更改："
git status --short
echo

git add -A

# 大文件护栏
if [ "$ALLOW_LARGE" -eq 0 ]; then
  big=$(git diff --cached --name-only --diff-filter=ACM \
        | xargs -r -I{} sh -c 'f="{}"; [ -f "$f" ] && s=$(stat -c%s "$f") && [ "$s" -gt '"$((MAX_FILE_MB*1024*1024))"' ] && echo "$s $f"' 2>/dev/null || true)
  if [ -n "$big" ]; then
    echo "${RED}以下文件超过 ${MAX_FILE_MB} MB：${NC}"
    echo "$big" | awk '{printf "  %.1f MB  %s\n", $1/1048576, $2}'
    die "如确认要提交，加 --allow-large 重跑"
  fi
fi

say "本次将提交："
git diff --cached --stat
echo

if [ "$DRY_RUN" -eq 1 ]; then
  git reset -q    # 撤销刚才为了算统计做的暂存，保持工作区原样
  warn "dry-run：不提交、不推送。"
  exit 0
fi

if [ "$ASSUME_YES" -eq 0 ]; then
  read -r -p "继续提交并推送？[y/N] " ok
  [[ $ok =~ ^[Yy]$ ]] || { warn "已取消。"; exit 0; }
fi

# ---------- 5. 提交 ----------
read -r -p "提交信息（留空用默认）: " msg
[ -z "$msg" ] && msg="Update: $(date '+%Y-%m-%d %H:%M:%S')"

git commit -q -m "$msg"
say "已提交：$(git log -1 --format='%h %s')"
echo

# ---------- 6. 远端领先就不推 ----------
if git rev-parse --verify -q "origin/$BRANCH" > /dev/null; then
  behind=$(git rev-list --count "HEAD..origin/$BRANCH")
  if [ "$behind" -gt 0 ]; then
    die "远端 $BRANCH 比你多 $behind 个提交，先 git pull --rebase 再推（本脚本不做强制推送）"
  fi
fi

# ---------- 7. 推送 ----------
REFSPEC="$BRANCH:$BRANCH"
[ "$PUSH_TAGS" -eq 1 ] && REFSPEC="$REFSPEC"   # 标签单独再推

say "推送到 $MODE …"
set +e
if [ "$MODE" = "https" ]; then
  # 不走 URL 内嵌 token，改用 GIT_ASKPASS 临时脚本，避免 ps 里看到明文
  read -r -s -p "GitHub Personal Access Token: " TOKEN; echo
  [ -z "$TOKEN" ] && die "token 为空"

  ASKPASS=$(mktemp)
  cat > "$ASKPASS" <<'EOS'
#!/bin/sh
case "$1" in
  *Username*) printf '%s\n' "$GIT_USERNAME" ;;
  *Password*) printf '%s\n' "$GIT_TOKEN" ;;
esac
EOS
  chmod 700 "$ASKPASS"
  trap 'rm -f "$ASKPASS"' EXIT

  timeout "$PUSH_TIMEOUT" env GIT_TERMINAL_PROMPT=0 GIT_ASKPASS="$ASKPASS" \
    GIT_USERNAME="$(git config user.name)" GIT_TOKEN="$TOKEN" \
    git push "$PUSH_URL" "$REFSPEC"
  rc=$?
else
  timeout "$PUSH_TIMEOUT" git push "$PUSH_URL" "$REFSPEC"
  rc=$?
fi
set -e

if [ "$rc" -ne 0 ]; then
  echo
  case "$MODE" in
    ssh)    warn "SSH 22 端口可能被挡。试试：./auto_push.sh --ssh443" ;;
    ssh443) warn "检查 ~/.ssh 里是否有密钥、且公钥已加到 GitHub" ;;
    https)  warn "HTTPS 到 github.com 在本机不通，token 正确也会失败；建议改用 SSH" ;;
  esac
  die "推送失败（退出码 $rc）"
fi

if [ "$PUSH_TAGS" -eq 1 ]; then
  say "推送标签…"
  timeout "$PUSH_TIMEOUT" git push "$PUSH_URL" --tags
fi

# ---------- 8. 刷新远端引用，避免 git status 一直显示 ahead ----------
timeout "$FETCH_TIMEOUT" git fetch "$PUSH_URL" "+refs/heads/$BRANCH:refs/remotes/origin/$BRANCH" > /dev/null 2>&1 && \
  git branch --set-upstream-to="origin/$BRANCH" "$BRANCH" > /dev/null 2>&1 || true

echo
say "推送成功。"
