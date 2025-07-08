#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检查是否在git仓库中
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo -e "${RED}错误：当前目录不是一个git仓库${NC}"
    exit 1
fi

# 获取git配置的用户名
GIT_USERNAME=$(git config user.name)
if [ -z "$GIT_USERNAME" ]; then
    echo -e "${YELLOW}未找到git用户名配置${NC}"
    read -p "请输入你的GitHub用户名: " GIT_USERNAME
    git config user.name "$GIT_USERNAME"
fi

# 获取远程仓库URL
REMOTE_URL=$(git remote get-url origin 2>/dev/null)
if [ -z "$REMOTE_URL" ]; then
    echo -e "${RED}错误：未找到远程仓库${NC}"
    exit 1
fi

# 提取仓库信息
if [[ $REMOTE_URL =~ github.com[:/]([^/]+)/(.+)(\.git)?$ ]]; then
    REPO_OWNER="${BASH_REMATCH[1]}"
    REPO_NAME="${BASH_REMATCH[2]}"
    REPO_NAME="${REPO_NAME%.git}"  # 移除.git后缀
else
    echo -e "${RED}错误：无法解析GitHub仓库URL${NC}"
    exit 1
fi

echo -e "${GREEN}仓库信息：${NC}"
echo "用户名: $GIT_USERNAME"
echo "仓库: $REPO_OWNER/$REPO_NAME"
echo ""

# 检查是否有更改
if [ -z "$(git status --porcelain)" ]; then
    echo -e "${YELLOW}没有检测到任何更改${NC}"
    exit 0
fi

# 显示更改的文件
echo -e "${GREEN}检测到以下更改：${NC}"
git status --short
echo ""

# 添加所有更改
echo -e "${GREEN}执行 git add .${NC}"
git add .

# 获取commit信息
read -p "请输入commit信息 (留空使用默认): " COMMIT_MSG
if [ -z "$COMMIT_MSG" ]; then
    COMMIT_MSG="Update: $(date '+%Y-%m-%d %H:%M:%S')"
fi

# 提交更改
echo -e "${GREEN}执行 git commit${NC}"
git commit -m "$COMMIT_MSG"

# 获取token
echo ""
read -s -p "请输入你的GitHub Personal Access Token: " GITHUB_TOKEN
echo ""

# 构建带认证的URL
AUTH_URL="https://${GIT_USERNAME}:${GITHUB_TOKEN}@github.com/${REPO_OWNER}/${REPO_NAME}.git"

# 推送到远程仓库
echo -e "${GREEN}执行 git push${NC}"
if git push $AUTH_URL main 2>/dev/null || git push $AUTH_URL master 2>/dev/null; then
    echo -e "${GREEN}推送成功！${NC}"
else
    echo -e "${RED}推送失败，请检查token是否正确${NC}"
    exit 1
fi
