#!/bin/bash
cd "$(dirname "$0")"
rm -f .git/index.lock .git/HEAD.lock .git/MERGE_HEAD.lock 2>/dev/null
git add .
git diff --cached --quiet && echo "没有改动，无需推送。" && exit 0
git commit -m "update $(date '+%Y-%m-%d %H:%M')"
git push && echo "✅ 推送成功！" || echo "❌ 推送失败，请检查网络。"
