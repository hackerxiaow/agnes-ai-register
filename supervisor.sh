#!/bin/bash
TARGET=${1:-10000}
DIR=/Users/moe/.zcode/workspace/default/agnes-ai-register
cd "$DIR"
while true; do
  NOW=$(wc -l < "$DIR/keys.txt" 2>/dev/null | tr -d ' ')
  [ -z "$NOW" ] && NOW=0
  if [ "$NOW" -ge "$TARGET" ]; then
    echo "[$(date '+%m-%d %H:%M')] 目标达成 $NOW/$TARGET, 守护退出"
    break
  fi
  REMAIN=$((TARGET - NOW))
  echo "[$(date '+%m-%d %H:%M')] 现有$NOW 目标$TARGET, 启动批次(本轮目标 $REMAIN)"
  env AGNES_PROXY_FILE=/tmp/proxylists/good.txt CREATE_KEY=1 REGISTER_COUNT=$REMAIN THREAD_COUNT=40 \
    /tmp/agnes-venv/bin/python -u register.py >> /tmp/agnes_local_pool.log 2>&1
  echo "[$(date '+%m-%d %H:%M')] 批次退出(码$?), 60秒后自动重启"
  sleep 60
done
