#!/usr/bin/env bash
# Pull all docker-library/php images needed for the dataset (priority-1 pass).
set -u
cd "$(dirname "$0")/.." || exit 1
mkdir -p work/logs
: > work/logs/docker-pull.log
for v in 8.1 8.2 8.3 8.4 8.5; do
  for s in apache fpm cli; do
    t="php:${v}-${s}"
    echo "=== pulling ${t}" >> work/logs/docker-pull.log
    if docker pull -q "$t" >> work/logs/docker-pull.log 2>&1; then
      echo "OK ${t}" >> work/logs/docker-pull.log
    else
      echo "FAIL ${t}" >> work/logs/docker-pull.log
    fi
  done
done
echo "ALL_PULLS_DONE" >> work/logs/docker-pull.log
