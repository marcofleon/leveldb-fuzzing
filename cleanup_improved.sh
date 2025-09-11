#!/bin/bash

TMP_DIR="/tmp"
DB_PATTERN="testdb_*"
KEEP_N=120
SLEEP_INTERVAL=1
PARALLEL_JOBS=8

echo "Starting cleanup script."
echo "  Watching: $TMP_DIR, keeping <= $KEEP_N directories."
echo "  Using $PARALLEL_JOBS parallel jobs for cleanup."

check_and_delete_if_orphan() {
    local dir="$1"
    
    if [ ! -d "$dir" ]; then
        return
    fi

    local pid_part=$(basename "$dir")
    pid_part=${pid_part#testdb_}
    local pid=${pid_part%%_*}

    if [[ "$pid" =~ ^[0-9]+$ ]] && ! kill -0 "$pid" 2>/dev/null; then
        # echo "Orphan detected for dead PID $pid. Removing: $dir"
        rm -rf "$dir"
    fi
}

export -f check_and_delete_if_orphan

while true; do
  count=$(find "$TMP_DIR" -maxdepth 1 -type d -name "$DB_PATTERN" 2>/dev/null | wc -l)

  if [[ "$count" -gt "$KEEP_N" ]]; then
    echo "Found $count directories (limit $KEEP_N). Starting orphan cleanup..."

    find "$TMP_DIR" -maxdepth 1 -type d -name "$DB_PATTERN" -print0 | \
        xargs -0 -r -n 1 -P "$PARALLEL_JOBS" bash -c 'check_and_delete_if_orphan "$@"' _
  fi

  sleep "$SLEEP_INTERVAL"
done
