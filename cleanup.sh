#!/bin/bash

TMP_DIR="/tmp"
DB_PATTERN="testdb_*"
KEEP_N=100
SLEEP_INTERVAL=1

echo "Keep newest $KEEP_N directories..."
echo "  Watching directory : $TMP_DIR"
echo "  Matching pattern   : $DB_PATTERN"
echo "  Keeping            : $KEEP_N newest"
echo "  Check interval     : ${SLEEP_INTERVAL} seconds"

while true; do
  count=$(find "$TMP_DIR" -maxdepth 1 -type d -name "$DB_PATTERN" 2>/dev/null | wc -l)

  if [[ "$count" -gt "$KEEP_N" ]]; then
    echo "Found $count directories, exceeding limit of $KEEP_N. Cleaning up..."

    # Use find to print modification time (epoch seconds) and path, NUL-separated
    # %T@ is epoch time, %p is path. Using \0 for safety.
    # Pipe to sort: -z=NUL separator, -k1,1=sort on field 1, n=numeric, r=reverse (newest first)
    # Pipe to tail: -z=NUL separator, +N+1 skips first N lines
    # Pipe to cut: -z=NUL separator, -d' '=space delimiter, -f2-=get field 2 onwards (the path)
    # Pipe to xargs: -0=NUL separator, -r=no-run-if-empty
    find "$TMP_DIR" -maxdepth 1 -type d -name "$DB_PATTERN" -printf '%T@ %p\0' 2>/dev/null | \
      sort -z -k1,1nr | \
      tail -z -n +$((KEEP_N + 1)) | \
      cut -z -d' ' -f2- | \
      xargs -0 -r -- rm -rf
  fi

  sleep "$SLEEP_INTERVAL"
done
