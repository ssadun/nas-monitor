#!/usr/bin/env bash
# Run this once before `docker compose up` to set up the persistent data directory.
set -e

mkdir -p data

# Copy default data files only if they don't exist yet
for f in credentials.json category-defs.json category-assignments.json disk-history.json; do
  if [ ! -f "data/$f" ]; then
    cp "$f" "data/$f"
    echo "Initialized data/$f"
  else
    echo "Skipped data/$f (already exists)"
  fi
done

echo ""
echo "Done. Now run:  docker compose up -d"
echo "Dashboard will be at: http://$(hostname -I | awk '{print $1}'):3232"
