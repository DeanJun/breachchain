#!/usr/bin/env sh
# Fetches only the atomics/ folder of the real Atomic Red Team repository
# via a blobless sparse checkout, so we don't pull its full history/assets.
# Run from the repo root: sh scripts/fetch_atomics.sh
set -e

REPO_URL="https://github.com/redcanaryco/atomic-red-team.git"
DEST="vendor/atomic-red-team"

mkdir -p vendor

if [ -d "$DEST/.git" ]; then
  echo "Already cloned at $DEST, pulling latest atomics/ ..."
  git -C "$DEST" pull --depth=1 origin main
else
  git clone --filter=blob:none --sparse "$REPO_URL" "$DEST"
  git -C "$DEST" sparse-checkout set atomics
fi

echo "Done. atomics/ is at $DEST/atomics"
