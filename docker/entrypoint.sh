#!/bin/sh
set -e

# Create default config on first run
if [ ! -f /data/config/config.yaml ]; then
  cp /app/config.default.yaml /data/config/config.yaml
  echo "Created default config at /data/config/config.yaml — add users to get started."
fi

# Tighten key-file permissions (bind mounts may reset them)
if [ -d /data/keys ] && [ "$(ls -A /data/keys 2>/dev/null)" ]; then
  chmod 700 /data/keys
  find /data/keys -type f -exec chmod 600 {} + 2>/dev/null || true
fi

exec githttps-proxy "$@"
