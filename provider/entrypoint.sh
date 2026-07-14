#!/usr/bin/env bash
# install.sh: start_ollama_background() + "Pulling model" step, made
# non-interactive and idempotent so it's safe to run on every container
# start (ollama itself skips the download when the model is already
# cached in the /root/.ollama volume).
set -euo pipefail

ollama serve >/var/log/ollama.log 2>&1 &

for _ in $(seq 1 30); do
  curl -sf http://localhost:11434/ >/dev/null 2>&1 && break
  sleep 1
done

ollama pull "${COCORE_MODEL}"

exec "$@"
