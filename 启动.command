#!/bin/zsh
cd "${0:A:h}"
demo_port="${JEV_DEMO_PORT:-8765}"
demo_url="http://127.0.0.1:${demo_port}"
if /usr/bin/curl -fsS --max-time 2 "${demo_url}/api/meta" >/dev/null 2>&1; then
  open "$demo_url"
  exit 0
fi
python3 server.py &
demo_pid=$!
trap 'kill "$demo_pid" 2>/dev/null' EXIT INT TERM
for attempt in {1..30}; do
  if /usr/bin/curl -fsS --max-time 1 "${demo_url}/api/meta" >/dev/null 2>&1; then
    open "$demo_url"
    break
  fi
  sleep 0.2
done
wait "$demo_pid"
