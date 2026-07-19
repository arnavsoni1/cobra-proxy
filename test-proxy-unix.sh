#!/usr/bin/env bash

set -Eeuo pipefail

expected_os="${1:-}"
case "$expected_os" in
	linux|macos) ;;
	*)
		echo "usage: $0 <linux|macos>" >&2
		exit 2
		;;
esac

actual_os="$(uname -s)"
case "$expected_os:$actual_os" in
	linux:Linux|macos:Darwin) ;;
	*)
		echo "error: requested $expected_os test on unsupported host $actual_os" >&2
		exit 2
		;;
esac

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir"

for command_name in cargo curl; do
	if ! command -v "$command_name" >/dev/null 2>&1; then
		echo "error: required command not found: $command_name" >&2
		exit 2
	fi
done

proxy_url="${PROXY_URL:-http://127.0.0.1:8080}"
tor_check_url="${TOR_CHECK_URL:-https://check.torproject.org/api/ip}"
startup_timeout_seconds="${PROXY_START_TIMEOUT_SECONDS:-180}"
request_timeout_seconds="${PROXY_REQUEST_TIMEOUT_SECONDS:-90}"
metrics_timeout_seconds="${PROXY_METRICS_TIMEOUT_SECONDS:-35}"
test_tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/proxy-smoke.XXXXXX")"
proxy_log="$test_tmpdir/proxy.log"
proxy_pid=""

cleanup() {
	if [[ -n "$proxy_pid" ]] && kill -0 "$proxy_pid" 2>/dev/null; then
		kill "$proxy_pid" 2>/dev/null || true
		wait "$proxy_pid" 2>/dev/null || true
	fi
	rm -rf -- "$test_tmpdir"
}
trap cleanup EXIT INT TERM

show_proxy_log() {
	echo
	echo "--- proxy log ---"
	if [[ -f "$proxy_log" ]]; then
		tail -n 100 "$proxy_log"
	else
		echo "(no proxy log was created)"
	fi
}

wait_for_proxy() {
	local deadline=$((SECONDS + startup_timeout_seconds))
	while (( SECONDS < deadline )); do
		if ! kill -0 "$proxy_pid" 2>/dev/null; then
			echo "error: proxy exited before becoming ready" >&2
			show_proxy_log
			exit 1
		fi
		if (exec 3<>/dev/tcp/127.0.0.1/8080) 2>/dev/null; then
			exec 3>&-
			exec 3<&-
			return 0
		fi
		sleep 1
	done

	echo "error: proxy did not listen on 127.0.0.1:8080 within ${startup_timeout_seconds}s" >&2
	show_proxy_log
	exit 1
}

echo "==> Checking, testing, and building on $actual_os"
cargo check --locked
cargo test --locked
cargo build --release --locked

echo "==> Starting proxy"
"$script_dir/target/release/proxy" >"$proxy_log" 2>&1 &
proxy_pid=$!
wait_for_proxy

echo "==> Verifying Tor routing through $proxy_url"
set +e
tor_response="$(curl \
	--fail \
	--silent \
	--show-error \
	--retry 2 \
	--max-time "$request_timeout_seconds" \
	--proxy "$proxy_url" \
	"$tor_check_url")"
curl_status=$?
set -e

if (( curl_status != 0 )); then
	echo "error: Tor check request failed with curl status $curl_status" >&2
	show_proxy_log
	exit 1
fi

compact_response="$(printf '%s' "$tor_response" | tr -d '[:space:]')"
if [[ "$compact_response" != *'"IsTor":true'* ]]; then
	echo "error: Tor Check did not report IsTor=true" >&2
	echo "response: $tor_response" >&2
	show_proxy_log
	exit 1
fi

echo "Tor Check response: $tor_response"
echo "==> Waiting for the periodic scheduler metrics sample"
metrics_deadline=$((SECONDS + metrics_timeout_seconds))
while (( SECONDS < metrics_deadline )); do
	if grep -Eq 'permits_in_use=0.*circuit_build_count=[1-9][0-9]*' "$proxy_log"; then
		break
	fi
	sleep 1
done

if ! grep -Eq 'permits_in_use=0.*circuit_build_count=[1-9][0-9]*' "$proxy_log"; then
	echo "error: no completed circuit-build metrics sample appeared within ${metrics_timeout_seconds}s" >&2
	show_proxy_log
	exit 1
fi

echo "==> Native $expected_os smoke test passed"
grep 'circuit metrics:' "$proxy_log" | tail -n 3

