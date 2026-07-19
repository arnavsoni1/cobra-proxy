#!/usr/bin/env bash

set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir"

requests=64
concurrency=40
target_url="https://example.com/"
proxy_url="${PROXY_URL:-http://127.0.0.1:8080}"
startup_timeout_seconds="${PROXY_START_TIMEOUT_SECONDS:-180}"
request_timeout_seconds="${PROXY_REQUEST_TIMEOUT_SECONDS:-90}"
start_proxy=1
run_scheduler_tests=1

usage() {
	cat <<'USAGE'
Usage: ./stress-test.sh [options]

Options:
  --requests N           Total requests (default: 64)
  --concurrency N        Parallel requests (default: 40; maximum: 64)
  --url URL              HTTPS target (default: https://example.com/)
  --proxy-url URL        Proxy URL (default: http://127.0.0.1:8080)
  --use-running-proxy    Do not build or start a proxy process
  --skip-scheduler-tests Skip the deterministic scheduler unit tests
  -h, --help             Show this help

Set ALLOW_HIGH_TOR_LOAD=1 to exceed the default safety limits of 512 requests
or 64 concurrent requests. Use high values only against infrastructure you own.
USAGE
}

while (( $# > 0 )); do
	case "$1" in
		--requests)
			requests="${2:?missing value for --requests}"
			shift 2
			;;
		--concurrency)
			concurrency="${2:?missing value for --concurrency}"
			shift 2
			;;
		--url)
			target_url="${2:?missing value for --url}"
			shift 2
			;;
		--proxy-url)
			proxy_url="${2:?missing value for --proxy-url}"
			shift 2
			;;
		--use-running-proxy)
			start_proxy=0
			shift
			;;
		--skip-scheduler-tests)
			run_scheduler_tests=0
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "error: unknown option: $1" >&2
			usage >&2
			exit 2
			;;
	esac
done

if [[ ! "$requests" =~ ^[1-9][0-9]*$ ]] || [[ ! "$concurrency" =~ ^[1-9][0-9]*$ ]]; then
	echo "error: requests and concurrency must be positive integers" >&2
	exit 2
fi

if (( concurrency > requests )); then
	concurrency=$requests
fi

if [[ "${ALLOW_HIGH_TOR_LOAD:-0}" != 1 ]] && (( requests > 512 || concurrency > 64 )); then
	echo "error: requested load exceeds the safety limit" >&2
	echo "Set ALLOW_HIGH_TOR_LOAD=1 only when the target infrastructure can handle it." >&2
	exit 2
fi

for command_name in cargo curl; do
	if ! command -v "$command_name" >/dev/null 2>&1; then
		echo "error: required command not found: $command_name" >&2
		exit 2
	fi
done

test_tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/proxy-stress.XXXXXX")"
result_dir="$test_tmpdir/results"
proxy_log="$test_tmpdir/proxy.log"
mkdir -p "$result_dir"
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
	if [[ -n "$proxy_pid" ]] && [[ -f "$proxy_log" ]]; then
		echo
		echo "--- proxy log ---"
		tail -n 100 "$proxy_log"
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

if (( run_scheduler_tests )); then
	echo "==> Running deterministic scheduler tests"
	cargo test --locked circuit_ -- --nocapture
fi

if (( start_proxy )); then
	echo "==> Checking and building the release proxy"
	cargo check --locked
	cargo build --release --locked

	echo "==> Starting proxy"
	"$script_dir/target/release/proxy" >"$proxy_log" 2>&1 &
	proxy_pid=$!
	wait_for_proxy
else
	echo "==> Using already-running proxy at $proxy_url"
fi

echo "==> Sending $requests requests with concurrency $concurrency"
echo "    target: $target_url"
echo "    proxy:  $proxy_url"
started_at=$SECONDS

for ((request_id = 1; request_id <= requests; request_id++)); do
	(
		set +e
		http_code="$(curl \
			--silent \
			--show-error \
			--max-time "$request_timeout_seconds" \
			--output "$result_dir/$request_id.body" \
			--write-out '%{http_code}' \
			--proxy "$proxy_url" \
			"$target_url" 2>"$result_dir/$request_id.stderr")"
		curl_status=$?
		printf '%s %s\n' "$curl_status" "${http_code:-000}" >"$result_dir/$request_id.status"
	) &

	if (( request_id % concurrency == 0 )); then
		wait
	fi
done
wait

elapsed_seconds=$((SECONDS - started_at))
completed="$(awk 'END { print NR + 0 }' "$result_dir"/*.status)"
successful="$(awk '$1 == 0 && $2 >= 200 && $2 < 400 { count++ } END { print count + 0 }' "$result_dir"/*.status)"
capacity_503="$(awk '$2 == 503 { count++ } END { print count + 0 }' "$result_dir"/*.status)"
other_failures=$((completed - successful - capacity_503))

echo
echo "Stress-test summary"
echo "  completed:             $completed"
echo "  successful HTTP:       $successful"
echo "  scheduler/proxy 503s:  $capacity_503"
echo "  other failures:        $other_failures"
echo "  elapsed seconds:       $elapsed_seconds"

if (( start_proxy )) && ! kill -0 "$proxy_pid" 2>/dev/null; then
	echo "error: proxy exited during the stress test" >&2
	show_proxy_log
	exit 1
fi

if (( other_failures > 0 )); then
	echo "error: requests failed for reasons other than controlled 503 responses" >&2
	echo "status breakdown (curl_status http_status count):" >&2
	awk '{ counts[$1 " " $2]++ } END { for (key in counts) print key, counts[key] }' "$result_dir"/*.status | sort >&2
	show_proxy_log
	exit 1
fi

if (( start_proxy )); then
	metrics_deadline=$((SECONDS + 35))
	while (( SECONDS < metrics_deadline )); do
		if grep -Eq 'circuit_build_count=[1-9][0-9]*' "$proxy_log"; then
			break
		fi
		sleep 1
	done

	if grep -q 'circuit metrics:' "$proxy_log"; then
		echo
		echo "Latest scheduler metrics"
		grep 'circuit metrics:' "$proxy_log" | tail -n 3
	else
		echo "warning: no periodic scheduler metrics sample was captured" >&2
	fi
fi

echo "==> Stress test passed"

