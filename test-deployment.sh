#!/usr/bin/env bash

set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir"

mode="local"
proxy_url="${PROXY_URL:-http://127.0.0.1:8080}"
metrics_url="${PROXY_METRICS_URL:-http://127.0.0.1:9090/metrics}"
tor_check_url="${TOR_CHECK_URL:-https://check.torproject.org/api/ip}"
http_test_url="${PROXY_TEST_HTTP_URL:-http://example.com/}"
https_test_url="${PROXY_TEST_HTTPS_URL:-https://example.com/}"
cache_test_url="${PROXY_TEST_CACHEABLE_URL:-}"
cache_count_url="${PROXY_TEST_CACHE_ORIGIN_COUNT_URL:-}"
proxy_curl_config="${PROXY_TEST_CURL_CONFIG:-}"
startup_timeout_seconds="${PROXY_START_TIMEOUT_SECONDS:-180}"
request_timeout_seconds="${PROXY_REQUEST_TIMEOUT_SECONDS:-120}"
local_shutdown_drain_seconds="${PROXY_TEST_SHUTDOWN_DRAIN_SECONDS:-1}"
local_shutdown_force_stop_seconds="${PROXY_TEST_SHUTDOWN_FORCE_STOP_SECONDS:-1}"
local_shutdown_wait_seconds=""
skip_build=0
keep_running=0
artifacts_dir=""

usage() {
	cat <<'USAGE'
Usage: ./test-deployment.sh [options]

Build, deploy, and verify the proxy end to end, or verify an already-running
deployment. Every run writes an evidence bundle under artifacts/deployment-e2e.

Options:
  --mode local|running     Build/start locally, or test an existing deployment
                           (default: local)
  --proxy-url URL          Proxy endpoint (default: http://127.0.0.1:8080)
  --metrics-url URL        Prometheus endpoint
                           (default: http://127.0.0.1:9090/metrics)
  --tor-check-url URL      Tor Check JSON endpoint
  --http-url URL           Plain-HTTP functional endpoint
  --https-url URL          HTTPS functional endpoint
  --cache-url URL          Controlled cacheable HTTP endpoint (optional)
  --cache-count-url URL    Counter endpoint for the controlled cache origin
  --proxy-curl-config PATH Owner-only curl config for production proxy auth
  --startup-timeout N      Readiness timeout in seconds (default: 180)
  --request-timeout N      Per-request timeout in seconds (default: 120)
  --skip-build             In local mode, reuse target/release/proxy
  --keep-running           Leave a locally started proxy running after the test
  --artifacts-dir PATH     Override the evidence bundle directory
  -h, --help               Show this help

Examples:
  ./test-deployment.sh
  ./test-deployment.sh --cache-url http://origin.example/cacheable
  ./test-deployment.sh --mode running \
    --proxy-url http://127.0.0.1:8080 \
    --metrics-url http://127.0.0.1:9090/metrics

The cache endpoint must be infrastructure you are authorized to test. It must
return a successful response with Cache-Control: public and a positive max-age.
The counter endpoint must report only that endpoint's integer request count.
Positive cache verification requires authenticated running mode and an exact
deployment allowlist entry; local development traffic intentionally bypasses.
USAGE
}

while (( $# > 0 )); do
	case "$1" in
		--mode)
			mode="${2:?missing value for --mode}"
			shift 2
			;;
		--proxy-url)
			proxy_url="${2:?missing value for --proxy-url}"
			shift 2
			;;
		--metrics-url)
			metrics_url="${2:?missing value for --metrics-url}"
			shift 2
			;;
		--tor-check-url)
			tor_check_url="${2:?missing value for --tor-check-url}"
			shift 2
			;;
		--http-url)
			http_test_url="${2:?missing value for --http-url}"
			shift 2
			;;
		--https-url)
			https_test_url="${2:?missing value for --https-url}"
			shift 2
			;;
		--cache-url)
			cache_test_url="${2:?missing value for --cache-url}"
			shift 2
			;;
		--cache-count-url)
			cache_count_url="${2:?missing value for --cache-count-url}"
			shift 2
			;;
		--proxy-curl-config)
			proxy_curl_config="${2:?missing value for --proxy-curl-config}"
			shift 2
			;;
		--startup-timeout)
			startup_timeout_seconds="${2:?missing value for --startup-timeout}"
			shift 2
			;;
		--request-timeout)
			request_timeout_seconds="${2:?missing value for --request-timeout}"
			shift 2
			;;
		--skip-build)
			skip_build=1
			shift
			;;
		--keep-running)
			keep_running=1
			shift
			;;
		--artifacts-dir)
			artifacts_dir="${2:?missing value for --artifacts-dir}"
			shift 2
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

if [[ "$mode" != "local" && "$mode" != "running" ]]; then
	echo "error: --mode must be local or running" >&2
	exit 2
fi
if [[ ! "$startup_timeout_seconds" =~ ^[1-9][0-9]*$ ]]; then
	echo "error: --startup-timeout must be a positive integer" >&2
	exit 2
fi
if [[ ! "$request_timeout_seconds" =~ ^[1-9][0-9]*$ ]]; then
	echo "error: --request-timeout must be a positive integer" >&2
	exit 2
fi
if [[ ! "$local_shutdown_drain_seconds" =~ ^[1-9][0-9]*$ ]] ||
	[[ ! "$local_shutdown_force_stop_seconds" =~ ^[1-9][0-9]*$ ]]; then
	echo "error: test shutdown drain and force-stop values must be positive integers" >&2
	exit 2
fi
local_shutdown_wait_seconds=$((local_shutdown_drain_seconds + local_shutdown_force_stop_seconds + 5))
if [[ "$proxy_url" != http://* && "$proxy_url" != https://* ]]; then
	echo "error: --proxy-url must be an HTTP(S) URL" >&2
	exit 2
fi
if [[ "$metrics_url" != http://* && "$metrics_url" != https://* ]]; then
	echo "error: --metrics-url must be an HTTP(S) URL" >&2
	exit 2
fi
if [[ "$tor_check_url" != https://* ]]; then
	echo "error: --tor-check-url must be an HTTPS URL" >&2
	exit 2
fi
if [[ "$http_test_url" != http://* ]]; then
	echo "error: --http-url must be a plain-HTTP URL" >&2
	exit 2
fi
if [[ "$https_test_url" != https://* ]]; then
	echo "error: --https-url must be an HTTPS URL" >&2
	exit 2
fi
if [[ -n "$cache_test_url" && "$cache_test_url" != http://* ]]; then
	echo "error: --cache-url must be a plain-HTTP URL" >&2
	exit 2
fi
if [[ -n "$cache_count_url" && "$cache_count_url" != http://* && "$cache_count_url" != https://* ]]; then
	echo "error: --cache-count-url must be an HTTP(S) URL" >&2
	exit 2
fi
if [[ -n "$cache_test_url" && -z "$cache_count_url" ]]; then
	echo "error: --cache-url requires --cache-count-url" >&2
	exit 2
fi
if [[ -n "$cache_count_url" && -z "$cache_test_url" ]]; then
	echo "error: --cache-count-url requires --cache-url" >&2
	exit 2
fi
if [[ -n "$proxy_curl_config" && ! -r "$proxy_curl_config" ]]; then
	echo "error: --proxy-curl-config must name a readable file" >&2
	exit 2
fi
if [[ "$mode" == "local" ]]; then
	if [[ "$proxy_url" != "http://127.0.0.1:8080" || "$metrics_url" != "http://127.0.0.1:9090/metrics" ]]; then
		echo "error: local mode uses the binary's fixed loopback endpoints" >&2
		echo "Use --mode running to test different deployment endpoints." >&2
		exit 2
	fi
else
	if (( skip_build )); then
		echo "warning: --skip-build has no effect in running mode" >&2
	fi
	if (( keep_running )); then
		echo "warning: --keep-running has no effect in running mode" >&2
	fi
fi

for command_name in curl awk cmp grep sed tee tr; do
	if ! command -v "$command_name" >/dev/null 2>&1; then
		echo "error: required command not found: $command_name" >&2
		exit 2
	fi
done
if [[ "$mode" == "local" ]] && (( ! skip_build )); then
	if ! command -v cargo >/dev/null 2>&1; then
		echo "error: required command not found: cargo" >&2
		exit 2
	fi
fi

run_stamp="$(date -u +%Y%m%dT%H%M%SZ)-$$"
if [[ -z "$artifacts_dir" ]]; then
	artifacts_dir="$script_dir/artifacts/deployment-e2e/$run_stamp"
elif [[ "$artifacts_dir" != /* ]]; then
	artifacts_dir="$script_dir/$artifacts_dir"
fi
mkdir -p "$artifacts_dir/cases"
artifacts_dir="$(cd "$artifacts_dir" && pwd)"
run_log="$artifacts_dir/run.log"
proxy_log="$artifacts_dir/proxy.log"
metrics_before="$artifacts_dir/metrics.before.prom"
metrics_after="$artifacts_dir/metrics.after.prom"
summary_file="$artifacts_dir/summary.txt"
local_proxy_pid=""
local_proxy_started=0
declare -a passed_cases=()
declare -a failed_cases=()
declare -a skipped_cases=()

exec > >(tee -a "$run_log") 2>&1

stop_local_proxy() {
	if (( ! local_proxy_started )) || ! kill -0 "$local_proxy_pid" 2>/dev/null; then
		return
	fi

	kill "$local_proxy_pid" 2>/dev/null || true
	local attempt
	for ((attempt = 0; attempt < local_shutdown_wait_seconds * 10; attempt++)); do
		if ! kill -0 "$local_proxy_pid" 2>/dev/null; then
			break
		fi
		sleep 0.1
	done
	if kill -0 "$local_proxy_pid" 2>/dev/null; then
		echo "warning: proxy did not stop gracefully; force-stopping PID $local_proxy_pid" >&2
		kill -KILL "$local_proxy_pid" 2>/dev/null || true
	fi
	wait "$local_proxy_pid" 2>/dev/null || true
	local_proxy_started=0
}

cleanup() {
	if (( ! keep_running )); then
		stop_local_proxy
	fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

proxy_curl() {
	if [[ -n "$proxy_curl_config" ]]; then
		curl --config "$proxy_curl_config" "$@"
	else
		curl "$@"
	fi
}

write_summary() {
	{
		echo "Deployment end-to-end test"
		if (( ${#failed_cases[@]} == 0 )); then
			echo "result: PASS"
		else
			echo "result: FAIL"
		fi
		echo "run: $run_stamp"
		echo "mode: $mode"
		echo "proxy: $proxy_url"
		echo "metrics: $metrics_url"
		echo "passed: ${#passed_cases[@]}"
		echo "failed: ${#failed_cases[@]}"
		echo "skipped: ${#skipped_cases[@]}"
		if (( ${#passed_cases[@]} > 0 )); then
			echo "passed_cases: ${passed_cases[*]}"
		fi
		if (( ${#failed_cases[@]} > 0 )); then
			echo "failed_cases: ${failed_cases[*]}"
		fi
		if (( ${#skipped_cases[@]} > 0 )); then
			echo "skipped_cases: ${skipped_cases[*]}"
		fi
	} > "$summary_file"
}

run_case() {
	local case_id="$1"
	local description="$2"
	shift 2
	local case_log="$artifacts_dir/cases/$case_id.log"
	local status

	echo "==> $description"
	set +e
	"$@" >"$case_log" 2>&1
	status=$?
	set -e
	if (( status == 0 )); then
		passed_cases+=("$case_id")
		echo "PASS: $case_id"
		return 0
	fi

	failed_cases+=("$case_id")
	echo "FAIL: $case_id (details: $case_log)" >&2
	sed -n '1,160p' "$case_log" >&2
	return 1
}

skip_case() {
	local case_id="$1"
	local reason="$2"
	skipped_cases+=("$case_id")
	echo "SKIP: $case_id ($reason)"
}

cargo_check_case() {
	cargo check --locked
}

cargo_test_case() {
	cargo test --locked
}

cargo_build_case() {
	cargo build --release --locked
}

local_endpoints_available_case() {
	local port
	for port in 8080 9090; do
		if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
			echo "127.0.0.1:$port is already in use" >&2
			echo "Stop the existing service or use --mode running to test it in place." >&2
			return 1
		fi
	done
}

start_local_proxy_case() {
	local binary="$script_dir/target/release/proxy"
	if [[ ! -x "$binary" ]]; then
		echo "release binary not found or not executable: $binary" >&2
		return 1
	fi
	PROXY_SHUTDOWN_DRAIN_SECONDS="$local_shutdown_drain_seconds" \
		PROXY_SHUTDOWN_FORCE_STOP_SECONDS="$local_shutdown_force_stop_seconds" \
		"$binary" >"$proxy_log" 2>&1 &
	local_proxy_pid=$!
	local_proxy_started=1
	echo "$local_proxy_pid" > "$artifacts_dir/proxy.pid"

	local deadline=$((SECONDS + startup_timeout_seconds))
	while (( SECONDS < deadline )); do
		if ! kill -0 "$local_proxy_pid" 2>/dev/null; then
			echo "proxy exited before becoming ready" >&2
			sed -n '1,200p' "$proxy_log" >&2
			return 1
		fi
		if curl --fail --silent --show-error --max-time 2 "$metrics_url" \
			--output "$metrics_before"; then
			if grep -q '^proxy_active_tunnels ' "$metrics_before"; then
				return 0
			fi
		fi
		sleep 1
	done

	echo "proxy did not expose metrics within ${startup_timeout_seconds}s" >&2
	sed -n '1,200p' "$proxy_log" >&2
	return 1
}

wait_for_running_proxy_case() {
	local deadline=$((SECONDS + startup_timeout_seconds))
	while (( SECONDS < deadline )); do
		if curl --fail --silent --show-error --max-time 2 "$metrics_url" \
			--output "$metrics_before"; then
			if grep -q '^proxy_active_tunnels ' "$metrics_before"; then
				return 0
			fi
		fi
		sleep 1
	done
	echo "deployment did not expose expected metrics within ${startup_timeout_seconds}s" >&2
	return 1
}

metrics_contract_case() {
	curl --fail --silent --show-error --max-time 10 "$metrics_url" \
		--output "$metrics_before" || return 1
	for metric_name in \
		proxy_active_tunnels \
		proxy_bridge_tasks_active \
		proxy_requests_total \
		proxy_bytes_to_tor_total \
		proxy_bytes_from_tor_total \
		proxy_isolation_tokens; do
		if ! grep -q "^# HELP $metric_name " "$metrics_before"; then
			echo "missing Prometheus metric: $metric_name" >&2
			return 1
		fi
	done
}

metrics_path_is_private_case() {
	local metrics_base="${metrics_url%/}"
	if [[ "$metrics_base" == */metrics ]]; then
		metrics_base="${metrics_base%/metrics}"
	fi
	local status
	status="$(curl --silent --show-error --max-time 10 \
		--output /dev/null --write-out '%{http_code}' \
		"$metrics_base/not-metrics")" || return 1
	if [[ "$status" != "404" ]]; then
		echo "expected 404 outside /metrics, received $status" >&2
		return 1
	fi
}

blocked_destination_case() {
	local connect_status curl_status
	connect_status="$(proxy_curl --silent --show-error --insecure --noproxy '' \
		--max-time 15 --proxy "$proxy_url" --output /dev/null \
		--write-out '%{http_connect}' https://127.0.0.1:443/)" && curl_status=0 || curl_status=$?
	if [[ "$connect_status" != "403" ]]; then
		echo "expected proxy CONNECT status 403, received '${connect_status:-none}' (curl=$curl_status)" >&2
		return 1
	fi
}

invalid_isolation_case() {
	local connect_status curl_status
	connect_status="$(proxy_curl --silent --show-error --insecure --noproxy '' \
		--max-time 15 --proxy "$proxy_url" --output /dev/null \
		--proxy-header 'X-Proxy-Isolation: invalid identity' \
		--write-out '%{http_connect}' https://example.com/)" && curl_status=0 || curl_status=$?
	if [[ "$connect_status" != "400" ]]; then
		echo "expected proxy CONNECT status 400, received '${connect_status:-none}' (curl=$curl_status)" >&2
		return 1
	fi
}

tor_session_routing_case() {
	local response_file="$artifacts_dir/tor-check-session.json"
	local compact_response
	proxy_curl --fail --silent --show-error --noproxy '' \
		--retry 1 --retry-all-errors --max-time "$request_timeout_seconds" \
		--proxy "$proxy_url" \
		--proxy-header "X-Proxy-Isolation: deployment-$run_stamp" \
		--proxy-header 'X-Proxy-Isolation-Mode: session' \
		--output "$response_file" "$tor_check_url" || return 1
	compact_response="$(tr -d '[:space:]' < "$response_file")"
	if [[ "$compact_response" != *'"IsTor":true'* ]]; then
		echo "Tor Check did not report IsTor=true" >&2
		echo "response: $(sed -n '1,10p' "$response_file")" >&2
		return 1
	fi
}

strict_https_case() {
	local status
	status="$(proxy_curl --silent --show-error --noproxy '' \
		--max-time "$request_timeout_seconds" --proxy "$proxy_url" \
		--proxy-header 'X-Proxy-Isolation-Mode: strict' \
		--output "$artifacts_dir/https-response.body" \
		--dump-header "$artifacts_dir/https-response.headers" \
		--write-out '%{http_code}' "$https_test_url")" || return 1
	if [[ ! "$status" =~ ^[23][0-9][0-9]$ ]]; then
		echo "expected HTTPS origin status 2xx/3xx, received $status" >&2
		return 1
	fi
}

plain_http_case() {
	local status
	status="$(proxy_curl --silent --show-error --noproxy '' \
		--max-time "$request_timeout_seconds" --proxy "$proxy_url" \
		--output "$artifacts_dir/http-response.body" \
		--dump-header "$artifacts_dir/http-response.headers" \
		--write-out '%{http_code}' "$http_test_url")" || return 1
	if [[ ! "$status" =~ ^[23][0-9][0-9]$ ]]; then
		echo "expected HTTP origin status 2xx/3xx, received $status" >&2
		return 1
	fi
}

cache_case() {
	local first_headers="$artifacts_dir/cache-first.headers"
	local second_headers="$artifacts_dir/cache-second.headers"
	local cache_identity="cache-$run_stamp"
	local cache_metrics_before="$artifacts_dir/cache-metrics.before.prom"
	local cache_metrics_after="$artifacts_dir/cache-metrics.after.prom"
	local origin_count_before_file="$artifacts_dir/cache-origin-count.before.txt"
	local origin_count_after_file="$artifacts_dir/cache-origin-count.after.txt"
	local hits_before hits_after origin_count_before origin_count_after

	curl --fail --silent --show-error --max-time 10 "$metrics_url" \
		--output "$cache_metrics_before" || return 1
	curl --fail --silent --show-error --max-time 10 "$cache_count_url" \
		--output "$origin_count_before_file" || return 1

	proxy_curl --fail --silent --show-error --noproxy '' \
		--max-time "$request_timeout_seconds" --proxy "$proxy_url" \
		--proxy-header "X-Proxy-Isolation: $cache_identity" \
		--dump-header "$first_headers" --output "$artifacts_dir/cache-first.body" \
		"$cache_test_url" || return 1
	proxy_curl --fail --silent --show-error --noproxy '' \
		--max-time "$request_timeout_seconds" --proxy "$proxy_url" \
		--proxy-header "X-Proxy-Isolation: $cache_identity" \
		--dump-header "$second_headers" --output "$artifacts_dir/cache-second.body" \
		"$cache_test_url" || return 1

	curl --fail --silent --show-error --max-time 10 "$cache_count_url" \
		--output "$origin_count_after_file" || return 1
	curl --fail --silent --show-error --max-time 10 "$metrics_url" \
		--output "$cache_metrics_after" || return 1

	if ! cmp -s "$artifacts_dir/cache-first.body" "$artifacts_dir/cache-second.body"; then
		echo "controlled cache responses differed" >&2
		return 1
	fi
	if tr -d '\r' < "$first_headers" | grep -qi '^x-proxy-cache:' ||
		tr -d '\r' < "$second_headers" | grep -qi '^x-proxy-cache:'; then
		echo "a controlled response exposed the forbidden X-Proxy-Cache header" >&2
		return 1
	fi

	hits_before="$(metric_value proxy_cache_hits_total "$cache_metrics_before")"
	hits_after="$(metric_value proxy_cache_hits_total "$cache_metrics_after")"
	origin_count_before="$(tr -d '[:space:]' < "$origin_count_before_file")"
	origin_count_after="$(tr -d '[:space:]' < "$origin_count_after_file")"
	if [[ ! "$hits_before" =~ ^[0-9]+$ || ! "$hits_after" =~ ^[0-9]+$ ]] ||
		(( hits_after <= hits_before )); then
		echo "tenant-scoped cache hit counter did not increase ($hits_before -> $hits_after)" >&2
		return 1
	fi
	if [[ ! "$origin_count_before" =~ ^[0-9]+$ || ! "$origin_count_after" =~ ^[0-9]+$ ]] ||
		(( origin_count_after != origin_count_before + 1 )); then
		echo "controlled origin count did not increase exactly once ($origin_count_before -> $origin_count_after)" >&2
		return 1
	fi
}

metric_value() {
	local metric_name="$1"
	local metrics_file="$2"
	awk -v name="$metric_name" '$1 == name { print $2; exit }' "$metrics_file"
}

metrics_activity_case() {
	curl --fail --silent --show-error --max-time 10 "$metrics_url" \
		--output "$metrics_after" || return 1
	local before_bytes after_bytes before_tokens after_tokens
	before_bytes="$(metric_value proxy_bytes_from_tor_total "$metrics_before")"
	after_bytes="$(metric_value proxy_bytes_from_tor_total "$metrics_after")"
	before_tokens="$(metric_value proxy_isolation_tokens "$metrics_before")"
	after_tokens="$(metric_value proxy_isolation_tokens "$metrics_after")"

	if [[ ! "$before_bytes" =~ ^[0-9]+$ || ! "$after_bytes" =~ ^[0-9]+$ ]]; then
		echo "byte counters were missing or non-integer" >&2
		return 1
	fi
	if (( after_bytes <= before_bytes )); then
		echo "proxy_bytes_from_tor_total did not increase ($before_bytes -> $after_bytes)" >&2
		return 1
	fi
	if [[ ! "$before_tokens" =~ ^[0-9]+$ || ! "$after_tokens" =~ ^[0-9]+$ ]]; then
		echo "isolation token gauges were missing or non-integer" >&2
		return 1
	fi
	if (( after_tokens <= before_tokens )); then
		echo "proxy_isolation_tokens did not increase ($before_tokens -> $after_tokens)" >&2
		return 1
	fi
}

process_survived_case() {
	if [[ "$mode" == "local" ]]; then
		if ! kill -0 "$local_proxy_pid" 2>/dev/null; then
			echo "local proxy exited during the test" >&2
			sed -n '1,200p' "$proxy_log" >&2
			return 1
		fi
	fi
	curl --fail --silent --show-error --max-time 10 "$metrics_url" --output /dev/null
}

echo "Deployment end-to-end test: $run_stamp"
echo "Mode: $mode"
echo "Evidence: $artifacts_dir"

setup_failed=0
if [[ "$mode" == "local" ]]; then
	if (( skip_build )); then
		skip_case cargo_check "--skip-build selected"
		skip_case cargo_test "--skip-build selected"
		skip_case cargo_build "--skip-build selected"
	else
		run_case cargo_check "Checking the locked dependency graph and source" cargo_check_case || setup_failed=1
		if (( ! setup_failed )); then
			run_case cargo_test "Running deterministic automated tests" cargo_test_case || setup_failed=1
		fi
		if (( ! setup_failed )); then
			run_case cargo_build "Building the release deployment artifact" cargo_build_case || setup_failed=1
		fi
	fi
	if (( ! setup_failed )); then
		run_case deployment_preflight "Confirming the local deployment endpoints are free" local_endpoints_available_case || setup_failed=1
	fi
	if (( ! setup_failed )); then
		run_case deployment_start "Starting the release proxy and waiting for readiness" start_local_proxy_case || setup_failed=1
	fi
else
	skip_case cargo_check "testing an already-running deployment"
	skip_case cargo_test "testing an already-running deployment"
	skip_case cargo_build "testing an already-running deployment"
	run_case deployment_ready "Waiting for the deployed metrics endpoint" wait_for_running_proxy_case || setup_failed=1
fi

if (( setup_failed )); then
	write_summary
	echo
	echo "Deployment setup failed. Evidence: $artifacts_dir" >&2
	exit 1
fi

run_case metrics_contract "Validating the Prometheus metrics contract" metrics_contract_case || true
run_case metrics_path_scope "Checking that the metrics service exposes only /metrics" metrics_path_is_private_case || true
run_case destination_policy "Rejecting a loopback CONNECT destination" blocked_destination_case || true
run_case invalid_isolation "Rejecting malformed isolation metadata" invalid_isolation_case || true
run_case tor_session "Verifying session-isolated HTTPS traffic exits through Tor" tor_session_routing_case || true
run_case strict_https "Verifying strict-isolation HTTPS forwarding" strict_https_case || true
run_case plain_http "Verifying the ordinary HTTP forwarding pipeline" plain_http_case || true
if [[ -n "$cache_test_url" && "$mode" == "running" ]]; then
	run_case controlled_cache "Verifying a cold fetch followed by a cache hit" cache_case || true
elif [[ -n "$cache_test_url" ]]; then
	skip_case controlled_cache "authenticated running mode is required for production cache access"
else
	skip_case controlled_cache "set --cache-url and --cache-count-url for an authenticated running deployment"
fi
run_case metrics_activity "Confirming this run changed Tor byte and isolation metrics" metrics_activity_case || true
run_case deployment_survived "Confirming the deployment remained healthy" process_survived_case || true

write_summary
echo
if (( ${#failed_cases[@]} == 0 )); then
	echo "All deployment checks passed."
	if (( local_proxy_started )) && (( keep_running )); then
		echo "Local proxy is still running with PID $local_proxy_pid."
	fi
	echo "Evidence: $artifacts_dir"
	exit 0
fi

echo "${#failed_cases[@]} deployment check(s) failed: ${failed_cases[*]}" >&2
echo "Evidence: $artifacts_dir" >&2
exit 1
