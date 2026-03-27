#!/bin/bash
# ffuf-circuit-breaker.sh - Safe ffuf wrapper with WAF protection
# Purpose: Automatically stop fuzzing if the WAF starts blocking requests
# Triggers on: 429 (rate-limit) OR 503 (hard block) — combined circuit breaker
# Source: https://github.com/Null0riginSec/ffuf-circuit-breaker

# =============================================================================
# Defaults (all overridable via CLI flags)
# =============================================================================

RESEARCHER_ID="Security Researcher"
FILTER_SIZE="230"   # WAF soft-block response size filter (e.g., F5 BIG-IP ~230 bytes)
MAX_BLOCK=5         # Trip breaker after this many consecutive 429/503 responses
REQUEST_RATE=10     # Hard ceiling on total requests/sec (ffuf -rate). Independent of -t/-p.
DRY_RUN=false

# =============================================================================
# Colors
# =============================================================================
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

# =============================================================================
# Usage
# =============================================================================
usage() {
    echo -e "${CYAN}Usage:${NC} $0 [OPTIONS] <URL/FUZZ> <wordlist> [extra ffuf flags...]"
    echo ""
    echo "Options:"
    echo "  -n, --dry-run        Print the resolved ffuf command, then exit"
    echo "  -fs <bytes>          WAF soft-block filter size (default: $FILTER_SIZE)"
    echo "  -m  <count>          Max consecutive blocks before tripping (default: $MAX_BLOCK)"
    echo "  -r  <req/sec>        Max request rate ceiling via ffuf -rate (default: $REQUEST_RATE)"
    echo "  -h, --help           Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 https://example.com/FUZZ wordlist.txt"
    echo "  $0 -fs 405 -m 3 -r 5 https://example.com/FUZZ wordlist.txt"
    echo "  $0 -n https://example.com/FUZZ wordlist.txt        # dry run"
    exit 0
}

# =============================================================================
# Parse script-level flags
# Guards on all shift 2 calls inside this loop so a missing value arg
# (e.g. `-fs` with no number after it) doesn't silently consume TARGET.
# =============================================================================
while [[ "${1:-}" == -* ]]; do
    case "$1" in
        -n|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -fs)
            [[ -z "${2:-}" ]] && { echo -e "${RED}[!] -fs requires a value.${NC}"; exit 1; }
            FILTER_SIZE="$2"
            shift 2
            ;;
        -m)
            [[ -z "${2:-}" ]] && { echo -e "${RED}[!] -m requires a value.${NC}"; exit 1; }
            MAX_BLOCK="$2"
            shift 2
            ;;
        -r)
            [[ -z "${2:-}" ]] && { echo -e "${RED}[!] -r requires a value.${NC}"; exit 1; }
            REQUEST_RATE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            # Unknown flag — stop parsing, remaining args belong to ffuf
            break
            ;;
    esac
done

# =============================================================================
# Input validation — BEFORE any shift, so shift can never underflow
# =============================================================================
TARGET="${1:-}"
WORDLIST="${2:-}"

[[ -z "$TARGET" || -z "$WORDLIST" ]] && {
    echo -e "${RED}[!] Missing required arguments.${NC}"
    echo ""
    usage
}

[[ "$TARGET" != *"FUZZ"* ]] && {
    echo -e "${YELLOW}[!] Warning: TARGET URL does not contain the FUZZ keyword.${NC}"
}

[[ ! -f "$WORDLIST" ]] && {
    echo -e "${RED}[!] Wordlist not found: $WORDLIST${NC}"
    exit 1
}

command -v ffuf &>/dev/null || {
    echo -e "${RED}[!] ffuf not found in PATH.${NC}"
    exit 1
}

# Safe shift: only runs after we've confirmed at least 2 args exist
[[ $# -ge 2 ]] && shift 2
# Remaining positional args ($@) are forwarded verbatim to ffuf

# =============================================================================
# Setup
# =============================================================================
TIMESTAMP=$(date +%F_%H%M)
LOGFILE="ffuf-live-${TIMESTAMP}.log"
OUTFILE="ffuf-safe-${TIMESTAMP}.json"

# Build the ffuf command as an array.
# Array form keeps args with spaces/special chars intact — no word-splitting.
# Safety layer explanation:
#   -t 2         : 2 threads max (limits parallelism)
#   -p 0.1       : 100 ms per-thread delay (throttles each worker)
#   -rate 10     : hard ceiling of 10 req/s total, independent of -t and -p
#   -timeout 10  : don't hang on slow/dead connections
#   -mc          : whitelist of interesting codes (no -fc needed; 404 is implicit)
#   -fs          : filter out WAF soft-blocks by response size
FFUF_CMD=(
    ffuf
    -u        "$TARGET"
    -w        "$WORDLIST"
    -t        2
    -p        0.1
    -rate     "$REQUEST_RATE"
    -timeout  10
    -mc       200,301,302,403
    -fs       "$FILTER_SIZE"
    -H        "User-Agent: Mozilla/5.0 (compatible; $RESEARCHER_ID)"
    -o        "$OUTFILE"
    "$@"
)

# =============================================================================
# Dry-run mode
# =============================================================================
if [[ "$DRY_RUN" == true ]]; then
    echo -e "${CYAN}[DRY RUN] Would execute:${NC}"
    echo ""
    # Print each element on its own line for readability
    local_cmd=("${FFUF_CMD[@]}")
    printf '  %s \\\n' "${local_cmd[@]::${#local_cmd[@]}-1}"
    printf '  %s\n'    "${local_cmd[-1]}"
    echo ""
    echo -e "${CYAN}  Log  → $LOGFILE${NC}"
    echo -e "${CYAN}  JSON → $OUTFILE${NC}"
    exit 0
fi

# =============================================================================
# FIFO — decouples ffuf's stdout from the monitoring loop.
# This lets us capture ffuf's PID for precise killing (no fragile pkill -f).
# The FIFO write-end closes when ffuf exits/dies, which propagates EOF cleanly
# through `cat` into the process substitution, ending the while loop naturally.
# =============================================================================
FIFO=$(mktemp -u /tmp/ffuf_fifo_XXXXXX)
mkfifo "$FIFO"

# Always clean up the FIFO on exit, regardless of how the script ends
trap 'rm -f "$FIFO"' EXIT

# =============================================================================
# Signal handling
# SIGINT (Ctrl+C) kills ffuf by stored PID — not by pkill -f pattern, which
# is fragile against special chars in $TARGET and could hit other ffuf procs.
# =============================================================================
FFUF_PID=""
trap '
    echo -e "\n${RED}[!] Caught SIGINT. Stopping cleanly...${NC}"
    [[ -n "$FFUF_PID" ]] && kill "$FFUF_PID" 2>/dev/null
    exit 0
' SIGINT

# =============================================================================
# Launch
# =============================================================================
echo -e "${GREEN}[+] ffuf Circuit Breaker started${NC}"
echo -e "    Target      : $TARGET"
echo -e "    Wordlist    : $WORDLIST"
echo -e "    Size filter : $FILTER_SIZE bytes"
echo -e "    Rate cap    : $REQUEST_RATE req/s  (-t 2, -p 0.1, -rate $REQUEST_RATE)"
echo -e "    Breaker     : trips on $MAX_BLOCK consecutive 429 or 503 responses"
echo -e "    Log         : $LOGFILE"
echo -e "    JSON output : $OUTFILE"
echo ""

# Start ffuf in the background, pipe stdout+stderr into the FIFO
"${FFUF_CMD[@]}" > "$FIFO" 2>&1 &
FFUF_PID=$!

# =============================================================================
# Monitoring loop
#
# DESIGN NOTE — why process substitution instead of a pipe:
#   cmd | while read   →  while loop runs in a SUBSHELL
#                          consecutive_block and request_count are lost after loop
#
#   while read done < <(cmd)  →  while loop runs in the PARENT shell
#                                 variables survive and are readable after the loop
#
# DESIGN NOTE — why write to log inside the loop instead of using `tee`:
#   With `done < <(tee -a logfile < FIFO)`, when we `break`, the read-end of
#   tee's stdout pipe is closed. tee receives SIGPIPE on its next write and may
#   not flush the final lines to the log file before dying.
#   Writing directly with >> inside the loop is synchronous and never races.
#
# PERFORMANCE NOTE — all string checks use native bash builtins:
#   [[ "$line" == *"pattern"* ]]   →  glob match, zero subprocesses
#   [[ "$line" =~ regex ]]         →  ERE match, zero subprocesses, BASH_REMATCH
#   printf -v VAR '%(fmt)T' -1     →  bash builtin strftime, zero subprocesses
#   All three replace echo|grep/date calls that would otherwise fork on every
#   line — critical when ffuf is outputting hundreds of lines per second.
# =============================================================================
consecutive_block=0
request_count=0
CIRCUIT_BROKEN=false

while read -r line; do

    # Write raw line to log synchronously (no tee, no SIGPIPE risk)
    printf '%s\n' "$line" >> "$LOGFILE"

    # Bash builtin strftime — no subprocess, no fork overhead per line
    printf -v CURRENT_TIME '%(%Y-%m-%d %H:%M:%S)T' -1
    echo "[$CURRENT_TIME] $line"

    # Gate: only process lines that carry a Status code.
    # Native glob match — zero subprocesses.
    if [[ "$line" == *"Status: "* ]]; then
        ((request_count++))

        # Progress checkpoint (counts actual result lines, not all output lines)
        if (( request_count % 500 == 0 )); then
            echo -e "${YELLOW}[$CURRENT_TIME] [PROGRESS] Requests completed: $request_count${NC}"
        fi

        # =====================================================================
        # Combined Circuit Breaker — 429 (rate-limit) AND 503 (hard WAF block)
        #
        # Why both codes?
        #   Many WAFs (Cloudflare, Akamai, AWS WAF) start with 429 and silently
        #   escalate to 503 after sustained scanning. A breaker watching only 429
        #   would reset its counter on every 503, letting the scan continue
        #   indefinitely while the WAF is in full hard-block mode.
        #
        # Reset condition:
        #   Counter resets ONLY on a clean non-blocking status line (200/301/302/403).
        #   This means N clean responses between blocks do NOT reset your exposure —
        #   the counter is strictly "consecutive blocks in a row."
        #
        # BASH_REMATCH[1] extracts the matched code (429 or 503) without grep.
        # =====================================================================
        if [[ "$line" =~ Status:[[:space:]]+(429|503) ]]; then
            BLOCKED_CODE="${BASH_REMATCH[1]}"
            ((consecutive_block++))
            echo -e "${RED}[$CURRENT_TIME] [!] WAF block — HTTP $BLOCKED_CODE ($consecutive_block/$MAX_BLOCK)${NC}"

            if (( consecutive_block >= MAX_BLOCK )); then
                echo -e "${RED}[$CURRENT_TIME] [X] CIRCUIT BREAKER ACTIVATED — $MAX_BLOCK consecutive blocks.${NC}"
                echo -e "${RED}[$CURRENT_TIME] [X] Halting scan to protect target and your IP.${NC}"

                # Graceful kill sequence: SIGTERM first, SIGKILL fallback.
                # SIGTERM asks ffuf to exit cleanly (flush buffers, close files).
                # SIGKILL is the hard stop if ffuf doesn't respond within 2 seconds.
                kill "$FFUF_PID" 2>/dev/null
                sleep 2
                if kill -0 "$FFUF_PID" 2>/dev/null; then
                    echo -e "${RED}[$CURRENT_TIME] [!] ffuf did not exit on SIGTERM — sending SIGKILL.${NC}"
                    kill -9 "$FFUF_PID" 2>/dev/null
                fi

                CIRCUIT_BROKEN=true
                break
            fi

        else
            # A clean (non-blocking) status line resets the consecutive counter
            consecutive_block=0
        fi
    fi

done < <(cat "$FIFO")

# Wait for ffuf to fully exit and capture its exit code.
# `wait` is non-optional: without it, the FIFO may still have a live writer
# and the EXIT trap could delete it before ffuf finishes draining.
wait "$FFUF_PID" 2>/dev/null
FFUF_EXIT_CODE=$?

# =============================================================================
# Final summary
# All variables (consecutive_block, request_count, CIRCUIT_BROKEN) are intact
# here because the loop ran in the parent shell via process substitution.
# =============================================================================
printf -v FINAL_TIME '%(%Y-%m-%d %H:%M:%S)T' -1

echo ""
if [[ "$CIRCUIT_BROKEN" == true ]]; then
    echo -e "${RED}[$FINAL_TIME] [X] Scan halted by circuit breaker.${NC}"
    echo -e "${RED}[$FINAL_TIME]     Requests before halt : $request_count${NC}"
    echo -e "${RED}[$FINAL_TIME]     Partial results      : $OUTFILE (may be incomplete JSON)${NC}"
    echo -e "${YELLOW}[$FINAL_TIME] [!] Recommended cooldown: wait 10-15 min before retrying.${NC}"
    echo -e "${YELLOW}[$FINAL_TIME] [!] Consider reducing -rate or increasing -p before next run.${NC}"
    exit 1

elif [[ $FFUF_EXIT_CODE -ne 0 && $request_count -eq 0 ]]; then
    # ffuf exited non-zero and we saw zero result lines — likely a startup failure
    # (bad flags, unreachable target, etc.). The log will have the real error.
    echo -e "${RED}[$FINAL_TIME] [!] ffuf exited with code $FFUF_EXIT_CODE and processed 0 requests.${NC}"
    echo -e "${RED}[$FINAL_TIME]     Check the log for ffuf's error output: $LOGFILE${NC}"
    exit "$FFUF_EXIT_CODE"

else
    echo -e "${GREEN}[$FINAL_TIME] [+] Scan completed cleanly.${NC}"
    echo -e "${GREEN}[$FINAL_TIME]     Total requests : $request_count${NC}"
    echo -e "${GREEN}[$FINAL_TIME]     Results saved  : $OUTFILE${NC}"
fi
