#!/bin/bash
# ffuf-circuit-breaker.sh - Safe ffuf wrapper with WAF protection
# Purpose: Automatically stop fuzzing if the WAF starts blocking requests (429)

# =============================================================================
# Configuration
# =============================================================================

TARGET="$1"          # The target URL with FUZZ keyword (e.g. https://example.com/FUZZ)
WORDLIST="$2"        # Path to the wordlist file
shift 2              # Remove the first two arguments to pass extra flags to ffuf

# Set your researcher identifier here (or leave as generic)
RESEARCHER_ID="Security Researcher"

echo "[+] ffuf Circuit Breaker started on $TARGET"
echo "[+] Wordlist: $WORDLIST"

consecutive_429=0    # Counter for consecutive 429 responses
MAX_429=5            # Threshold - stop after this many 429s in a row
request_count=0      # Total requests sent (for progress tracking)

# =============================================================================
# Clean exit handling
# =============================================================================

# Trap Ctrl+C (SIGINT) to ensure ffuf is properly killed and not left running
trap 'echo -e "\n[!] Caught SIGINT. Stopping cleanly..."; pkill -f "ffuf -u $TARGET" 2>/dev/null; exit 0' SIGINT

# =============================================================================
# Main ffuf execution with live monitoring
# =============================================================================
# Safe Defaults applied below:
# -t 2 : Low thread count for safety and stealth
# -mc 200,301,302,403 : Only show interesting status codes
# -fc 404 : Filter out noise (404 pages)
# =============================================================================

TIMESTAMP=$(date +%F_%H%M)

ffuf \
  -u "$TARGET" \
  -w "$WORDLIST" \
  -t 2 \
  -mc 200,301,302,403 \
  -fc 404 \
  -H "User-Agent: Mozilla/5.0 (compatible; $RESEARCHER_ID)" \
  -o "ffuf-safe-${TIMESTAMP}.json" \
  -v "$@" 2>&1 | tee -a "ffuf-live-${TIMESTAMP}.log" | while read -r line; do

    # Print every line to terminal (live view)
    echo "$line"
    ((request_count++))

    # Show progress every 500 requests
    if (( request_count % 500 == 0 )); then
        echo "[PROGRESS] Requests sent: $request_count"
    fi

    # =============================================================================
    # WAF Rate Limit Detection (Circuit Breaker Logic)
    # =============================================================================

    # Check if the current line contains a 429 response
    if echo "$line" | grep -q "429"; then
        ((consecutive_429++))
        echo "[!] WAF Warning: 429 detected ($consecutive_429/$MAX_429)"

        # If we hit the threshold, stop everything
        if [ $consecutive_429 -ge $MAX_429 ]; then
            echo "[X] CRITICAL: WAF Rate Limit hit $MAX_429 times. CIRCUIT BREAKER ACTIVATED."
            echo "[X] Halting scan to protect target and your IP..."
            pkill -f "ffuf -u $TARGET" 2>/dev/null
            exit 1
        fi
    else
        # Reset counter if we get a normal response (WAF cooled down)
        consecutive_429=0
    fi
done

echo "[+] Scan completed or safely halted. Results saved to JSON."
