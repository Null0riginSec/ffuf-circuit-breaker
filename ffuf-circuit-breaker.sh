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
# Colors
# =============================================================================
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# =============================================================================
# Clean exit handling
# =============================================================================

# Trap Ctrl+C (SIGINT) to ensure ffuf is properly killed and not left running
trap 'echo -e "\n${RED}[!] Caught SIGINT. Stopping cleanly...${NC}"; pkill -f "ffuf -u $TARGET" 2>/dev/null; exit 0' SIGINT

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

    # Get current Date and Time for this exact log line
    CURRENT_TIME=$(date +'%Y-%m-%d %H:%M:%S')

    # Print every line to terminal with timestamp (Live view)
    echo "[$CURRENT_TIME] $line"
    ((request_count++))

    # Show progress every 500 requests
    if (( request_count % 500 == 0 )); then
        echo -e "${YELLOW}[$CURRENT_TIME] [PROGRESS] Requests sent: $request_count${NC}"
    fi

    # =============================================================================
    # WAF Rate Limit Detection (Circuit Breaker Logic) - FIXED
    # =============================================================================

    # Check specifically for a 429 Status code
    if echo "$line" | grep -q "Status: 429"; then
        ((consecutive_429++))
        echo -e "${RED}[$CURRENT_TIME] [!] WAF Warning: 429 detected ($consecutive_429/$MAX_429)${NC}"

        # If we hit the threshold, stop everything
        if [ $consecutive_429 -ge $MAX_429 ]; then
            echo -e "${RED}[$CURRENT_TIME] [X] CRITICAL: WAF Rate Limit hit $MAX_429 times. CIRCUIT BREAKER ACTIVATED.${NC}"
            echo -e "${RED}[$CURRENT_TIME] [X] Halting scan to protect target and your IP...${NC}"
            pkill -f "ffuf -u $TARGET" 2>/dev/null
            exit 1
        fi
        
    # Reset counter ONLY if we see a valid, non-429 Status line
    elif echo "$line" | grep -q "Status: "; then
        consecutive_429=0
    fi
done

# Print final completion message with timestamp and green color
FINAL_TIME=$(date +'%Y-%m-%d %H:%M:%S')
echo -e "${GREEN}[$FINAL_TIME] [+] Scan completed or safely halted. Results saved to JSON.${NC}"
