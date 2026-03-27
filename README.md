# ffuf-circuit-breaker
A highly optimized, production-aware wrapper for **ffuf** that automatically detects WAF rate-limiting and hard blocks, stopping the scan gracefully before causing damage or getting your IP banned.

### Philosophy
**Fail-safe by design.**  
This tool was built with one core principle: **Never harm the target, never get yourself banned**. It monitors every response in real-time and activates a "Circuit Breaker" the moment it detects consistent `429` (Too Many Requests) or `503` (Service Unavailable) responses from modern WAFs (like Cloudflare, AWS WAF, or Akamai).

### Features
- **Combined Threat Detection:** Monitors for both rate limits (`429`) and hard WAF blocks (`503`).
- **Zero-Fork Performance:** Uses native Bash string matching and regex (no `grep` or subshells in the monitoring loop) to handle thousands of lines per second without CPU bottlenecks.
- **Precision Process Control:** Uses a FIFO buffer to capture ffuf's exact PID, ensuring safe and targeted termination without relying on fragile `pkill` commands.
- **Customizable CLI Flags:** Control rate limits, block thresholds, and filter sizes on the fly.
- **Dry-Run Mode:** Safely preview the exact `ffuf` command array before execution.
- **Graceful Degradation:** Attempts clean `SIGTERM` shutdown before falling back to `SIGKILL`.
- **Persistent Logging & JSON:** Saves live logs and professional JSON output with timestamps.

### Usage & Options

```bash
chmod +x ffuf-circuit-breaker.sh
```
```bash
./ffuf-circuit-breaker.sh [OPTIONS] <URL/FUZZ> <wordlist> [extra ffuf flags...]
```
### Available Options:
- **-n, --dry-run** : Print the resolved ffuf command, then exit safely.
- **-fs <bytes>** : WAF soft-block filter size (default: 230 bytes).
- **-m <count>** : Max consecutive blocks before tripping the breaker (default: 5).
- **-r <req/sec>** : Hard ceiling on total requests per second via ffuf -rate (default: 10).
- **-h, --help** : Show help menu.

### Examples:

#### Basic run with defaults
```bash
./ffuf-circuit-breaker.sh target[.]com/FUZZ wordlist.txt
```
#### Custom filter size, max blocks, and request rate ceiling
```bash
./ffuf-circuit-breaker.sh -fs 405 -m 3 -r 5 target[.]com/FUZZ wordlist.txt -t 4
```
#### Test run (Dry-Run mode)
```bash
./ffuf-circuit-breaker.sh -n target[.]com/FUZZ wordlist.txt
```

### How It Works (Technical Breakdown)
The script isolates ffuf's output through a temporary FIFO pipe, allowing a parent-shell monitoring loop to analyze the stream in real-time without losing variable state.

### Dual Detection (429 & 503)
Modern WAFs often start with a polite 429 and silently escalate to a 503 or 403 drop. The breaker watches for both, ensuring a sudden shift to hard-blocking doesn't bypass the counter.

### Circuit Breaker Logic
- If the consecutive block counter reaches the MAX_BLOCK threshold, the script:
- Prints a critical warning and halts the scan.
- Issues a graceful kill to the exact ffuf PID.
- Waits 2 seconds and issues a kill -9 if the process hangs.
- Exits safely, preserving the JSON results gathered so far.

### Strict Reset Mechanism
The block counter resets to 0 only when a clean, non-blocking status code (like 200, 301, 302) is received. This prevents WAF timeouts from tricking the breaker.

### Safety & Responsible Use
This tool is intended strictly for authorized security testing (such as Bug Bounty programs, Vulnerability Disclosure Programs, or systems where you have explicit, written permission to test).

Unauthorized use of this tool against targets without prior mutual consent is illegal. The author assumes no liability and is not responsible for any misuse, disruption, or damage caused by this script.

Always adhere strictly to the target program's Rules of Engagement (RoE) and respect designated rate limits and out-of-scope declarations.

### Author
Null0riginSec

### License
This project is licensed under the MIT License.

