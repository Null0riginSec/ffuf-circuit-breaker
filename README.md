# ffuf-circuit-breaker

A safe, production-aware wrapper for **ffuf** that automatically detects WAF rate-limiting and stops the scan before causing damage or getting blocked.

### Philosophy
**Fail-safe by design.**  
This tool was built with one core principle: **Never harm the target, never get yourself banned**. It monitors every response in real-time and activates a "Circuit Breaker" the moment it detects consistent 429 (Too Many Requests) responses from a WAF.

### Features
- Real-time parsing of ffuf output
- Consecutive 429 detection and counter
- Automatic hard-stop after 5 consecutive rate limits
- Clean SIGINT (Ctrl+C) handling with process cleanup
- Live progress counter (works even with `-recursion`)
- Persistent logging (`ffuf-safe-live.log`)
- Professional JSON output with timestamp

### How It Works (Technical Breakdown)

The script uses a `while read -r line` loop to analyze **every single line** of ffuf's verbose output in real-time.

1. **429 Detection**  
   Every time a `429` status appears, the counter `consecutive_429` increases.

2. **Circuit Breaker Logic**  
   If the counter reaches `MAX_429` (default: 5), the script:
   - Prints a clear warning
   - Executes `pkill -f "ffuf -u $TARGET"`
   - Exits with code 1 (safe termination)

3. **Reset Mechanism**  
   Any successful response (non-429) resets the counter to 0. This prevents false positives from occasional rate limits.

4. **Progress Tracking**  
   Prints "Requests sent: X" every 500 requests — useful when using recursion (where ffuf hides the default progress bar).

This approach gives full visibility and control without interfering with ffuf's core functionality.

### Usage Example
```bash
chmod +x ffuf-circuit-breaker.sh
./ffuf-circuit-breaker.sh https://target.com/FUZZ wordlist.txt
```

## Safety & Responsible Use
This tool is intended **strictly for authorized security testing** (such as Bug Bounty programs, Vulnerability Disclosure Programs, or systems where you have explicit, written permission to test). 

Unauthorized use of this tool against targets without prior mutual consent is illegal. The author assumes no liability and is not responsible for any misuse, disruption, or damage caused by this script. 

Always adhere strictly to the target program's Rules of Engagement (RoE) and respect designated rate limits and out-of-scope declarations.

## Author
**Null0riginSec**

## License
This project is licensed under the MIT License.
