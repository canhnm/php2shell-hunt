# php2shell-hunt

Read-only triage over SSH for possible exploitation of the **PHP2Shell** vulnerabilities
(**CVE-2026-109618** / **CVE-2026-109619**) across a fleet of Linux servers.

The script connects to each server you list, runs a set of read-only checks (files, sessions,
web/error logs, crashes, processes, network, persistence) and writes one report per server plus
a summary on your machine. **Nothing is written, changed or restarted on the servers.**

> **This tool does not replace patching.** Apply the fixed PHP builds from the PHP Foundation or
> your distribution first. A clean result here is **not** proof that a server was not compromised
> (see [Limitations](#limitations)).

## Background

According to public reporting (The Hacker News, 22 Oct 2026, citing Amazon Threat Intelligence,
CrowdStrike and VulnCheck), PHP2Shell is a pair of PHP core vulnerabilities (CVSS 9.2) that allow
pre-authentication remote code execution on affected PHP 7.x and 8.x releases, and exploitation
attempts were observed in the wild starting 17 Oct 2026 and widely from 21 Oct 2026. The reporting
also states that a successful exploit leaves almost no trace: HTTP 200 responses, stable workers,
clean application logs, and a single *"Allowed memory size ... exhausted"* line in the web server
error log. This script is built around those points, plus the usual signs of what an attacker does
after getting code execution (webshells, new processes, persistence).

## Requirements

- **Machine running the script:** macOS or Linux with `bash` >= 3.2, `ssh`, `xargs`, `grep`, `sed`, `awk`.
- **Servers:** Linux with GNU `find`, `grep`, `ps`, and key-based SSH (no password prompts).
  Root, or a user with passwordless `sudo`, is needed to read all logs and process information.
- Nothing is installed on the servers.

## Quick start

```bash
git clone https://github.com/canhnm/php2shell-hunt.git
cd php2shell-hunt
chmod +x php2shell-hunt.sh

cp hosts.example.txt hosts.txt      # then edit hosts.txt with your servers
ONLY='^web-01$' ./php2shell-hunt.sh # try ONE server first
./php2shell-hunt.sh                 # then all servers in hosts.txt
```

Results are saved to `~/php2shell-hunt-<timestamp>/` (directory mode 700):

- `SUMMARY.txt` - table of `[!]` / `[?]` counts per server and the details of all `[!]` findings
- `<label>.txt` - the full report for each server

### Hosts file

One server per line, `#` starts a comment:

```text
# label  host            [port]
web-01   203.0.113.10
web-02   203.0.113.11     2222
198.51.100.7                      # host only: label = host, port 22
```

Labels may contain letters, digits, `.`, `_`, `-`. Hosts and ports are validated before use.
Pass a different file as the first argument: `./php2shell-hunt.sh /path/to/hosts.txt`.

## Options

All options are environment variables.

| Variable | Default | Meaning |
|---|---|---|
| `DAYS` | `14` | Look-back window (days) for file, log and persistence checks. Use at least `7` if you are checking from 17 Oct 2026 onward. |
| `ONLY` | *(all)* | Only run on labels matching this regex, e.g. `ONLY='^web-'`. |
| `PAR` | `6` | Number of servers scanned in parallel. |
| `IOC_FILE` | `./iocs.txt` | Extra IOC IP addresses (IPv4/IPv6), one per line, `#` for comments. Added to the built-in list. |
| `SSH_USER` | `root` | SSH login user. |
| `USE_SUDO` | `0` | Set to `1` to run the remote part with `sudo -n` (needs passwordless sudo). |
| `SSH_OPTS` | *(empty)* | Extra `ssh` options, e.g. `-i ~/.ssh/ops_key -J bastion`. |
| `WINDOW_START` | `2026/10/17` | Error-log memory-limit fatals on or after this date (`YYYY/MM/DD`) are listed per hour. |

Examples:

```bash
DAYS=30 ./php2shell-hunt.sh
SSH_USER=ubuntu USE_SUDO=1 SSH_OPTS='-i ~/.ssh/ops_key' ./php2shell-hunt.sh
IOC_FILE=./my-iocs.txt PAR=3 ./php2shell-hunt.sh
```

## What it checks

1. **Files** - PHP code inside upload/storage/media/tmp directories; PHP files owned by the web user
   or world-writable and recently modified; hidden PHP files; images/text containing `<?php`
   (polyglots); common webshell code patterns; `auto_prepend_file` / `auto_append_file`;
   scripts and executables in `/tmp`, `/var/tmp`, `/dev/shm`.
2. **Sessions** - PHP session files containing code or dangerous paths, and the number of sessions
   containing `upload_progress_` entries.
3. **Web access logs** - requests from IOC IPs, the `php2shell-scan` user-agent, exploit-style URLs
   answered with 200/500, successful requests to `.php` files inside upload directories, unusual
   PHP endpoints, and 5xx/499/413 counts per day.
4. **Web error logs** - `Allowed memory size ... exhausted` fatals per day and per hour since
   `WINDOW_START`, the clients and requests behind them, and IOC IPs.
5. **Crashes** - kernel segfault/OOM lines and php-fpm crash/memory messages.
6. **Behaviour and persistence** - shells/`curl`/`wget` spawned by php-fpm or Apache, processes of the
   web user that are not web/queue processes, reverse-shell and miner patterns, deleted or
   memfd-backed binaries, outbound connections owned by shells/interpreters, connections to IOC IPs,
   files written by the web user outside storage/tmp/log, new cron/systemd units, changed
   `authorized_keys`, extra UID-0 users, `ld.so.preload`, recently changed system binaries,
   successful SSH logins.

## Reading the output

| Marker | Meaning |
|---|---|
| `[!]` | Strong indicator - review immediately. |
| `[?]` | Needs review or correlation; often legitimate (deploys, patching, package upgrades). |
| `[i]` | Information (counts, baselines to compare against). |
| `[ok]` | Nothing found for that check. |

Tips:

- Your own deploys and patching create noise: recently changed PHP files, changed systemd units,
  changed system binaries, and new memory-limit log lines if you lowered `memory_limit`.
  Compare timestamps with your change history.
- For the error-log check, a steady trickle of memory-limit fatals is normal for many apps. Look for
  a **burst** from 17 Oct 2026 onward, especially from 21 Oct 2026 02:00 UTC.
- Treat any webshell pattern, PHP file in an upload directory, shell spawned by php-fpm, or
  connection to an IOC IP as a real incident until proven otherwise.

## Limitations

- **A clean result is not proof of safety.** Public reporting says a successful exploit can leave
  almost no trace.
- **CDN/proxy in front (e.g. Cloudflare):** web and error logs show the proxy's IP, not the real
  client, unless your web server logs the real client IP. IP matching can miss attacker IPs;
  correlate by time with your CDN's own logs.
- The built-in IOC list comes from public reporting dated 2026-10-22 and is **not exhaustive**.
- The nginx error-log date format (`YYYY/MM/DD`) is assumed for the per-hour breakdown; other
  formats are still scanned for the other checks.
- Web root detection reads nginx/Apache configuration. Unusual layouts (containers, custom paths)
  may need a manual look or an edit to the web-root detection near the top of the remote part of the script.
- Some exclusions are tuned for common PHP frameworks (e.g. `vendor/`, `storage/framework/views`,
  `bootstrap/cache`) and for common queue-worker process names; adjust them in the script for
  your stack.
- Output can contain attacker URLs, hostnames and process command lines. Review and redact before
  sharing.

## If you find something

1. **Isolate** the server from the network (prefer this to powering off if you want memory evidence).
2. **Preserve evidence** before cleaning: snapshot the disk, copy logs, copy suspicious files
   (do not delete them first).
3. **Rotate secrets** that were readable from that host: application `.env` files, database
   credentials, API keys, SSH keys.
4. Review database and outbound traffic for that host, rebuild from a known-good image, and patch PHP.
5. Check the other hosts that share credentials or networks with it.

## IOC sources

IP addresses and the user-agent are taken from public reporting dated 2026-10-22 (Amazon Threat
Intelligence, VulnCheck, via The Hacker News). They are defanged in the article and appear here as
plain addresses:

`103.216.220.92`, `31.223.184.166`, `37.19.200.5`, `134.209.159.64`, `103.114.163.188`,
`95.217.98.37`, `85.11.167.243`, `45.198.224.169`, `109.71.252.97`, and user-agent `php2shell-scan/109618`.

Add your own with `IOC_FILE`.

## Troubleshooting

- **`Permission denied (publickey)`** - the script uses `BatchMode`; make sure key-based login works
  (`ssh -p <port> <user>@<host>`) or pass `SSH_OPTS='-i /path/to/key'`.
- **`sudo: a password is required`** - `USE_SUDO=1` needs passwordless sudo (`sudo -n`), or use root.
- **A server shows `[!] SSH or remote script failed`** - open `<label>.txt` for the ssh error.
- **Slow scan** - lower `DAYS`, or reduce `PAR` on busy servers (log checks read rotated logs).

## Contributing

Issues and pull requests are welcome, especially: additional IOCs with a public source, support for
other log formats, and false-positive reports (please redact hostnames and IPs).

## License

Released under the [MIT License](LICENSE).

## Disclaimer

Provided as is, without warranty. It is a read-only triage helper, not a forensic or incident-response
product. Test it on one server first and review the script before running it against production.
