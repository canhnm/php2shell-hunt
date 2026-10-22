#!/usr/bin/env bash
#
# php2shell-hunt.sh - READ-ONLY triage for possible PHP2Shell exploitation
# (CVE-2026-109618 / CVE-2026-109619) across a list of Linux servers over SSH.
#
# Nothing is written, changed or restarted on the servers. Results are saved
# locally under ~/php2shell-hunt-<timestamp>/ (mode 700).
#
# USAGE
#   chmod +x php2shell-hunt.sh
#   ./php2shell-hunt.sh [hosts-file]
#
#   hosts-file (default ./hosts.txt), one server per line, "#" starts a comment:
#       web-01 203.0.113.10          # label host            (port 22)
#       web-02 203.0.113.11 2222     # label host port
#       198.51.100.7                 # host only (label = host, port 22)
#
# OPTIONS (environment variables)
#   DAYS=14               look-back window in days for file/log/persistence checks
#   ONLY='^web-'          only run on labels matching this regex
#   PAR=6                 number of servers scanned in parallel
#   IOC_FILE=./iocs.txt   extra IOC IP addresses, one per line ("#" = comment)
#   SSH_USER=root         SSH login user
#   USE_SUDO=1            run the remote part with "sudo -n" (needs passwordless sudo)
#   SSH_OPTS='-i ~/.ssh/key -J jump-host'   extra ssh options
#   WINDOW_START=2026/10/17   error-log hits on/after this date (YYYY/MM/DD) are
#                             listed per hour (nginx error-log date format)
#
# REQUIREMENTS
#   Local machine: bash >= 3.2 (macOS/Linux), ssh, xargs, grep, sed, awk.
#   Targets: Linux with GNU find/grep/ps and key-based SSH (BatchMode, no prompts).
#            Root (or sudo) is needed to read all logs and process information.
#
# WHAT IT CHECKS
#   1. Files    : PHP code in upload/storage/media/tmp directories, PHP files owned
#                 by the web user or world-writable, hidden PHP files, polyglot
#                 images/text containing "<?php", webshell code patterns,
#                 auto_prepend_file / auto_append_file, scripts in /tmp.
#   2. Sessions : PHP session files containing code or dangerous paths, and a count
#                 of sessions with "upload_progress_" entries.
#   3. Web logs : IOC IPs, the "php2shell-scan" user-agent, exploit-style URLs,
#                 requests to .php files inside upload directories, 5xx/499/413
#                 counts per day.
#      Error logs: "Allowed memory size ... exhausted" fatals per day/hour, clients
#                 and requests behind them, IOC IPs. Public reporting describes
#                 this as the only server-side trace of a successful exploit.
#   4. Crashes  : kernel segfault/OOM lines and php-fpm crash/memory messages.
#   5. Behaviour: shells/curl/wget spawned by php-fpm/apache, processes of the web
#                 user, reverse-shell/miner patterns, deleted or memfd binaries,
#                 outbound connections from shells, new cron/systemd/authorized_keys,
#                 UID-0 users, ld.so.preload, recently changed system binaries,
#                 successful SSH logins.
#
# OUTPUT LEVELS
#   [!]  strong indicator, review immediately
#   [?]  needs review / correlation (may be legitimate: deploys, patching, ...)
#   [i]  information
#   [ok] nothing found
#
# LIMITATIONS - PLEASE READ
#   * Public reporting says a successful exploit leaves almost no trace (HTTP 200,
#     stable workers, clean application logs). A clean result is NOT proof that a
#     server was not compromised.
#   * Behind a CDN/proxy (e.g. Cloudflare) web and error logs show the proxy IP,
#     not the real client; IP-based matching can miss attacker IPs unless your web
#     server logs the real client IP. Correlate by time with the CDN's own logs.
#   * File/log findings after your own patching can be noise: changing memory_limit
#     or restarting services produces new log lines and recently changed files.
#   * The built-in IOC list comes from public reporting dated 2026-10-22 (Amazon
#     Threat Intelligence, VulnCheck, The Hacker News) and is not exhaustive.
#   * Output may contain attacker URLs, hostnames and process command lines.
#     Review and redact before sharing it.
#   * Provided as is, without warranty. Test on one server first, e.g.
#     ONLY='^web-01$' ./php2shell-hunt.sh

set -u
umask 077

DAYS="${DAYS:-14}"
HOSTS_FILE="${1:-${HOSTS_FILE:-./hosts.txt}}"
ONLY="${ONLY:-}"
PAR="${PAR:-6}"
IOC_FILE="${IOC_FILE:-./iocs.txt}"
SSH_USER="${SSH_USER:-root}"
SSH_OPTS="${SSH_OPTS:-}"
USE_SUDO="${USE_SUDO:-0}"
WINDOW_START="${WINDOW_START:-2026/10/17}"

case "$DAYS" in ''|*[!0-9]*) echo "DAYS must be a number"; exit 1;; esac
case "$PAR" in ''|*[!0-9]*|0) echo "PAR must be a positive number"; exit 1;; esac
if ! printf '%s' "$WINDOW_START" | grep -qE '^[0-9]{4}/[0-9]{2}/[0-9]{2}$'; then
  echo "WINDOW_START must look like YYYY/MM/DD"; exit 1
fi
if [ ! -f "$HOSTS_FILE" ]; then
  echo "Hosts file not found: $HOSTS_FILE"
  echo "Create it with one server per line, e.g.:  web-01 203.0.113.10 22"
  exit 1
fi

OUT="$HOME/php2shell-hunt-$(date +%Y%m%d-%H%M)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$OUT"

# --- IOC IPs from public reporting (2026-10-22) plus optional IOC_FILE
IOC_DEFAULT="103.216.220.92 31.223.184.166 37.19.200.5 134.209.159.64 103.114.163.188 95.217.98.37 85.11.167.243 45.198.224.169 109.71.252.97"
IOC_LIST="$IOC_DEFAULT"
if [ -f "$IOC_FILE" ]; then
  IOC_LIST="$IOC_LIST $(grep -vE '^[[:space:]]*(#|$)' "$IOC_FILE" | tr -d '\r ' | tr '\n' ' ')"
  echo "Loaded extra IOCs from $IOC_FILE"
fi
IOC_RE="$(printf '%s\n' $IOC_LIST | sort -u | sed 's/\./\\./g' | paste -sd'|' -)"
if printf '%s' "$IOC_RE" | grep -qE '[^0-9A-Fa-f:.\\|]'; then
  echo "IOC list contains invalid characters; only IPv4/IPv6 addresses are allowed"; exit 1
fi
echo "Matching $(printf '%s\n' $IOC_LIST | sort -u | wc -l | tr -d ' ') IOC IPs and the 'php2shell-scan' user-agent"

# --- parse and validate the hosts file -> "label|host|port"
TARGETS="$TMP/targets.txt"; : > "$TARGETS"
while read -r a b c _rest; do
  case "$a" in ''|\#*) continue;; esac
  if [ -z "${b:-}" ]; then label="$a"; host="$a"; port=22
  else label="$a"; host="$b"; port="${c:-22}"; fi
  if ! printf '%s' "$label" | grep -qE '^[A-Za-z0-9._-]+$'; then echo "Skipping invalid label: $label"; continue; fi
  if ! printf '%s' "$host"  | grep -qE '^[A-Za-z0-9][A-Za-z0-9._:-]*$'; then echo "Skipping invalid host: $host"; continue; fi
  if ! printf '%s' "$port"  | grep -qE '^[0-9]{1,5}$'; then echo "Skipping invalid port for $label: $port"; continue; fi
  if [ -n "$ONLY" ] && ! printf '%s' "$label" | grep -qE -- "$ONLY"; then continue; fi
  echo "$label|$host|$port" >> "$TARGETS"
done < "$HOSTS_FILE"
if [ ! -s "$TARGETS" ]; then echo "No servers to scan (check $HOSTS_FILE and ONLY)"; exit 1; fi

# ======================= REMOTE PART (read-only) =======================
cat > "$TMP/remote.sh" <<'REMOTE'
main() {
export LC_ALL=C
DAYS="${DAYS:-14}"
IOC_RE="${IOC_RE:-}"
WINDOW_START="${WINDOW_START:-2026/10/17}"
sec() { echo; echo "##### $*"; }
# emit LEVEL TITLE : read stdin; print matching lines with a level prefix, else "[ok] ... none"
emit() {
  lvl="$1"; shift; title="$*"
  tmp="$(head -n 40 | cut -c1-260)"
  if [ -n "$tmp" ]; then
    echo "--- $title"
    printf '%s\n' "$tmp" | sed "s/^/[$lvl] /"
  else
    echo "[ok] $title: none"
  fi
}

sec "HOST"
echo "[i] $(hostname) | $(date -u '+%F %T UTC') | $(uptime -p 2>/dev/null) | window ${DAYS} days"
echo "[i] running services: $(systemctl list-units --type=service --state=running 2>/dev/null | grep -oE 'php[0-9.]+-fpm|nginx|apache2|supervisor|redis-server' | sort -u | tr '\n' ' ')"
for b in /usr/sbin/php-fpm[0-9]*; do [ -x "$b" ] && echo "[i] $("$b" -v 2>/dev/null | head -1)"; done

# ---- locate web roots (from nginx/apache config) and their parent directories
ROOTS=""
for r in $( { nginx -T 2>/dev/null | awk '$1=="root"{gsub(";","",$2);print $2}'; grep -rhiE '^[[:space:]]*DocumentRoot' /etc/apache2 /etc/httpd 2>/dev/null | awk '{gsub("\"","",$2);print $2}'; } | sort -u); do
  if [ -d "$r" ]; then
    ROOTS="$ROOTS $r"
    p="$(dirname "$r")"
    case "$p" in /|/var|/home|/usr|/opt|/srv|/etc) ;; *) ROOTS="$ROOTS $p";; esac
  fi
done
[ -d /var/www ] && ROOTS="$ROOTS /var/www"
ROOTS="$ROOTS ${EXTRA_ROOTS:-}"
ROOTS="$(printf '%s\n' $ROOTS | sort -u | tr '\n' ' ')"
echo "[i] web roots scanned: ${ROOTS:-<none found>}"

# find under the web roots, skipping dependency/cache/log trees that are noisy by design
ffind() { [ -n "$ROOTS" ] && timeout 240 nice -n 19 find $ROOTS -xdev \( -path '*/vendor' -o -path '*/node_modules' -o -path '*/.git' -o -path '*/storage/framework/views' -o -path '*/bootstrap/cache' -o -path '*/storage/logs' \) -prune -o "$@"; }
phpext() { ffind -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' -o -iname '*.pht' -o -iname '*.php5' -o -iname '*.php7' -o -iname '*.inc' \) "$@"; }

# ================= 1. FILES =================
sec "1. FILES: webshells / unexpected files"
phpext \( -path '*/storage/app/*' -o -path '*/public/storage/*' -o -path '*/uploads/*' -o -path '*/upload/*' -o -path '*/public/images/*' -o -path '*/public/files/*' -o -path '*/media/*' -o -path '*/tmp/*' \) -printf '%TY-%Tm-%Td %TH:%TM %u %m %p\n' | sort -r | emit '!' "PHP code inside upload/storage/media/tmp directories (should not exist)"
WU=(); for u in www-data nginx apache nobody; do getent passwd "$u" >/dev/null 2>&1 && { [ ${#WU[@]} -gt 0 ] && WU+=(-o); WU+=(-user "$u"); }; done
[ ${#WU[@]} -gt 0 ] && phpext -mtime -"$DAYS" \( "${WU[@]}" \) -printf '%TY-%Tm-%Td %TH:%TM %u %m %p\n' | sort -r | emit '!' "PHP files owned by the web user, modified in the last ${DAYS} days"
phpext -mtime -"$DAYS" -perm -o+w -printf '%TY-%Tm-%Td %TH:%TM %u %m %p\n' | sort -r | emit '!' "world-writable PHP files, modified in the last ${DAYS} days"
ffind -type f -iname '.*.php' -printf '%TY-%Tm-%Td %TH:%TM %u %p\n' | emit '!' "hidden PHP files (name starts with a dot)"
ffind -type f -name '.user.ini' -printf '%TY-%Tm-%Td %TH:%TM %p\n' | emit '?' ".user.ini files (can be abused for auto_prepend_file)"
phpext -mtime -"$DAYS" -printf '%TY-%Tm-%Td %TH:%TM %u %p\n' | sort -r | emit 'i' "PHP files (excluding vendor/views/cache) modified in the last ${DAYS} days - compare with your deploy history"

# polyglot files: PHP code hidden in image/text uploads
ffind -type f \( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.gif' -o -iname '*.webp' -o -iname '*.ico' -o -iname '*.txt' -o -iname '*.svg' \) \( -path '*/storage/app/*' -o -path '*/public/storage/*' -o -path '*/uploads/*' -o -path '*/upload/*' -o -path '*/public/images/*' -o -path '*/public/files/*' -o -path '*/media/*' \) -mtime -"$DAYS" -print0 | xargs -0 -r grep -laE '<\?(php|=)' 2>/dev/null | emit '!' "image/text files in upload dirs containing <?php (polyglot)"

# common webshell code patterns in recently modified PHP files
PATS=(
 -e 'eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13)'
 -e '(eval|assert|system|shell_exec|passthru|exec|popen|proc_open)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)'
 -e 'base64_decode[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)'
 -e '\$_(GET|POST|REQUEST|COOKIE)\[[^]]*\][[:space:]]*\('
 -e 'FilesMan|c99shell|r57shell|b374k|php2shell|WSO[[:space:]]*Shell'
)
phpext -mtime -"$DAYS" -print0 | xargs -0 -r grep -laE "${PATS[@]}" 2>/dev/null | emit '!' "recently modified PHP files with webshell patterns (eval/base64/\$_POST...)"

# auto_prepend_file / auto_append_file with a value
{ grep -rnE '^[[:space:]]*(auto_prepend_file|auto_append_file)[[:space:]]*=[[:space:]]*[^[:space:];]' /etc/php /etc/apache2 /etc/nginx 2>/dev/null; [ -n "$ROOTS" ] && grep -rnE '(auto_prepend_file|auto_append_file)[[:space:]]*[= ][[:space:]]*[^[:space:];]' $ROOTS --include=.htaccess --include=.user.ini --include=php.ini 2>/dev/null; } | emit '!' "auto_prepend_file / auto_append_file set to a value"

find /tmp /var/tmp /dev/shm -xdev -type f \( -iname '*.php*' -o -iname '*.sh' -o -iname '*.pl' -o -iname '*.py' -o -perm -u+x \) -printf '%TY-%Tm-%Td %TH:%TM %u %m %p\n' 2>/dev/null | sort -r | emit '!' "scripts/executables in /tmp, /var/tmp, /dev/shm"
find /tmp /var/tmp -xdev -maxdepth 1 -name '.*' ! -name '.' ! -name '..' ! -name '.X11-unix' ! -name '.ICE-unix' ! -name '.font-unix' ! -name '.Test-unix' ! -name '.XIM-unix' -printf '%TY-%Tm-%Td %p\n' 2>/dev/null | emit '?' "hidden entries in /tmp, /var/tmp"
echo "[i] stale PHP upload temp files (php*) in /tmp, /var/tmp: $(find /tmp /var/tmp -xdev -maxdepth 1 -type f -name 'php*' -mtime +0 2>/dev/null | wc -l)  (many = interrupted/crashed uploads)"

# ================= 2. SESSIONS =================
sec "2. SESSIONS (session.upload_progress)"
SDIRS="/var/lib/php/sessions $(find $ROOTS -xdev -type d -path '*/storage/framework/sessions' 2>/dev/null | tr '\n' ' ')"
for d in $SDIRS; do
  [ -d "$d" ] || continue
  echo "[i] $d: $(ls -f "$d" 2>/dev/null | wc -l) files; containing 'upload_progress_': $(grep -rla 'upload_progress_' "$d" 2>/dev/null | wc -l)"
  grep -rlaE '<\?(php|=)|php://|\.\./\.\./|/etc/passwd|/proc/self' "$d" 2>/dev/null | emit '!' "session files in $d with code or dangerous paths"
done
find /var/lib/php/sessions -maxdepth 1 -type f ! -name 'sess_*' 2>/dev/null | emit '?' "unexpected files in the PHP session directory"

# ================= 3. WEB ACCESS LOGS =================
sec "3. WEB ACCESS LOGS (nginx/apache, ${DAYS} days + rotation margin)"
LOGS="$(ls /var/log/nginx/*access*.log* /var/log/apache2/*access*.log* /var/log/httpd/*access*.log* 2>/dev/null | while read -r f; do [ -n "$(find "$f" -mtime -$((DAYS+1)) 2>/dev/null)" ] && echo "$f"; done)"
echo "[i] access log files: $(echo $LOGS | wc -w)"
zc() { for f in $LOGS; do case "$f" in *.gz) zcat "$f" 2>/dev/null;; *) cat "$f" 2>/dev/null;; esac; done; }
if [ -n "$LOGS" ]; then
  if [ -n "$IOC_RE" ]; then
    zc | timeout 240 grep -aE "(^|[^0-9.])(${IOC_RE})([^0-9]|\$)" | emit '!' "requests from IOC IPs"
  else
    echo "[i] no IOC list -> skipping IOC IP matching"
  fi
  zc | timeout 240 grep -aiE 'php2shell-scan' | cut -c1-240 | emit '!' "user-agent php2shell-scan (known scanner)"
  zc | timeout 240 grep -aiE 'php://|data://|expect://|phar://|zip://|%2e%2e%2f|\.\./\.\./|%00|PHP_SESSION_UPLOAD_PROGRESS|auto_prepend_file|allow_url_include|/proc/self/|/etc/passwd|[?&](cmd|exec|shell)=|base64_decode|eval\(|wget%20|curl%20|whoami|%24_(GET|POST)' | grep -aE '" (200|500) ' | cut -c1-240 | emit '!' "exploit-style URLs answered with 200/500"
  zc | timeout 240 grep -aE '"(GET|POST) [^ ]*/(storage|uploads?|images|files|media|tmp|public)/[^ ?]*\.(php|phtml|phar|pht)[^ ]* HTTP[^"]*" (200|500)' | cut -c1-240 | emit '!' "successful requests to .php files inside upload directories"
  zc | timeout 240 grep -aE '" 200 ' | grep -aoE '"(GET|POST|HEAD) [^ ?]+\.php' | awk '{print $2}' | sort | uniq -c | sort -rn | grep -vE ' /index\.php$' | head -25 | emit 'i' "PHP endpoints other than index.php answered with 200 (count, path) - look for odd or single-hit paths"
  zc | timeout 240 grep -aoE '\[[0-9]{2}/[A-Za-z]{3}/[0-9]{4}[^]]*\] "[^"]*" [0-9]{3}' | sed -E 's/^\[([0-9]{2}\/[A-Za-z]{3}\/[0-9]{4}).*" ([0-9]{3})$/\1 \2/' | awk '($2>=500)||$2==499||$2==413{c[$1" "$2]++} END{for(k in c) print c[k], k}' | sort -k2 | emit 'i' "5xx/499/413 responses per day (spikes may indicate crashes/OOM during exploitation)"
  zc | timeout 240 grep -aE '"POST [^"]*" 5[0-9]{2} ' | awk '{print $1}' | sort | uniq -c | sort -rn | head -10 | emit 'i' "top client IPs with POST requests answered 5xx (behind a CDN this is the proxy IP)"
else
  echo "[?] no access logs found within ${DAYS} days"
fi

# ================= 3b. ERROR LOGS =================
sec "3b. ERROR LOGS: memory-limit fatals (nginx/apache error logs, ${DAYS} days)"
echo "[i] Public reporting: a successful exploit leaves a single 'Allowed memory size ... exhausted' line in the web server error log while the access log shows HTTP 200. Look for spikes on/after ${WINDOW_START}; lowering memory_limit as a mitigation can itself create new lines."
ELOGS="$(ls /var/log/nginx/*error*.log* /var/log/apache2/*error*.log* /var/log/httpd/*error*.log* 2>/dev/null | while read -r f; do [ -n "$(find "$f" -mtime -$((DAYS+1)) 2>/dev/null)" ] && echo "$f"; done)"
ze() { for f in $ELOGS; do case "$f" in *.gz) zcat "$f" 2>/dev/null;; *) cat "$f" 2>/dev/null;; esac; done; }
if [ -n "$ELOGS" ]; then
  ze | grep -aE 'Allowed memory size .* exhausted' | grep -aoE '^[0-9]{4}/[0-9]{2}/[0-9]{2}' | sort | uniq -c | emit 'i' "'Allowed memory size exhausted' lines per day (nginx error log format)"
  ze | grep -aE 'Allowed memory size .* exhausted' | awk -v s="$WINDOW_START" '$1>=s{print substr($0,1,13)}' | sort | uniq -c | emit '?' "memory-limit fatals per hour since ${WINDOW_START} (server time) - look for bursts"
  ze | grep -aE 'Allowed memory size .* exhausted' | grep -aoE 'client: [0-9a-fA-F:.]+' | sort | uniq -c | sort -rn | head -15 | emit 'i' "clients behind memory-limit fatals (behind a CDN: correlate times with CDN logs)"
  ze | grep -aE 'Allowed memory size .* exhausted' | grep -aoE 'request: "[^"]{0,70}' | sort | uniq -c | sort -rn | head -10 | emit 'i' "requests behind memory-limit fatals"
  if [ -n "$IOC_RE" ]; then
    ze | grep -aE "(^|[^0-9.])(${IOC_RE})([^0-9]|\$)" | emit '!' "IOC IPs in error logs"
  fi
else
  echo "[?] no error logs found within ${DAYS} days"
fi

# ================= 4. CRASHES / OOM =================
sec "4. CRASHES / OOM (worker failures that can accompany exploitation)"
journalctl -k --since "-${DAYS}days" --no-pager 2>/dev/null | grep -aiE 'segfault|general protection|oom-kill|out of memory|killed process' | tail -15 | emit '?' "kernel: segfault/OOM"
for f in /var/log/php*fpm*.log*; do [ -f "$f" ] && { case "$f" in *.gz) zcat "$f";; *) cat "$f";; esac; }
done 2>/dev/null | grep -aE 'SIGSEGV|SIGABRT|SIGBUS|exited on signal|Allowed memory size|reached pm\.max_children' | tail -15 | emit '?' "php-fpm log: crashes / memory / max_children (check dates at the end of each line)"

# ================= 5. BEHAVIOUR / PERSISTENCE =================
sec "5. BEHAVIOUR: processes / network / persistence"
# processes of the web user that are not web or common queue-worker processes (adjust the exclusion list to your stack)
ps -eo user:20,pid,ppid,etime,args --no-headers 2>/dev/null | awk '$1=="www-data"||$1=="nginx"||$1=="apache"||$1=="nobody"' | grep -vE 'php-fpm|nginx:|apache2|httpd|php-cgi|supervisor|artisan|horizon|queue:work|redis' | emit '!' "processes of the web user that are not web/queue processes (shell? tool?)"
FPIDS=" $(pgrep -f 'php-fpm|apache2|httpd' 2>/dev/null | tr '\n' ' ') "
ps -eo pid,ppid,user:20,comm,args --no-headers 2>/dev/null | awk -v p="$FPIDS" 'index(p," "$2" ")>0 && $4 ~ /^(sh|bash|dash|zsh|curl|wget|nc|ncat|socat|python[0-9.]*|perl|ruby|busybox|tar|chmod|crontab)$/' | emit '!' "shell/curl/wget running as a child of php-fpm/apache (PHP spawning shells or downloading files)"
WU2=(); for u in www-data nginx apache nobody; do getent passwd "$u" >/dev/null 2>&1 && { [ ${#WU2[@]} -gt 0 ] && WU2+=(-o); WU2+=(-user "$u"); }; done
[ ${#WU2[@]} -gt 0 ] && timeout 240 nice -n 19 find / -xdev \( -path /proc -o -path /sys -o -path /var/lib/php/sessions -o -path /var/cache -o -path /var/log -o -path /var/lib/mysql -o -path '*/storage' -o -path '*/bootstrap/cache' -o -path '*/node_modules' -o -path '*/.git' -o -path /tmp -o -path /var/tmp \) -prune -o -type f \( "${WU2[@]}" \) -mtime -"$DAYS" -printf '%TY-%Tm-%Td %TH:%TM %u %m %p\n' 2>/dev/null | sort -r | emit '?' "files created/modified by the web user outside storage/tmp/log in the last ${DAYS} days (payloads may land here)"
ps -eo pid,user:20,args --no-headers 2>/dev/null | grep -aE 'nc -e|ncat |socat |/dev/tcp/|bash -i|python[0-9.]* -c .*socket|perl -e|xmrig|minerd|kdevtmpfsi|kinsing' | grep -v grep | emit '!' "processes resembling reverse shells / miners"
ls -l /proc/[0-9]*/exe 2>/dev/null | grep ' (deleted)' | grep -v 'memfd:' | emit '!' "processes running from deleted binaries"
ls -l /proc/[0-9]*/exe 2>/dev/null | grep 'memfd:' | emit '?' "processes running from memfd (fileless; some runtimes/agents do this legitimately)"
ss -tnpH state established 2>/dev/null | grep -aE '"(sh|bash|dash|nc|ncat|socat|python[0-9.]*|perl|curl|wget|ruby)"' | emit '!' "established connections owned by shells/interpreters"
[ -n "$IOC_RE" ] && ss -tnH 2>/dev/null | grep -aE "(^|[^0-9.])(${IOC_RE})([^0-9]|\$)" | emit '!' "connections to/from IOC IPs"
ss -tlnpH 2>/dev/null | awk '{print $4, $6}' | sort -u | emit 'i' "listening ports (compare with your baseline)"
[ -e /etc/ld.so.preload ] && { echo "[!] /etc/ld.so.preload exists:"; cut -c1-200 /etc/ld.so.preload; }
awk -F: '$3==0 && $1!="root"{print}' /etc/passwd | emit '!' "UID 0 users other than root"
find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron /etc/crontab /etc/rc.local -type f -mtime -"$DAYS" -printf '%TY-%Tm-%Td %p\n' 2>/dev/null | emit '?' "cron/rc.local changed in the last ${DAYS} days"
crontab -l -u www-data 2>/dev/null | grep -vE '^[[:space:]]*(#|$)' | emit '?' "crontab of www-data (normally empty)"
find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system -type f -mtime -"$DAYS" -printf '%TY-%Tm-%Td %p\n' 2>/dev/null | emit '?' "systemd units changed in the last ${DAYS} days (your own patching/hardening will show up here)"
find /root /home -maxdepth 3 \( -name authorized_keys -o -name authorized_keys2 \) -mtime -"$DAYS" -printf '%TY-%Tm-%Td %p\n' 2>/dev/null | emit '!' "authorized_keys changed in the last ${DAYS} days"
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do [ -f "$f" ] && echo "$f: $(grep -c '^ssh-\|^ecdsa-\|^sk-' "$f") keys"; done | emit 'i' "number of keys in authorized_keys files"
find /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin -xdev -type f -mtime -"$DAYS" -printf '%TY-%Tm-%Td %p\n' 2>/dev/null | head -30 | emit '?' "system binaries changed in the last ${DAYS} days (package upgrades also cause this)"
{ journalctl -u ssh -u sshd --since "-${DAYS}days" --no-pager 2>/dev/null; zcat -f /var/log/auth.log* 2>/dev/null; } | grep -a 'Accepted' | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1), $(i-1)}' | sort | uniq -c | sort -rn | head -15 | emit 'i' "successful SSH logins (count, source IP, user) - compare with your known admin IPs"
echo; echo "##### DONE $(hostname)"
}
main </dev/null
REMOTE

# ======================= LOCAL PART =======================
export OUT TMP DAYS IOC_RE SSH_USER SSH_OPTS USE_SUDO WINDOW_START

run_one() {
  label="${1%%|*}"; rest="${1#*|}"; host="${rest%%|*}"; port="${rest#*|}"
  out="$OUT/$label.txt"
  if [ "$USE_SUDO" = "1" ]; then rcmd="sudo -n bash -s"; else rcmd="bash -s"; fi
  {
    echo "DAYS=$DAYS"
    echo "IOC_RE='$IOC_RE'"
    echo "WINDOW_START='$WINDOW_START'"
    cat "$TMP/remote.sh"
  } | ssh -p "$port" -o ConnectTimeout=10 -o BatchMode=yes -o ServerAliveInterval=15 $SSH_OPTS -- "$SSH_USER@$host" "$rcmd" > "$out" 2>&1
  rc=$?
  [ $rc -ne 0 ] && echo "[!] SSH or remote script failed (rc=$rc)" >> "$out"
  echo "done $label rc=$rc"
}
export -f run_one

echo "Started $(date '+%F %T') - $(wc -l < "$TARGETS" | tr -d ' ') server(s), $PAR in parallel - results: $OUT"
xargs -P "$PAR" -I{} bash -c 'run_one "$1"' _ {} < "$TARGETS"

# ---- summary
SUM="$OUT/SUMMARY.txt"
{
  echo "php2shell-hunt $(date '+%F %T')  DAYS=$DAYS"
  printf '%-26s %6s %6s\n' HOST '[!]' '[?]'
  for f in "$OUT"/*.txt; do
    [ "$(basename "$f")" = "SUMMARY.txt" ] && continue
    printf '%-26s %6s %6s\n' "$(basename "$f" .txt)" "$(grep -c '^\[!\]' "$f")" "$(grep -c '^\[?\]' "$f")"
  done
  echo
  echo "===== DETAILS: [!] FINDINGS ====="
  for f in "$OUT"/*.txt; do
    [ "$(basename "$f")" = "SUMMARY.txt" ] && continue
    if grep -q '^\[!\]' "$f"; then echo "## $(basename "$f" .txt)"; grep -E '^(---|\[!\])' "$f" | grep -B1 '^\[!\]' | grep -v '^--$' | cut -c1-240; fi
  done
} > "$SUM"
cat "$SUM"
echo; echo "Per-server details: $OUT/<label>.txt"
