#!/usr/bin/env bash
# blueteam-audit.sh - Bestandsaufnahme & Integritaetspruefung fuer Debian/Ubuntu
# Sammelt den Systemzustand in einem Report-Verzeichnis, laesst etablierte
# Audit-Tools (Lynis, debsums, rkhunter, chkrootkit) laufen, wertet deren
# Ergebnisse aus und gibt am Ende eine gegliederte Gesamt-Summary aus.
# Das Script veraendert nichts am System (ausser optional: apt install der Tools).
#
# Nutzung:  sudo ./blueteam-audit.sh [--install-tools] [--force-install] [--days N]
#   --install-tools   installiert fehlende Tools (lynis debsums rkhunter chkrootkit)
#                     per apt - aber NUR wenn die APT-Repo-Pruefung sauber ist
#   --force-install   installiert auch, wenn die Repo-Pruefung HIGH-Funde hat
#   --days N          Zeitraum fuer "kuerzlich geaendert" & Logs (Default: 45)
#   --sample N        Sekunden, die Verbindungen & Prozesse beobachtet werden (Default: 60, 0 = aus)
#   --fetch-originals laedt Original-.debs der Dienst-Pakete (nur bei sauberer Repo-Pruefung),
#                     um Configs zu diffen und Binaries gegen das Original zu vergleichen
#   --trace N         beobachtet jeden Custom-Service N Sekunden mit strace (process,network)

set -u
export LC_ALL=C

DAYS=45
SAMPLE=60
FETCH=0
TRACE=0
INSTALL=0
FORCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --install-tools) INSTALL=1 ;;
    --force-install) INSTALL=1; FORCE=1 ;;
    --days) shift; DAYS="${1:-45}" ;;
    --sample) shift; SAMPLE="${1:-60}" ;;
    --fetch-originals) FETCH=1 ;;
    --trace) shift; TRACE="${1:-30}" ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "Unbekannte Option: $1" >&2; exit 1 ;;
  esac
  shift
done

if [ "$(id -u)" -ne 0 ]; then
  echo "Bitte als root ausfuehren (sudo)." >&2
  exit 1
fi

TS="$(date +%Y%m%d-%H%M%S)"
OUT="/root/blueteam-audit-$(hostname)-$TS"
mkdir -p "$OUT"
chmod 700 "$OUT"
FINDINGS="$OUT/findings.tsv"     # LEVEL<TAB>KATEGORIE<TAB>Text
SUMMARY="$OUT/00-SUMMARY.txt"
: > "$FINDINGS"
HARDENING_INDEX="n/a"

RED=$'\e[31m'; YEL=$'\e[33m'; GRN=$'\e[32m'; BLU=$'\e[34m'; CYA=$'\e[36m'; BLD=$'\e[1m'; RST=$'\e[0m'

section() { echo; echo "${BLU}==> $*${RST}"; }

# finding LEVEL KATEGORIE TEXT   (LEVEL: HIGH | MED | LOW | INFO)
finding() {
  local col="$YEL"
  case "$1" in HIGH) col="$RED" ;; LOW) col="$CYA" ;; INFO) col="$GRN" ;; esac
  printf '   %s[%s]%s %s\n' "$col" "$1" "$RST" "$3"
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$FINDINGS"
}
run() { # run DATEI KOMMANDO... ; schreibt Ausgabe in Report-Datei
  local f="$OUT/$1"; shift
  { echo "# $*"; echo; "$@"; } > "$f" 2>&1
}
have() { command -v "$1" >/dev/null 2>&1; }
count() { grep -c . "$1" 2>/dev/null || true; }
owned() { # gehoert die Datei zu einem Debian-Paket? (beruecksichtigt merged-/usr)
  local f="$1" r
  dpkg -S "$f" >/dev/null 2>&1 && return 0
  r=$(readlink -f "$f" 2>/dev/null)
  [ -n "$r" ] && [ "$r" != "$f" ] && dpkg -S "$r" >/dev/null 2>&1 && return 0
  case "$r" in /usr/bin/*|/usr/sbin/*|/usr/lib/*|/usr/lib64/*) dpkg -S "${r#/usr}" >/dev/null 2>&1 && return 0 ;; esac
  case "$f" in /bin/*|/sbin/*|/lib/*) dpkg -S "/usr$f" >/dev/null 2>&1 && return 0 ;; esac
  return 1
}
declare -A OWN_CACHE
owned_c() { # wie owned, aber mit Cache (nur im Haupt-Shell-Kontext wirksam)
  local k="$1"
  if [ -z "${OWN_CACHE[$k]+x}" ]; then
    if owned "$k"; then OWN_CACHE[$k]=1; else OWN_CACHE[$k]=0; fi
  fi
  [ "${OWN_CACHE[$k]}" = 1 ]
}
pkg_of() { # Paketname zu einer Datei (beruecksichtigt merged-/usr)
  local f="$1" c cand r
  for c in "$f" "$(readlink -f "$f" 2>/dev/null)"; do
    [ -n "$c" ] || continue
    for cand in "$c" "${c#/usr}" "/usr$c"; do
      r=$(dpkg -S "$cand" 2>/dev/null | grep -v '^diversion' | head -1 | sed 's/: \/.*//' | cut -d, -f1 | cut -d: -f1 | tr -d ' ')
      [ -n "$r" ] && { echo "$r"; return 0; }
    done
  done
  return 1
}
case "$SAMPLE" in ''|*[!0-9]*) SAMPLE=60 ;; esac
case "$TRACE" in ''|*[!0-9]*) TRACE=30 ;; esac
case "$DAYS" in ''|*[!0-9]*) DAYS=45 ;; esac
SINCE_DATE="$(date -d "-$DAYS days" '+%Y-%m-%d')"

echo "${BLD}Blue-Team Audit $(hostname) - $(date)${RST}"
echo "Report-Verzeichnis: $OUT"

# ===========================================================================
section "APT-Repositories & Paketquellen pruefen (vor jeder Installation)"
REPO_HIGH_BEFORE=0
OFFICIAL_RE='^(https?|tor\+https?)://([a-z0-9.-]+\.)?(debian\.org|ubuntu\.com|canonical\.com)(/|$)'
PPA_RE='^https?://(ppa\.launchpad\.net|ppa\.launchpadcontent\.net)/'

{
  echo "== Quellen"
  for f in /etc/apt/sources.list /etc/apt/sources.list.d/*; do
    [ -f "$f" ] && { echo "--- $f"; ls -la "$f"; grep -vE '^\s*(#|$)' "$f"; }
  done
  echo; echo "== apt.conf / apt.conf.d"
  for f in /etc/apt/apt.conf /etc/apt/apt.conf.d/*; do
    [ -f "$f" ] && { echo "--- $f"; grep -vE '^\s*(//|#|$)' "$f"; }
  done
  echo; echo "== Pinning (preferences)"
  for f in /etc/apt/preferences /etc/apt/preferences.d/*; do
    [ -f "$f" ] && { echo "--- $f"; cat "$f"; }
  done
  echo; echo "== Keyrings"
  ls -la /etc/apt/trusted.gpg /etc/apt/trusted.gpg.d /etc/apt/keyrings /usr/share/keyrings 2>/dev/null
} > "$OUT/01-apt-repos.txt" 2>&1

# 1) Einzeilige Quellen (.list)
for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do
  [ -f "$f" ] || continue
  grep -E '^\s*deb(-src)?\s' "$f" | while IFS= read -r line; do
    if echo "$line" | grep -qiE 'trusted=yes|allow-insecure=yes|allow-weak=yes|allow-downgrade-to-insecure=yes'; then
      finding HIGH REPOS "Signaturpruefung deaktiviert in $f: $line"
    fi
    uri=$(echo "$line" | sed -E 's/\[[^]]*\]//' | awk '{print $2}')
    if echo "$uri" | grep -qiE "$OFFICIAL_RE"; then :;
    elif echo "$uri" | grep -qiE "$PPA_RE"; then finding INFO REPOS "PPA eingebunden: $uri ($f)"
    else finding MED REPOS "Nicht-offizielle Paketquelle: $uri ($f)"
    fi
  done
done
# 2) deb822-Quellen (.sources)
for f in /etc/apt/sources.list.d/*.sources; do
  [ -f "$f" ] || continue
  grep -qiE '^\s*(Trusted|Allow-Insecure|Allow-Weak|Allow-Downgrade-To-Insecure):\s*yes' "$f" && \
    finding HIGH REPOS "Signaturpruefung deaktiviert in $f"
  grep -iE '^\s*URIs:' "$f" | sed -E 's/^\s*URIs:\s*//I' | tr ' ' '\n' | grep . | while read -r uri; do
    if echo "$uri" | grep -qiE "$OFFICIAL_RE"; then :;
    elif echo "$uri" | grep -qiE "$PPA_RE"; then finding INFO REPOS "PPA eingebunden: $uri ($f)"
    else finding MED REPOS "Nicht-offizielle Paketquelle: $uri ($f)"
    fi
  done
done
# 3) APT-Konfiguration: Signaturen aus, Proxy, Hooks
APTCONF=$(ls /etc/apt/apt.conf /etc/apt/apt.conf.d/* 2>/dev/null)
for f in $APTCONF; do
  [ -f "$f" ] || continue
  grep -nviE '^\s*(//|#)' "$f" | grep -iE 'AllowUnauthenticated|AllowInsecureRepositories|AllowDowngradeToInsecure|Check-Valid-Until\s*"?false|allow-unauthenticated|--force-' | while IFS= read -r l; do
    finding HIGH REPOS "APT-Sicherheit abgeschwaecht in $f: $l"
  done
  grep -nviE '^\s*(//|#)' "$f" | grep -iE 'Acquire::(https?|ftp)::Proxy|Acquire::.*::Proxy' | while IFS= read -r l; do
    finding MED REPOS "APT-Proxy gesetzt in $f: $l"
  done
  if grep -qiE 'Pre-Invoke|Post-Invoke|Pre-Install-Pkgs|Post-Invoke-Success' "$f"; then
    if ! owned "$f"; then
      finding HIGH REPOS "APT/DPkg-Hook in paketfremder Datei $f - Inhalt pruefen (laeuft bei jedem apt-Aufruf)"
    elif dpkg --verify "$(dpkg -S "$f" 2>/dev/null | cut -d: -f1 | head -1)" 2>/dev/null | grep -q " $f\$"; then
      finding HIGH REPOS "APT/DPkg-Hook in veraenderter Paketdatei $f"
    fi
  fi
done
# 4) Pinning mit Prioritaet > 1000 (erzwingt Downgrades / Fremdpakete)
for f in /etc/apt/preferences /etc/apt/preferences.d/*; do
  [ -f "$f" ] || continue
  awk '/Pin-Priority:/ {if ($2+0 > 1000) print}' "$f" | while read -r l; do
    finding MED REPOS "Pinning mit hoher Prioritaet in $f: $l"
  done
done
# 5) Keyrings
[ -s /etc/apt/trusted.gpg ] && finding MED REPOS "Legacy-Keyring /etc/apt/trusted.gpg vorhanden (Keys pruefen: apt-key list)"
for f in /etc/apt/trusted.gpg.d/* /usr/share/keyrings/*; do
  [ -f "$f" ] || continue
  owned "$f" || finding MED REPOS "Paketfremder APT-Schluessel: $f"
done
for f in /etc/apt/keyrings/*; do
  [ -f "$f" ] || continue
  if [ -n "$(find "$f" -mtime -"$DAYS" 2>/dev/null)" ]; then
    finding MED REPOS "APT-Schluessel kuerzlich hinzugefuegt/geaendert: $f"
  else
    finding INFO REPOS "Manuell hinterlegter APT-Schluessel: $f"
  fi
done
# 6) Umleitung von Repo-Hosts ueber /etc/hosts
grep -vE '^\s*#' /etc/hosts | grep -iE 'debian\.org|ubuntu\.com|canonical\.com|launchpad' | while read -r l; do
  finding HIGH REPOS "/etc/hosts leitet Repo-Host um: $l"
done
# 7) Integritaet der Paketverwaltung selbst
for p in apt dpkg gpgv gnupg debian-archive-keyring ubuntu-keyring; do
  dpkg -s "$p" >/dev/null 2>&1 || continue
  dpkg --verify "$p" 2>/dev/null | grep -E '^..5' | grep -v ' c /' | while read -r l; do
    finding HIGH REPOS "Paketverwaltung manipuliert ($p): $l"
  done
done

REPO_HIGH=$(awk -F'\t' '$1=="HIGH" && $2=="REPOS"' "$FINDINGS" | wc -l)
[ "$REPO_HIGH" -eq 0 ] && finding INFO REPOS "Keine kritischen Auffaelligkeiten bei den Paketquellen"

# ===========================================================================
section "Tools"
TOOLS="lynis debsums rkhunter chkrootkit"
MISSING=""
for t in $TOOLS; do have "$t" || MISSING="$MISSING $t"; done
if [ -n "$MISSING" ]; then
  if [ "$INSTALL" -eq 1 ]; then
    if [ "$REPO_HIGH" -gt 0 ] && [ "$FORCE" -eq 0 ]; then
      finding HIGH TOOLS "Installation von${MISSING} abgebrochen: Repo-Pruefung hat $REPO_HIGH kritische Funde (erst beheben oder --force-install)"
    else
      echo "   Installiere:$MISSING"
      if apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $MISSING > "$OUT/01-apt-install.txt" 2>&1; then
        finding INFO TOOLS "Installiert:$MISSING"
      else
        finding MED TOOLS "Installation fehlgeschlagen -> 01-apt-install.txt"
      fi
    fi
  else
    finding INFO TOOLS "Nicht installiert:$MISSING (mit --install-tools nachinstallieren)"
  fi
fi

# ===========================================================================
section "Systeminfo"
run 02-system.txt sh -c 'uname -a; echo; cat /etc/os-release; echo; uptime; echo; df -h; echo; ip -br addr; echo; ip route'

# ===========================================================================
section "Paket-Integritaet (veraenderte Dateien aus Debian-Paketen)"
if have debsums; then
  debsums -s > "$OUT/03-debsums-changed.txt" 2>&1
  n=$(count "$OUT/03-debsums-changed.txt")
  [ "$n" -gt 0 ] && finding HIGH PAKETE "debsums: $n veraenderte Paketdateien -> 03-debsums-changed.txt"
fi
dpkg --verify > "$OUT/03-dpkg-verify.txt" 2>&1
grep -E '^..5' "$OUT/03-dpkg-verify.txt" | grep -v ' c /' > "$OUT/03-dpkg-verify-binaries.txt"
grep -E '^..5' "$OUT/03-dpkg-verify.txt" | grep ' c /' > "$OUT/03-dpkg-verify-configs.txt"
while read -r l; do
  finding HIGH PAKETE "Veraenderte Paketdatei: ${l##* }"
done < <(head -30 "$OUT/03-dpkg-verify-binaries.txt")
n=$(count "$OUT/03-dpkg-verify-binaries.txt")
[ "$n" -gt 30 ] && finding HIGH PAKETE "... insgesamt $n veraenderte Nicht-Config-Dateien -> 03-dpkg-verify-binaries.txt"
n=$(count "$OUT/03-dpkg-verify-configs.txt")
[ "$n" -gt 0 ] && finding LOW PAKETE "$n Config-Dateien weichen vom Paket-Original ab -> 03-dpkg-verify-configs.txt"

section "Paketfremde Dateien in System-Binaerpfaden"
: > "$OUT/03-unpackaged-binaries.txt"
for d in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /lib/systemd/system /etc/systemd/system; do
  [ -d "$d" ] || continue
  find "$d" -maxdepth 1 -type f 2>/dev/null | while read -r f; do
    owned "$f" || echo "$f" >> "$OUT/03-unpackaged-binaries.txt"
  done
done
n=$(count "$OUT/03-unpackaged-binaries.txt")
[ "$n" -gt 0 ] && finding MED DATEIEN "$n Dateien in System-Pfaden gehoeren zu keinem Paket -> 03-unpackaged-binaries.txt"

# ===========================================================================
section "Netzwerk: lauschende Ports & Verbindungen"
run 04-listening.txt ss -tulpnH
run 04-established.txt ss -tupnH state established
run 04-firewall.txt sh -c 'nft list ruleset 2>/dev/null; echo; iptables-save 2>/dev/null; echo; ufw status verbose 2>/dev/null'
run 04-hosts-resolv.txt sh -c 'cat /etc/hosts; echo; cat /etc/resolv.conf; echo; ls -la /etc/hosts /etc/resolv.conf'
grep -v '^#' "$OUT/04-listening.txt" | awk 'NF {print $1, $5, $7}' | sort -u | while read -r proto addr proc; do
  case "$addr" in 127.*|"[::1]"*|"::1"*) continue ;; esac
  finding MED NETZ "Lauscht extern: $proto $addr ${proc:-?}"
done
n=$(grep -vc '^#' "$OUT/04-established.txt" 2>/dev/null || true)
[ "${n:-0}" -gt 2 ] && finding INFO NETZ "$((n-2)) bestehende Verbindungen -> 04-established.txt (Gegenstellen pruefen)"
if ! grep -qE 'chain|-A |Status: active' "$OUT/04-firewall.txt"; then
  finding MED NETZ "Keine aktiven Firewall-Regeln gefunden"
fi

# ===========================================================================
section "Dienste, Autostart & geplante Tasks"
run 05-services-enabled.txt systemctl list-unit-files --state=enabled --no-pager
run 05-services-running.txt systemctl list-units --type=service --state=running --no-pager
run 05-timers.txt systemctl list-timers --all --no-pager
run 05-failed.txt systemctl --failed --no-pager

find /etc/systemd /lib/systemd/system /usr/lib/systemd /run/systemd/system \
  -type f -mtime -"$DAYS" 2>/dev/null > "$OUT/05-units-recently-modified.txt"
while read -r f; do
  finding MED AUTOSTART "systemd-Datei in den letzten $DAYS Tagen geaendert: $f"
done < <(head -25 "$OUT/05-units-recently-modified.txt")
find /etc/systemd/system -name '*.d' -type d 2>/dev/null > "$OUT/05-dropin-dirs.txt"
while read -r d; do finding LOW AUTOSTART "systemd Drop-in-Verzeichnis: $d"; done < "$OUT/05-dropin-dirs.txt"

systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print $1}' | while read -r u; do
  echo "== $u"; systemctl cat "$u" 2>/dev/null | grep -E '^(Exec|User=|# /)'
done > "$OUT/05-enabled-execstart.txt"
grep -c '^== ' "$OUT/05-enabled-execstart.txt" | { read -r n; finding INFO AUTOSTART "$n aktivierte Dienste mit ExecStart -> 05-enabled-execstart.txt"; }
n=$(grep -c 'loaded failed' "$OUT/05-failed.txt" 2>/dev/null || true)
[ "${n:-0}" -gt 0 ] && finding LOW AUTOSTART "$n fehlgeschlagene Units -> 05-failed.txt"

{
  for f in /etc/crontab /etc/anacrontab; do [ -f "$f" ] && { echo "== $f"; cat "$f"; }; done
  for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron/crontabs; do
    [ -d "$d" ] && for f in "$d"/*; do [ -f "$f" ] && { echo "== $f"; cat "$f"; }; done
  done
  echo "== at-Jobs"; atq 2>/dev/null
} > "$OUT/06-cron.txt" 2>&1
ls /var/spool/cron/crontabs 2>/dev/null | while read -r u; do finding MED AUTOSTART "User-Crontab vorhanden: $u -> 06-cron.txt"; done
for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
  [ -d "$d" ] || continue
  for f in "$d"/*; do
    [ -f "$f" ] || continue
    owned "$f" || finding MED AUTOSTART "Paketfremder Cronjob: $f"
  done
done
[ -n "$(atq 2>/dev/null)" ] && finding MED AUTOSTART "at-Jobs vorhanden -> 06-cron.txt"
{
  for f in /etc/rc.local /etc/profile /etc/bash.bashrc /etc/environment /etc/ld.so.preload; do
    [ -f "$f" ] && { echo "== $f"; ls -la "$f"; cat "$f"; }
  done
  for d in /etc/profile.d /etc/update-motd.d; do
    [ -d "$d" ] && ls -la "$d"
  done
} > "$OUT/06-startup-files.txt" 2>&1
[ -s /etc/ld.so.preload ] && finding HIGH AUTOSTART "/etc/ld.so.preload ist nicht leer: $(tr '\n' ' ' < /etc/ld.so.preload)"
[ -f /etc/rc.local ] && finding MED AUTOSTART "/etc/rc.local existiert -> 06-startup-files.txt"
for f in /etc/profile.d/* /etc/update-motd.d/*; do
  [ -f "$f" ] || continue
  owned "$f" || finding MED AUTOSTART "Paketfremdes Login-/MOTD-Skript: $f"
done
for f in /etc/init.d/*; do
  [ -f "$f" ] || continue
  owned "$f" || finding MED AUTOSTART "Paketfremdes init.d-Skript: $f"
done

# ===========================================================================
section "Benutzer, Gruppen, sudo"
awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd | while read -r u; do
  finding HIGH USER "Weiterer Account mit UID 0: $u"
done
awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)$/ {print $1":"$3":"$6":"$7}' /etc/passwd > "$OUT/07-login-users.txt"
finding INFO USER "$(count "$OUT/07-login-users.txt") Accounts mit Login-Shell -> 07-login-users.txt"
awk -F: '$3>=1000 && $3<65534 {print $1}' /etc/passwd | while read -r u; do finding LOW USER "Normaler Benutzer: $u (legitim?)"; done
awk -F: '$2=="" {print $1}' /etc/shadow | while read -r u; do finding HIGH USER "Account ohne Passwort: $u"; done
run 07-groups-privileged.txt sh -c 'getent group sudo adm wheel docker lxd disk shadow root'
for g in sudo wheel docker lxd disk shadow root; do
  m=$(getent group "$g" | cut -d: -f4)
  [ -n "$m" ] && finding MED USER "Mitglieder der Gruppe $g: $m"
done
run 07-sudoers.txt sh -c 'ls -la /etc/sudoers /etc/sudoers.d; echo; cat /etc/sudoers; for f in /etc/sudoers.d/*; do echo "== $f"; cat "$f"; done'
grep -rhE 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -v '^\s*#' | while read -r l; do
  finding MED USER "sudo NOPASSWD: $l"
done
for f in /etc/sudoers.d/*; do
  [ -f "$f" ] || continue
  owned "$f" || finding MED USER "Zusaetzliche sudoers-Datei: $f"
done
run 07-passwd-shadow-perms.txt ls -la /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers
for f in /etc/shadow /etc/gshadow; do
  [ -f "$f" ] && [ "$(stat -c %a "$f")" -gt 640 ] && finding HIGH USER "$f hat zu offene Rechte: $(stat -c '%a %U:%G' "$f")"
done
[ "$(stat -c %a /etc/passwd)" != 644 ] && finding MED USER "/etc/passwd hat ungewoehnliche Rechte: $(stat -c '%a %U:%G' /etc/passwd)"
run 07-pam.txt sh -c 'for f in /etc/pam.d/*; do echo "== $f"; grep -v "^#" "$f" | grep .; done'
grep -hE 'pam_permit\.so' /etc/pam.d/common-auth /etc/pam.d/sshd /etc/pam.d/sudo /etc/pam.d/su 2>/dev/null | grep -v '^\s*#' | while read -r l; do
  finding HIGH USER "pam_permit in Auth-Stack: $l"
done

section "SSH"
run 08-sshd-effective.txt sshd -T
grep -qiE '^permitrootlogin yes' "$OUT/08-sshd-effective.txt" && finding MED SSH "PermitRootLogin yes"
grep -qiE '^passwordauthentication yes' "$OUT/08-sshd-effective.txt" && finding LOW SSH "PasswordAuthentication yes"
grep -qiE '^permitemptypasswords yes' "$OUT/08-sshd-effective.txt" && finding HIGH SSH "PermitEmptyPasswords yes"
grep -iE '^authorizedkeysfile ' "$OUT/08-sshd-effective.txt" | grep -vqE '^authorizedkeysfile \.ssh/authorized_keys( \.ssh/authorized_keys2)?$' && \
  finding HIGH SSH "Ungewoehnlicher AuthorizedKeysFile: $(grep -i '^authorizedkeysfile ' "$OUT/08-sshd-effective.txt")"
grep -iE '^authorizedkeyscommand ' "$OUT/08-sshd-effective.txt" | grep -vqi ' none$' && \
  finding HIGH SSH "AuthorizedKeysCommand gesetzt: $(grep -i '^authorizedkeyscommand ' "$OUT/08-sshd-effective.txt")"
{
  getent passwd | awk -F: '{print $1":"$6}' | while IFS=: read -r u h; do
    for k in "$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2"; do
      [ -f "$k" ] && { echo "== $u ($k)"; ls -la "$k"; cat "$k"; }
    done
  done
} > "$OUT/08-authorized-keys.txt" 2>&1
grep '^== ' "$OUT/08-authorized-keys.txt" | while read -r _ u k; do
  n=$(grep -cE '^(ssh-|ecdsa-|sk-)|^[a-z].* (ssh-|ecdsa-)' "${k//[()]/}" 2>/dev/null || echo "?")
  finding MED SSH "authorized_keys fuer $u: $n Key(s) ${k//[()]/} - verifizieren"
done

# ===========================================================================
section "Prozesse & Kernel"
run 09-processes.txt ps auxwwf
run 09-kernel-modules.txt lsmod
ls -l /proc/[0-9]*/exe 2>/dev/null | grep '(deleted)' > "$OUT/09-deleted-exe.txt"
while read -r l; do finding HIGH PROZESSE "Prozess laeuft von geloeschtem Binary: $(echo "$l" | awk '{print $9, $10, $11, $12}')"; done < "$OUT/09-deleted-exe.txt"
run 09-docker.txt sh -c 'docker ps -a 2>/dev/null; echo; crictl ps -a 2>/dev/null'
[ "$(cat /proc/sys/kernel/tainted 2>/dev/null)" != 0 ] && finding LOW PROZESSE "Kernel ist 'tainted' ($(cat /proc/sys/kernel/tainted)) - nicht-signierte/fremde Module?"

# ===========================================================================
section "Custom-Services (nicht aus Debian-Paketen) & ihre Verbindungen"
# Ein Service gilt als "custom", wenn Unit-Datei, ein Drop-in, ein ausgefuehrtes
# Programm oder ein vom Interpreter gestartetes Skript zu keinem Paket gehoert.
# Damit werden auch manipulierte Paket-Dienste erfasst (z.B. Drop-in-Override
# mit zusaetzlichem ExecStartPost).
CS_DIR="$OUT/15-custom-services"; mkdir -p "$CS_DIR"
CUSTOM_UNITS="$OUT/15-custom-units.txt"; : > "$CUSTOM_UNITS"
LISTEN_PORTS=" $(ss -tulnH 2>/dev/null | awk '{n=split($5,a,":"); print a[n]}' | sort -u | tr '\n' ' ') "
is_outbound() { case "$LISTEN_PORTS" in *" ${1##*:} "*) return 1 ;; esac; return 0; }
is_loopback() { case "$1" in 127.*|"[::1]"*|"::1"*|"[::ffff:127."*) return 0 ;; esac; return 1; }
SS_NOW="$(ss -tunapH 2>/dev/null)"

{ systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}'
  systemctl list-units --type=service --all --no-legend --plain 2>/dev/null | awk '{print $1}'
} | grep -v '@\.service$' | grep '\.service$' | sort -u | while read -r u; do
  frag=$(systemctl show -p FragmentPath --value "$u" 2>/dev/null)
  { [ -n "$frag" ] && [ -f "$frag" ]; } || continue
  dropins=$(systemctl show -p DropInPaths --value "$u" 2>/dev/null)
  execinfo=$(systemctl show -p ExecStart -p ExecStartPre -p ExecStartPost -p ExecReload -p ExecStop -p ExecStopPost --value "$u" 2>/dev/null)
  execs=$(echo "$execinfo" | grep -oE 'path=[^ ;]+' | cut -d= -f2 | sort -u)
  argfiles=$(echo "$execinfo" | grep -oE 'argv\[\]=[^;]+' | sed 's/^argv\[\]=//' | tr ' ' '\n' | grep '^/' | sort -u)
  envfiles=$(systemctl show -p EnvironmentFiles --value "$u" 2>/dev/null | awk '{print $1}')

  reason=""
  owned "$frag" || reason="Unit-Datei paketfremd"
  for f in $dropins; do [ -f "$f" ] && ! owned "$f" && reason="${reason:+$reason, }Drop-in paketfremd ($f)"; done
  for f in $execs; do [ -e "$f" ] && ! owned "$f" && reason="${reason:+$reason, }Programm paketfremd ($f)"; done
  scripts=""
  for f in $argfiles; do [ -f "$f" ] && ! owned "$f" && scripts="$scripts $f"; done
  [ -n "$scripts" ] && reason="${reason:+$reason, }Skript paketfremd ($(echo $scripts))"
  [ -z "$reason" ] && continue

  echo "$u" >> "$CUSTOM_UNITS"
  d="$CS_DIR/$u"; mkdir -p "$d/files"
  systemctl cat "$u" > "$d/unit.txt" 2>&1
  systemctl status "$u" --no-pager -l -n 30 > "$d/status.txt" 2>&1
  journalctl -u "$u" --since "$SINCE_DATE" --no-pager -o short-iso 2>/dev/null | tail -500 > "$d/journal.txt"
  user=$(systemctl show -p User --value "$u" 2>/dev/null); user=${user:-root}
  state=$(systemctl is-active "$u" 2>/dev/null); en=$(systemctl is-enabled "$u" 2>/dev/null)
  finding MED CUSTOM "$u [$state/$en, User=$user]: $reason -> 15-custom-services/$u/"

  # Beteiligte Dateien sichern (Kopie + Hash + Zeitstempel) zur manuellen Code-Review
  for f in $frag $dropins $execs $scripts $envfiles; do
    [ -f "$f" ] || continue
    owned "$f" && continue
    cp -p --parents "$f" "$d/files/" 2>/dev/null
    printf '%s  %s  %s\n' "$(stat -c '%y %U:%G %a' "$f")" "$(sha256sum "$f" | cut -c1-64)" "$f" >> "$d/files.txt"
    [ -n "$(find "$f" -mtime -"$DAYS" 2>/dev/null)" ] && \
      finding MED CUSTOM "$u: $f in den letzten $DAYS Tagen geaendert ($(stat -c %y "$f" | cut -d. -f1))"
  done
  wd=$(systemctl show -p WorkingDirectory --value "$u" 2>/dev/null)
  [ -n "$wd" ] && [ -d "$wd" ] && [ "$wd" != / ] && \
    find "$wd" -maxdepth 2 -printf '%TY-%Tm-%Td %TH:%TM %u %m %p\n' 2>/dev/null | sort -r | head -200 > "$d/workdir.txt"

  # Prozesse im cgroup des Service (inkl. Kindprozesse)
  cg=$(systemctl show -p ControlGroup --value "$u" 2>/dev/null)
  procs=""
  [ -n "$cg" ] && procs=$(cat "/sys/fs/cgroup$cg/cgroup.procs" "/sys/fs/cgroup/systemd$cg/cgroup.procs" 2>/dev/null | sort -un)
  mainpid=$(systemctl show -p MainPID --value "$u" 2>/dev/null)
  mainexe=$(readlink "/proc/$mainpid/exe" 2>/dev/null)
  for p in $procs; do
    ps -o pid=,ppid=,user=,etime=,args= -p "$p" >> "$d/processes.txt" 2>/dev/null
    exe=$(readlink "/proc/$p/exe" 2>/dev/null)
    if [ -n "$mainexe" ] && [ -n "$exe" ] && [ "$exe" != "$mainexe" ]; then
      finding MED CUSTOM "$u: weiterer Prozess mit anderem Programm im Service: PID $p $(ps -o args= -p "$p" 2>/dev/null | cut -c1-120)"
    fi
  done

  # Netzwerk-Sockets der Service-Prozesse
  for p in $procs; do
    echo "$SS_NOW" | grep "pid=$p," | while read -r net st _ _ loc peer proc; do
      echo "$net $st $loc -> $peer $proc" >> "$d/network.txt"
      case "$st" in
        LISTEN|UNCONN) finding INFO CUSTOM "$u lauscht auf $net $loc" ;;
        *) if is_outbound "$loc" && ! is_loopback "$peer"; then
             finding HIGH CUSTOM "$u: AUSGEHENDE Verbindung $net $st -> $peer $proc"
           fi ;;
      esac
    done
  done
done
n=$(count "$CUSTOM_UNITS")
finding INFO CUSTOM "$n Custom-/veraenderte Services gefunden; Code liegt zur Review in 15-custom-services/<unit>/files/"

# Ausgehende Verbindungen ueber Zeit beobachten: periodische Verbindungen
# (z.B. Rueckverbindungen, die alle paar Sekunden neu aufgebaut werden) fallen
# in einem einzelnen Schnappschuss oft nicht auf.
# Prozess-Schnappschuss: welcher Dienst (cgroup) fuehrt welches Programm aus
proc_snapshot() {
  local p u exe
  for p in /proc/[0-9]*; do
    u=$(grep -oE '[^/]+\.service' "$p/cgroup" 2>/dev/null | tail -1)
    [ -n "$u" ] || continue
    exe=$(readlink "$p/exe" 2>/dev/null) || continue
    printf '%s|%s|%s\n' "$u" "${exe% (deleted)}" "$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null | cut -c1-200)"
  done
}
proc_snapshot > "$OUT/15-process-samples.raw"
: > "$OUT/15-outbound-samples.txt"

if [ "$SAMPLE" -gt 0 ]; then
  echo "   Beobachte Verbindungen & Prozesse fuer ${SAMPLE}s (--sample 0 zum Abschalten)..."
  end=$((SECONDS + SAMPLE))
  while [ "$SECONDS" -lt "$end" ]; do
    proc_snapshot >> "$OUT/15-process-samples.raw"
    ss -tunapH 2>/dev/null | while read -r net st _ _ loc peer proc; do
      case "$st" in ESTAB|SYN-SENT) ;; *) continue ;; esac
      is_outbound "$loc" || continue
      is_loopback "$peer" && continue
      pid=$(echo "$proc" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
      name=$(echo "$proc" | grep -oE '"[^"]+"' | head -1 | tr -d '"')
      unit=$(grep -oE '[^/]+\.(service|scope)' "/proc/${pid:-0}/cgroup" 2>/dev/null | tail -1)
      echo "$net|$st|${name:-?}|${pid:-?}|${unit:-?}|$peer"
    done
    sleep 2
  done | sort -u > "$OUT/15-outbound-samples.txt"
  awk -F'|' '{print $3"|"$5"|"$6"|"$2"|"$1}' "$OUT/15-outbound-samples.txt" | sort -u | \
  while IFS='|' read -r name unit peer st net; do
    port=${peer##*:}
    if grep -qx "$unit" "$CUSTOM_UNITS"; then
      finding HIGH CUSTOM "Ausgehend aus Custom-Service $unit: $name -> $peer ($st)"
    elif [ "$st" = SYN-SENT ]; then
      finding MED NETZ "Wiederholter/haengender Verbindungsversuch (SYN-SENT): $name [$unit] -> $peer"
    elif [ "$net" = udp ] && { [ "$port" = 53 ] || [ "$port" = 123 ]; }; then
      finding INFO NETZ "DNS/NTP: $name [$unit] -> $peer"
    else
      finding MED NETZ "Ausgehende Verbindung: $name [$unit] -> $peer"
    fi
  done
fi

# ---------------------------------------------------------------------------
# Auswertung der Prozess-Schnappschuesse: was fuehren Dienste aus?
sort -u "$OUT/15-process-samples.raw" > "$OUT/15-process-samples.txt"
SHELL_RE='/(ba|da|z|k|c|tc|mk)?sh$'
SAFE_RE='^(cron|crond|anacron|atd|ssh|sshd|systemd-.*|getty@.*|serial-getty@.*|user@.*|unattended-upgrades|apt-daily.*|packagekit|snapd.*|cloud-.*|networkd-dispatcher|NetworkManager.*|dbus|rsyslog|logrotate|man-db|e2scrub.*|fstrim|motd-news|update-notifier.*|plymouth.*|console-setup|keyboard-setup|ifup@.*|networking|lightdm|gdm.*|sddm|dpkg-db-backup|sysstat.*|needrestart|landscape-.*|ubuntu-advantage|ua-.*|cups.*|postfix.*|exim4|nullmailer)\.service$'
WEB_RE='^(apache2|httpd|nginx|php.*-fpm|lighttpd|tomcat.*|jetty.*|mysql|mariadb|postgresql.*|redis.*|mongod|memcached|vsftpd|proftpd|pure-ftpd|named|bind9|smbd|nmbd|squid|haproxy|gunicorn.*|uwsgi.*|caddy|traefik|grafana.*|jenkins|gitea|elasticsearch|rabbitmq.*)\.service$'
declare -A MAINEXE
while IFS='|' read -r u exe args; do
  [ -n "$exe" ] || continue
  if grep -qx "$u" "$CUSTOM_UNITS"; then
    echo "$exe | $args" >> "$CS_DIR/$u/processes-sampled.txt"
    continue
  fi
  case "$u" in snap.*) continue ;; esac
  if ! owned_c "$exe"; then
    finding HIGH SVC "Paket-Dienst $u fuehrt paketfremdes Programm aus: $exe ($(echo "$args" | cut -c1-100))"
    continue
  fi
  if [[ "$exe" =~ $SHELL_RE ]] && ! [[ "$u" =~ $SAFE_RE ]]; then
    if [ -z "${MAINEXE[$u]+x}" ]; then
      mp=$(systemctl show -p MainPID --value "$u" 2>/dev/null)
      MAINEXE[$u]=$(readlink "/proc/${mp:-0}/exe" 2>/dev/null)
    fi
    [[ "${MAINEXE[$u]}" =~ $SHELL_RE ]] && continue
    if [[ "$u" =~ $WEB_RE ]]; then lvl=HIGH; else lvl=MED; fi
    finding "$lvl" SVC "Dienst $u startet eine Shell: $(echo "$args" | cut -c1-120)"
  fi
done < "$OUT/15-process-samples.txt"
while read -r u; do
  f="$CS_DIR/$u/processes-sampled.txt"
  [ -f "$f" ] || continue
  sort -u "$f" -o "$f"
  nexe=$(cut -d'|' -f1 "$f" | sort -u | grep -c .)
  [ "$nexe" -gt 1 ] && finding MED SVC "Custom-Service $u startet weitere Programme: $(cut -d'|' -f1 "$f" | sort -u | xargs -n1 basename | tr '\n' ' ')"
done < "$CUSTOM_UNITS"

# ===========================================================================
section "Bestehende Dienste auf Manipulation pruefen"
SV_DIR="$OUT/19-service-integrity"; mkdir -p "$SV_DIR"
ORIG_DIR="$OUT/19-originals"; mkdir -p "$ORIG_DIR/debs"
ENV_RE='^[[:space:]]*(export[[:space:]]+)?(LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT|PYTHONPATH|PYTHONSTARTUP|PYTHONHOME|NODE_OPTIONS|NODE_PATH|PERL5LIB|PERL5OPT|RUBYOPT|RUBYLIB|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|BASH_ENV|PROMPT_COMMAND)='
[ "$FETCH" -eq 1 ] && [ "$REPO_HIGH" -gt 0 ] && \
  finding MED TOOLS "--fetch-originals ignoriert: Repo-Pruefung hat kritische Funde"

# get_original PAKET DATEI -> Pfad der Originaldatei aus der .deb (Cache oder Download)
get_original() {
  local pkg="$1" f="$2" x="$ORIG_DIR/$1" ver arch deb
  if [ ! -d "$x" ]; then
    mkdir -p "$x"
    ver=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null)
    arch=$(dpkg-query -W -f='${Architecture}' "$pkg" 2>/dev/null)
    deb=$(ls "/var/cache/apt/archives/${pkg}_${ver//:/%3a}_${arch}.deb" 2>/dev/null | head -1)
    if [ -z "$deb" ] && [ "$FETCH" -eq 1 ] && [ "$REPO_HIGH" -eq 0 ]; then
      ( cd "$ORIG_DIR/debs" && apt-get download "$pkg=$ver" >/dev/null 2>&1 )
      deb=$(ls "$ORIG_DIR/debs/${pkg}_"*.deb 2>/dev/null | head -1)
    fi
    [ -n "$deb" ] && dpkg-deb -x "$deb" "$x" 2>/dev/null
  fi
  local c
  for c in "$f" "${f#/usr}" "/usr$f"; do [ -f "$x$c" ] && { echo "$x$c"; return 0; }; done
  return 1
}

declare -A PKG_DONE
while read -r u; do
  frag=$(systemctl show -p FragmentPath --value "$u" 2>/dev/null)
  { [ -n "$frag" ] && [ -f "$frag" ]; } || continue
  case "$u" in snap.*) continue ;; esac
  custom=0; grep -qx "$u" "$CUSTOM_UNITS" && custom=1

  # 1) Paket-Unit durch eigene, vollstaendige Kopie ersetzt
  case "$frag" in
    /etc/systemd/system/*)
      for alt in "/lib/systemd/system/$(basename "$frag")" "/usr/lib/systemd/system/$(basename "$frag")"; do
        if [ -f "$alt" ] && ! owned_c "$frag"; then
          diff -u "$alt" "$frag" > "$SV_DIR/$u.override.diff" 2>&1
          finding HIGH SVC "Dienst $u: Paket-Unit wird durch $frag ersetzt -> 19-service-integrity/$u.override.diff"
          break
        fi
      done ;;
  esac

  # 2) Kritische Umgebungsvariablen (Library-/Code-Injektion)
  envs=$(systemctl show -p Environment --value "$u" 2>/dev/null)
  envf=$(systemctl show -p EnvironmentFiles --value "$u" 2>/dev/null | awk '{print $1}')
  { echo "$envs" | tr ' ' '\n'; for f in $envf; do [ -f "$f" ] && cat "$f"; done; } | grep -E "$ENV_RE" | \
    while read -r l; do finding HIGH SVC "Dienst $u setzt kritische Umgebungsvariable: $l"; done

  # 3) Dateien der zugehoerigen Pakete gegen dpkg-Datenbank/Original pruefen
  pkgs=""
  for f in "$frag" $(systemctl show -p ExecStart --value "$u" 2>/dev/null | grep -oE 'path=[^ ;]+' | cut -d= -f2); do
    p=$(pkg_of "$f") && pkgs="$pkgs $p"
  done
  for pkg in $(echo $pkgs | tr ' ' '\n' | sort -u); do
    [ -n "${PKG_DONE[$pkg]+x}" ] && continue
    PKG_DONE[$pkg]=1
    while read -r line; do
      path="/${line#*/}"
      if echo "$line" | grep -q ' c /'; then
        if orig=$(get_original "$pkg" "$path"); then
          dfile="$SV_DIR/diff_${pkg}$(echo "$path" | tr '/' '_').diff"
          diff -u "$orig" "$path" > "$dfile" 2>&1
          finding MED SVC "Dienst $u ($pkg): Konfig geaendert $path -> $(basename "$dfile")"
        else
          finding MED SVC "Dienst $u ($pkg): Konfig geaendert $path (kein Original verfuegbar, --fetch-originals)"
        fi
      else
        extra=""
        if orig=$(get_original "$pkg" "$path"); then
          cmp -s "$orig" "$path" && extra=" (gleich wie Original-.deb?! dpkg-DB pruefen)" || extra=" (bestaetigt: weicht von Original-.deb ab)"
        fi
        finding HIGH SVC "Dienst $u ($pkg): Datei manipuliert $path$extra"
      fi
    done < <(dpkg --verify "$pkg" 2>/dev/null | grep -E '^..5')

    # Programm gegen Original-.deb vergleichen (erkennt auch manipulierte md5sums)
    if [ "$FETCH" -eq 1 ] && [ "$REPO_HIGH" -eq 0 ]; then
      for f in $(systemctl show -p ExecStart --value "$u" 2>/dev/null | grep -oE 'path=[^ ;]+' | cut -d= -f2); do
        [ "$(pkg_of "$f")" = "$pkg" ] || continue
        if orig=$(get_original "$pkg" "$(readlink -f "$f")") || orig=$(get_original "$pkg" "$f"); then
          cmp -s "$orig" "$(readlink -f "$f")" || finding HIGH SVC "Dienst $u: $f weicht vom Original-.deb ab (dpkg-Pruefsummen evtl. gefaelscht)"
        fi
      done
    fi

    # Zusaetzliche, paketfremde Dateien in den Konfig-Verzeichnissen des Pakets
    dpkg-query -W -f='${Conffiles}\n' "$pkg" 2>/dev/null | awk 'NF {print $1}' | xargs -r -n1 dirname 2>/dev/null | sort -u | \
    while read -r cd; do
      case "$cd" in /etc|/etc/default|/etc/init.d|/etc/logrotate.d|/etc/cron.*|/etc/ssl*|/etc/systemd*|/etc/pam.d|/etc/sudoers.d|/etc/profile.d|/etc/apt*) continue ;; esac
      find "$cd" -maxdepth 2 -type f 2>/dev/null | grep -vE '/ssh_host_|\.dpkg-(old|dist|new)$|\.ucf-' | \
        while read -r f; do owned "$f" || echo "$f"; done
    done | sort -u > "$SV_DIR/extra-conf-$pkg.txt"
    while read -r f; do
      finding MED SVC "Dienst $u ($pkg): zusaetzliche Datei im Konfig-Verzeichnis: $f ($(stat -c %y "$f" | cut -d. -f1))"
    done < <(head -20 "$SV_DIR/extra-conf-$pkg.txt")
    [ -s "$SV_DIR/extra-conf-$pkg.txt" ] || rm -f "$SV_DIR/extra-conf-$pkg.txt"
  done

  # 4) Laufende Prozesse: geladene Bibliotheken & Rechte
  cg=$(systemctl show -p ControlGroup --value "$u" 2>/dev/null)
  [ -n "$cg" ] || continue
  procs=$(cat "/sys/fs/cgroup$cg/cgroup.procs" "/sys/fs/cgroup/systemd$cg/cgroup.procs" 2>/dev/null | sort -un)
  [ -n "$procs" ] || continue
  for p in $procs; do awk '$6 ~ /\.so/ {print $6, $7}' "/proc/$p/maps" 2>/dev/null; done | sort -u > "$SV_DIR/libs-$u.txt"
  while read -r lib del; do
    case "$lib" in /snap/*) continue ;; esac
    if [ "$del" = "(deleted)" ]; then
      finding MED SVC "Dienst $u nutzt geloeschte Bibliothek $lib (Neustart nach Update noetig - sonst verdaechtig)"
    elif ! owned_c "$lib"; then
      if [ "$custom" = 1 ]; then echo "$lib" >> "$CS_DIR/$u/foreign-libs.txt"
      else finding HIGH SVC "Paket-Dienst $u laedt paketfremde Bibliothek: $lib"; fi
    fi
  done < "$SV_DIR/libs-$u.txt"
  rm -f "$SV_DIR/libs-$u.txt"
  mp=$(systemctl show -p MainPID --value "$u" 2>/dev/null)
  if [ "${mp:-0}" -gt 0 ] 2>/dev/null; then
    euid=$(awk '/^Uid:/ {print $3}' "/proc/$mp/status" 2>/dev/null)
    cap=$(awk '/^CapEff:/ {print $2}' "/proc/$mp/status" 2>/dev/null)
    if [ -n "$euid" ] && [ "$euid" != 0 ] && [ -n "$cap" ] && [ "$cap" != 0000000000000000 ]; then
      finding INFO SVC "Dienst $u laeuft als UID $euid mit Capabilities $cap $(capsh --decode="$cap" 2>/dev/null | cut -d= -f2)"
    fi
  fi
done < <( { systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}'
            systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print $1}'; } | grep -v '@\.service$' | sort -u )

# 5) dpkg-Datenbank selbst: Pruefsummen/Maintainer-Skripte geaendert ohne Paket-Update?
zcat -f /var/log/dpkg.log* 2>/dev/null | awk '$3 ~ /^(install|upgrade|configure|trigproc)$/ {print $4}' | cut -d: -f1 | sort -u > "$SV_DIR/dpkg-log-packages.txt"
find /var/lib/dpkg/info -type f \( -name '*.md5sums' -o -name '*.list' -o -name '*.postinst' -o -name '*.preinst' -o -name '*.prerm' -o -name '*.postrm' -o -name '*.triggers' \) \
  -mtime -"$DAYS" 2>/dev/null | while read -r f; do
  b=$(basename "$f"); pkg=${b%.*}; pkg=${pkg%%:*}
  grep -qx "$pkg" "$SV_DIR/dpkg-log-packages.txt" || \
    finding HIGH SVC "dpkg-Datenbank: $b geaendert ohne Paket-Installation im Log ($(stat -c %y "$f" | cut -d. -f1))"
done

# 6) Python-Autoload-Mechanismen (laufen beim Start JEDES Python-Dienstes)
for d in /usr/lib/python3*/ /usr/lib/python3/dist-packages /usr/local/lib/python3*/dist-packages /usr/local/lib/python3*/site-packages; do
  [ -d "$d" ] || continue
  find "$d" -maxdepth 1 -type f \( -name '*.pth' -o -name 'sitecustomize.py' -o -name 'usercustomize.py' \) 2>/dev/null | while read -r f; do
    owned "$f" && continue
    case "$f" in
      *customize.py) finding HIGH SVC "Python-Autoload-Datei nicht aus Paket: $f" ;;
      *) if grep -qE '^\s*import ' "$f"; then finding HIGH SVC ".pth-Datei mit Code (laeuft bei jedem Python-Start): $f"
         else finding LOW SVC ".pth-Datei nicht aus Paket: $f"; fi ;;
    esac
  done
done

# ===========================================================================
section "Verhaltensprofil der Custom-Services"
[ "$TRACE" -gt 0 ] && ! have strace && finding INFO TOOLS "--trace angegeben, aber strace ist nicht installiert"
while read -r u; do
  d="$CS_DIR/$u"
  [ -d "$d" ] || continue
  cg=$(systemctl show -p ControlGroup --value "$u" 2>/dev/null)
  procs=""
  [ -n "$cg" ] && procs=$(cat "/sys/fs/cgroup$cg/cgroup.procs" "/sys/fs/cgroup/systemd$cg/cgroup.procs" 2>/dev/null | sort -un)

  # Laufzeit-Eigenschaften jedes Prozesses
  for p in $procs; do
    {
      echo "== PID $p  $(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | cut -c1-200)"
      echo "exe:  $(readlink "/proc/$p/exe" 2>/dev/null)"
      echo "cwd:  $(readlink "/proc/$p/cwd" 2>/dev/null)"
      echo "root: $(readlink "/proc/$p/root" 2>/dev/null)"
      grep -E '^(PPid|Uid|Gid|Groups|CapEff|CapBnd|NoNewPrivs|Seccomp):' "/proc/$p/status" 2>/dev/null
      echo "-- offene Dateien/Sockets"
      ls -l "/proc/$p/fd" 2>/dev/null | awk 'NR>1 {print $NF}' | sort | uniq -c | sort -rn | head -60
      echo
    } >> "$d/behaviour.txt"
    tr '\0' '\n' < "/proc/$p/environ" > "$d/environ-$p.txt" 2>/dev/null
    r=$(readlink "/proc/$p/root" 2>/dev/null); [ -n "$r" ] && [ "$r" != / ] && finding INFO SVC "Custom-Service $u laeuft in chroot $r"
    ls -l "/proc/$p/fd" 2>/dev/null | awk '{print $NF}' | grep -E '^/(tmp|var/tmp|dev/shm)/' | sort -u | while read -r f; do
      finding MED SVC "Custom-Service $u haelt Datei in temporaerem Verzeichnis offen: $f"
    done
  done
  [ -s "$d/foreign-libs.txt" ] && finding INFO SVC "Custom-Service $u laedt $(sort -u "$d/foreign-libs.txt" | grep -c .) eigene Bibliotheken -> 15-custom-services/$u/foreign-libs.txt"

  # Im Code hinterlegte Netzwerkziele (IP-Adressen, URLs)
  wd=$(systemctl show -p WorkingDirectory --value "$u" 2>/dev/null)
  {
    grep -raoHE '([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]{1,5})?|[a-zA-Z][a-zA-Z0-9+.-]*://[^ "'"'"'<>()]+' "$d/files" 2>/dev/null
    if [ -n "$wd" ] && [ -d "$wd" ] && [ "$wd" != / ]; then
      grep -raoHE --exclude-dir={venv,.venv,node_modules,site-packages,dist-packages,.git,__pycache__} \
        '([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]{1,5})?|[a-zA-Z][a-zA-Z0-9+.-]*://[^ "'"'"'<>()]+' "$wd" 2>/dev/null | head -2000
    fi
  } | sed "s#^$d/files##" | sort -u > "$d/indicators.txt"
  cut -d: -f2- "$d/indicators.txt" | grep -vE '^(0\.0\.0\.0|127\.|255\.|0\.)' | sort -u | head -15 | while read -r ioc; do
    finding MED SVC "Custom-Service $u: im Code hinterlegtes Ziel $ioc -> 15-custom-services/$u/indicators.txt"
  done

  # Optional: strace (Prozessstarts & Netzwerkaufrufe live mitschneiden)
  if [ "$TRACE" -gt 0 ] && have strace && [ -n "$procs" ]; then
    echo "   strace auf $u fuer ${TRACE}s..."
    targs=""; for p in $procs; do targs="$targs -p $p"; done
    timeout -s INT "$((TRACE + 2))" strace -f -tt -s 200 -e trace=process,network -o "$d/strace.txt" -I 2 $targs >/dev/null 2>&1 &
    spid=$!; sleep "$TRACE"; kill -INT "$spid" 2>/dev/null; wait "$spid" 2>/dev/null
    grep 'connect(' "$d/strace.txt" 2>/dev/null | grep -E 'AF_INET6?' | while read -r l; do
      port=$(echo "$l" | grep -oE 'htons\([0-9]+\)' | tr -dc '0-9')
      addr=$(echo "$l" | grep -oE '"[0-9a-fA-F:.]+"' | head -1 | tr -d '"')
      echo "$addr:$port"
    done | sort -u | grep -vE '^(127\.|::1:|:)' | while read -r t; do
      finding HIGH SVC "strace: Custom-Service $u verbindet zu $t"
    done
    grep -oE 'execve\("[^"]+", \[[^]]*\]' "$d/strace.txt" 2>/dev/null | sort -u | head -20 | while read -r l; do
      finding MED SVC "strace: Custom-Service $u fuehrt aus: $(echo "$l" | cut -c1-150)"
    done
  fi

  # Zusammenfassendes Profil
  {
    echo "################ PROFIL: $u ################"
    echo; echo "## Unit (effektiv)"; cat "$d/unit.txt" 2>/dev/null
    echo; echo "## Dateien (Zeit, Besitzer, Rechte, SHA256)"; cat "$d/files.txt" 2>/dev/null
    echo; echo "## Laufzeit"; cat "$d/behaviour.txt" 2>/dev/null
    echo; echo "## Sockets (Schnappschuss)"; cat "$d/network.txt" 2>/dev/null
    echo; echo "## Ausgehende Verbindungen (Sampling)"; grep -F "|$u|" "$OUT/15-outbound-samples.txt" 2>/dev/null
    echo; echo "## Beobachtete Prozesse (Sampling)"; cat "$d/processes-sampled.txt" 2>/dev/null
    echo; echo "## Im Code hinterlegte Ziele"; head -100 "$d/indicators.txt" 2>/dev/null
    if [ -f "$d/strace.txt" ]; then
      echo; echo "## strace: Prozessstarts"; grep -oE 'execve\("[^"]+", \[[^]]*\]' "$d/strace.txt" | sort -u | head -50
      echo; echo "## strace: Netzwerkaufrufe"; grep -E 'connect\(|bind\(|accept' "$d/strace.txt" | head -50
    fi
    echo; echo "## Letzte Journal-Eintraege"; tail -40 "$d/journal.txt" 2>/dev/null
  } > "$d/PROFIL.txt"
done < "$CUSTOM_UNITS"
[ -s "$CUSTOM_UNITS" ] && finding INFO SVC "Verhaltensprofil je Custom-Service -> 15-custom-services/<unit>/PROFIL.txt"

# ===========================================================================
section "Container (Docker, Podman, containerd, LXC/LXD/Incus, Kubernetes)"
CT_DIR="$OUT/16-container"; mkdir -p "$CT_DIR"
virt=$(systemd-detect-virt 2>/dev/null); cvirt=$(systemd-detect-virt -c 2>/dev/null)
finding INFO CONTAINER "Virtualisierung: ${virt:-?}, Container-Umgebung: ${cvirt:-none}"
[ -f /.dockerenv ] && finding MED CONTAINER "Dieses System laeuft selbst in einem Docker-Container (/.dockerenv)"
CT_TOOLS=""
for b in docker dockerd podman containerd ctr nerdctl crictl lxc incus lxc-ls kubectl k3s microk8s; do
  have "$b" && CT_TOOLS="$CT_TOOLS $b"
done
[ -n "$CT_TOOLS" ] && finding INFO CONTAINER "Container-Tools gefunden:$CT_TOOLS"

CT_FMT='{{.Name}}|{{.Config.Image}}|{{.State.Status}}|{{.HostConfig.Privileged}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.CapAdd}}|{{.HostConfig.SecurityOpt}}|{{.Config.User}}|{{.HostConfig.RestartPolicy.Name}}|{{.Created}}|{{range .Mounts}}{{.Source}}>{{.Destination}}>{{.RW}} {{end}}|{{.HostConfig.Devices}}'

# audit_containers ENGINE-KOMMANDO LABEL  (docker/podman-kompatible CLI)
audit_containers() {
  local e="$1" lbl="$2" d="$CT_DIR/$2" ids n id
  mkdir -p "$d"
  $e info > "$d/info.txt" 2>&1
  $e ps -a --no-trunc > "$d/ps.txt" 2>&1
  $e images --no-trunc > "$d/images.txt" 2>&1
  $e network ls > "$d/networks.txt" 2>&1
  $e volume ls > "$d/volumes.txt" 2>&1
  ids=$($e ps -aq 2>/dev/null)
  n=$(echo "$ids" | grep -c . || true)
  finding INFO CONTAINER "$lbl: $n Container -> 16-container/$lbl/"
  for id in $ids; do
    $e inspect "$id" > "$d/inspect-$id.json" 2>&1
    local name img st priv net pidm ipc capadd secopt cuser restart created mounts devices
    IFS='|' read -r name img st priv net pidm ipc capadd secopt cuser restart created mounts devices \
      < <($e inspect --format "$CT_FMT" "$id" 2>/dev/null)
    local c="$lbl:${name#/} ($img, $st)"
    [ "$priv" = true ] && finding HIGH CONTAINER "$c: laeuft --privileged"
    [ "$net" = host ] && finding MED CONTAINER "$c: Host-Netzwerk"
    [ "$pidm" = host ] && finding HIGH CONTAINER "$c: Host-PID-Namespace"
    [ "$ipc" = host ] && finding MED CONTAINER "$c: Host-IPC-Namespace"
    case "$capadd" in
      ""|"[]"|"<no value>"|"map[]") ;;
      *SYS_ADMIN*|*SYS_PTRACE*|*SYS_MODULE*|*DAC_READ_SEARCH*|*ALL*|*NET_ADMIN*) finding HIGH CONTAINER "$c: weitreichende Capabilities $capadd" ;;
      *) finding MED CONTAINER "$c: zusaetzliche Capabilities $capadd" ;;
    esac
    echo "$secopt" | grep -qiE 'unconfined|label=disable|label:disable' && finding MED CONTAINER "$c: Sicherheitsprofil deaktiviert $secopt"
    case "$devices" in ""|"[]"|"<no value>") ;; *) finding MED CONTAINER "$c: Host-Devices durchgereicht $devices" ;; esac
    local m src rest dst rw
    for m in $mounts; do
      src=${m%%>*}; rest=${m#*>}; dst=${rest%%>*}; rw=${rest##*>}
      case "$src" in
        /) finding HIGH CONTAINER "$c: Host-Root / gemountet nach $dst (rw=$rw)" ;;
        *docker.sock|*podman.sock|*containerd.sock|*crio.sock) finding HIGH CONTAINER "$c: Container-Socket gemountet ($src) = Root auf dem Host" ;;
        /etc|/etc/*|/root|/root/*|/home|/home/*|/boot|/boot/*|/proc|/proc/*|/sys|/sys/*|/dev|/var/run|/run|/usr|/usr/*|/bin|/sbin|/lib|/lib/*|/var/spool/cron*)
          if [ "$rw" = true ]; then finding HIGH CONTAINER "$c: sensibler Host-Pfad SCHREIBBAR gemountet $src -> $dst"
          else finding MED CONTAINER "$c: sensibler Host-Pfad gemountet (ro) $src -> $dst"; fi ;;
      esac
    done
    case "$cuser" in ""|root|0|0:0) finding LOW CONTAINER "$c: Prozess laeuft als root im Container" ;; esac
    case "$restart" in always|unless-stopped) finding INFO CONTAINER "$c: Restart-Policy $restart (startet automatisch)" ;; esac
    local cts
    cts=$(date -d "$(echo "${created%%.*}" | sed 's/T/ /')" +%s 2>/dev/null || echo 0)
    [ "$cts" -gt $(( $(date +%s) - DAYS*86400 )) ] && finding MED CONTAINER "$c: in den letzten $DAYS Tagen erstellt (${created%%.*})"
  done
}

if have docker; then
  audit_containers docker docker
  if [ -f /etc/docker/daemon.json ]; then
    cp /etc/docker/daemon.json "$CT_DIR/daemon.json"
    grep -q 'tcp://' /etc/docker/daemon.json && finding HIGH CONTAINER "daemon.json: Docker-API ueber TCP freigegeben"
    grep -q 'insecure-registries' /etc/docker/daemon.json && finding MED CONTAINER "daemon.json: insecure-registries gesetzt"
    grep -q '"userns-remap"' /etc/docker/daemon.json || finding LOW CONTAINER "Docker ohne userns-remap"
  fi
  systemctl cat docker.service > "$CT_DIR/docker.service.txt" 2>/dev/null
  grep -E '^ExecStart=' "$CT_DIR/docker.service.txt" | grep -qE '(-H|--host)[= ]*tcp://' && \
    finding HIGH CONTAINER "docker.service startet die Docker-API auf TCP"
  for f in /root/.docker/config.json /home/*/.docker/config.json; do
    [ -f "$f" ] && finding INFO CONTAINER "Gespeicherte Registry-Zugangsdaten: $f"
  done
fi
ss -tlnH 2>/dev/null | awk '{print $4}' | grep -qE ':2375$' && finding HIGH CONTAINER "Docker-API unverschluesselt auf Port 2375 erreichbar"
ss -tlnH 2>/dev/null | awk '{print $4}' | grep -qE ':2376$' && finding MED CONTAINER "Docker-API (TLS) auf Port 2376 - Zertifikate pruefen"
for s in /var/run/docker.sock /run/docker.sock /run/podman/podman.sock /run/containerd/containerd.sock /var/run/crio/crio.sock; do
  [ -S "$s" ] || continue
  mode=$(stat -c %a "$s")
  [ "${mode: -1}" != 0 ] && finding HIGH CONTAINER "Container-Socket fuer alle zugreifbar: $s ($(stat -c '%a %U:%G' "$s"))"
done

if have podman; then
  audit_containers podman podman-root
  for f in /etc/containers/registries.conf /etc/containers/policy.json /etc/containers/containers.conf; do
    [ -f "$f" ] && cp "$f" "$CT_DIR/" 2>/dev/null
  done
  grep -qs 'insecureAcceptAnything' /etc/containers/policy.json && finding LOW CONTAINER "policy.json akzeptiert unsignierte Images (insecureAcceptAnything)"
  # Rootless-Container einzelner Benutzer
  for h in /root /home/*; do
    [ -d "$h/.local/share/containers/storage" ] || continue
    u=$(stat -c %U "$h"); [ "$u" = root ] && continue
    uid=$(id -u "$u" 2>/dev/null) || continue
    runuser -u "$u" -- env XDG_RUNTIME_DIR="/run/user/$uid" podman ps -a > "$CT_DIR/podman-rootless-$u.txt" 2>&1
    n=$(tail -n +2 "$CT_DIR/podman-rootless-$u.txt" | grep -c . || true)
    finding MED CONTAINER "Rootless-Podman bei Benutzer $u: $n Container -> 16-container/podman-rootless-$u.txt"
  done
fi
for f in /etc/containers/systemd/* /usr/share/containers/systemd/* /root/.config/containers/systemd/* /home/*/.config/containers/systemd/*; do
  [ -f "$f" ] && finding MED CONTAINER "Quadlet (Container als systemd-Dienst): $f"
done

if have ctr; then
  for ns in $(ctr namespaces ls -q 2>/dev/null); do
    { echo "== Namespace $ns"; ctr -n "$ns" containers ls; ctr -n "$ns" tasks ls; } >> "$CT_DIR/containerd.txt" 2>&1
  done
  [ -s "$CT_DIR/containerd.txt" ] && finding INFO CONTAINER "containerd-Container -> 16-container/containerd.txt"
fi
if have crictl; then
  { crictl pods; echo; crictl ps -a; } > "$CT_DIR/crictl.txt" 2>&1
  finding INFO CONTAINER "CRI-Pods/Container -> 16-container/crictl.txt"
fi

for e in lxc incus; do
  have "$e" || continue
  $e list > "$CT_DIR/$e-list.txt" 2>&1 || continue
  for c in $($e list --format csv -c n 2>/dev/null); do
    $e config show "$c" --expanded > "$CT_DIR/$e-$c.yaml" 2>&1
    grep -q 'security.privileged: "true"' "$CT_DIR/$e-$c.yaml" && finding HIGH CONTAINER "$e:$c ist ein privilegierter Container"
    grep -q 'security.nesting: "true"' "$CT_DIR/$e-$c.yaml" && finding MED CONTAINER "$e:$c erlaubt Nesting"
    grep -q 'raw.lxc' "$CT_DIR/$e-$c.yaml" && finding MED CONTAINER "$e:$c nutzt raw.lxc-Konfiguration"
    grep -qE '^\s*source: /$' "$CT_DIR/$e-$c.yaml" && finding HIGH CONTAINER "$e:$c hat Host-Root / eingebunden"
  done
  finding INFO CONTAINER "$e-Container -> 16-container/$e-list.txt"
done
if have lxc-ls; then
  lxc-ls -f > "$CT_DIR/lxc-classic.txt" 2>&1
  for cfg in /var/lib/lxc/*/config; do
    [ -f "$cfg" ] || continue
    cp "$cfg" "$CT_DIR/lxc-$(basename "$(dirname "$cfg")").config"
    grep -qE '^\s*lxc\.apparmor\.profile\s*=\s*unconfined' "$cfg" && finding HIGH CONTAINER "LXC ohne AppArmor: $cfg"
    grep -E '^\s*lxc\.mount\.entry' "$cfg" | while read -r l; do finding MED CONTAINER "LXC-Mount in $cfg: $l"; done
  done
fi

KUBECTL=""
if have kubectl; then KUBECTL="kubectl"; elif have k3s; then KUBECTL="k3s kubectl"; elif have microk8s; then KUBECTL="microk8s kubectl"; fi
if [ -n "$KUBECTL" ] && $KUBECTL get nodes >/dev/null 2>&1; then
  {
    $KUBECTL get nodes -o wide; echo
    $KUBECTL get pods -A -o wide; echo
    $KUBECTL get deploy,ds,sts,cronjob,job -A; echo
    $KUBECTL get svc -A; echo
    $KUBECTL get clusterrolebindings -o wide
  } > "$CT_DIR/kubernetes.txt" 2>&1
  finding INFO CONTAINER "Kubernetes-Cluster gefunden -> 16-container/kubernetes.txt"
  $KUBECTL get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}|{.spec.hostNetwork}|{.spec.hostPID}|{range .spec.containers[*]}{.securityContext.privileged} {end}|{range .spec.volumes[*]}{.hostPath.path} {end}{"\n"}{end}' 2>/dev/null | \
  while IFS='|' read -r pod hn hp priv hps; do
    [ "$hn" = true ] && finding MED CONTAINER "Pod $pod: hostNetwork"
    [ "$hp" = true ] && finding HIGH CONTAINER "Pod $pod: hostPID"
    echo "$priv" | grep -q true && finding HIGH CONTAINER "Pod $pod: privilegierter Container"
    for p in $hps; do
      case "$p" in
        /|/etc*|/root*|/var/run/docker.sock|/run/containerd*|/var/lib/kubelet*|/proc*|/sys*|/dev*) finding HIGH CONTAINER "Pod $pod: sensibler hostPath $p" ;;
        *) finding MED CONTAINER "Pod $pod: hostPath $p" ;;
      esac
    done
  done
  $KUBECTL get clusterrolebindings -o jsonpath='{range .items[?(@.roleRef.name=="cluster-admin")]}{.metadata.name}: {.subjects[*].name}{"\n"}{end}' 2>/dev/null | \
  while read -r l; do
    case "$l" in system:*|cluster-admin:\ system:*) finding INFO CONTAINER "cluster-admin-Binding: $l" ;;
      *) finding MED CONTAINER "cluster-admin-Binding: $l" ;; esac
  done
fi

# ===========================================================================
section "Benutzerkonten & unter welchen Usern Dienste/Prozesse laufen"
# Konten-Konsistenz
awk -F: '{print $3}' /etc/passwd | sort | uniq -d | while read -r id; do
  finding HIGH USER "Doppelte UID $id: $(awk -F: -v i="$id" '$3==i {printf "%s ", $1}' /etc/passwd)"
done
awk -F: '{print $1}' /etc/passwd | sort | uniq -d | while read -r n; do finding HIGH USER "Doppelter Benutzername: $n"; done
awk -F: '$4==0 && $1!="root" {print $1}' /etc/passwd | while read -r u; do finding HIGH USER "Primaere Gruppe root (GID 0): $u"; done
awk -F: '$3>0 && $3<1000 && $7 !~ /(nologin|false|sync|halt|shutdown)$/ {print $1" ("$7")"}' /etc/passwd | while read -r l; do
  finding MED USER "Systemkonto mit Login-Shell: $l"
done
awk -F: 'NR==FNR {uid[$1]=$3; next} ($1 in uid) && uid[$1]>0 && uid[$1]<1000 && $2!="" && $2 !~ /^[!*]/ {print $1}' /etc/passwd /etc/shadow | while read -r u; do
  finding MED USER "Systemkonto hat ein Passwort gesetzt: $u"
done
TODAY_D=$(( $(date +%s) / 86400 ))
awk -F: -v t="$TODAY_D" -v d="$DAYS" '$3 ~ /^[0-9]+$/ && $3>0 && $3 > t-d {print $1, $3}' /etc/shadow | while read -r u day; do
  finding MED USER "Passwort von $u in den letzten $DAYS Tagen geaendert ($(date -d "@$((day*86400))" +%F))"
done
for h in $(awk -F: '$3>0 && $3<1000 {print $6}' /etc/passwd | sort -u); do
  [ -d "$h/.ssh" ] && [ "$h" != / ] && finding MED USER "Systemkonto-Home mit .ssh-Verzeichnis: $h/.ssh"
done

# Laufende Dienste: konfigurierter vs. tatsaechlicher Benutzer
printf '%-45s %-14s %-14s %s\n' UNIT CONFIG-USER LAEUFT-ALS PROGRAMM > "$OUT/17-service-users.txt"
systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}' | while read -r u; do
  mp=$(systemctl show -p MainPID --value "$u" 2>/dev/null)
  [ "${mp:-0}" -gt 0 ] 2>/dev/null || continue
  cfg=$(systemctl show -p User --value "$u" 2>/dev/null)
  dyn=$(systemctl show -p DynamicUser --value "$u" 2>/dev/null)
  euid=$(ps -o uid= -p "$mp" 2>/dev/null | tr -d ' ')
  [ -n "$euid" ] || continue
  eff=$(getent passwd "$euid" | cut -d: -f1); eff=${eff:-UID$euid}
  eshell=$(getent passwd "$euid" | cut -d: -f7)
  exe=$(readlink "/proc/$mp/exe" 2>/dev/null)
  printf '%-45s %-14s %-14s %s\n' "$u" "${cfg:-(root)}" "$eff" "$exe" >> "$OUT/17-service-users.txt"
  if [ "$euid" -ge 1000 ] && [ "$euid" -lt 65534 ] && [ "$dyn" != yes ]; then
    finding MED USER "Dienst $u laeuft unter normalem Benutzerkonto $eff"
  fi
  if [ -n "$cfg" ] && [ "$cfg" != root ] && [ "$euid" = 0 ]; then
    finding MED USER "Dienst $u ist fuer User=$cfg konfiguriert, laeuft aber als root"
  fi
  if [ "$euid" != 0 ] && [ "$euid" -lt 1000 ] && [ "$dyn" != yes ]; then
    case "$eshell" in *nologin|*false|"") ;; *) finding MED USER "Dienst $u laeuft als $eff, das Konto hat eine Login-Shell ($eshell)" ;; esac
  fi
  grep -qx "$u" "$CUSTOM_UNITS" 2>/dev/null && [ "$euid" = 0 ] && \
    finding MED USER "Custom-Service $u laeuft als root"
done
finding INFO USER "Dienst-/Benutzer-Zuordnung -> 17-service-users.txt"

# Alle Prozesse nach Benutzer
ps -eo user:32,uid,pid,ppid,etime,args --sort=uid > "$OUT/17-processes-by-user.txt" 2>/dev/null
ps -eo uid=,pid=,args= 2>/dev/null | while read -r uid pid args; do
  getent passwd "$uid" >/dev/null || finding HIGH PROZESSE "Prozess mit UID ohne Benutzerkonto: UID $uid PID $pid $(echo "$args" | cut -c1-100)"
done
ps -eo user= 2>/dev/null | sort | uniq -c | sort -rn | while read -r c u; do
  finding INFO USER "Prozesse von $u: $c"
done

# Prozess-Auffaelligkeiten
for p in /proc/[0-9]*; do
  pid=${p#/proc/}
  exe=$(readlink "$p/exe" 2>/dev/null) || continue
  [ -n "$exe" ] || continue
  args=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null | cut -c1-120)
  owner=$(stat -c %U "$p" 2>/dev/null)
  case "$exe" in
    /tmp/*|/var/tmp/*|/dev/shm/*|/run/user/*|/run/shm/*) finding HIGH PROZESSE "Prozess laeuft aus temporaerem Verzeichnis: PID $pid ($owner) $exe" ;;
    /home/*|/root/*) [ "$owner" = root ] && finding MED PROZESSE "root-Prozess laeuft aus Home-Verzeichnis: PID $pid $exe" ;;
  esac
  case "$args" in
    \[*) finding HIGH PROZESSE "Userland-Prozess tarnt sich als Kernel-Thread: PID $pid ($owner) '$args' -> $exe" ;;
  esac
  if tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -q '^LD_PRELOAD='; then
    finding HIGH PROZESSE "Prozess mit LD_PRELOAD: PID $pid ($owner) $exe $(tr '\0' '\n' < "$p/environ" | grep '^LD_PRELOAD=')"
  fi
done
# Prozesse, die in /proc existieren, aber nicht in ps auftauchen (Hinweis auf Rootkit)
ps -eo pid= | tr -d ' ' | sort > "$OUT/17-pids-ps.txt"
ls /proc | grep -E '^[0-9]+$' | sort > "$OUT/17-pids-proc.txt"
comm -13 "$OUT/17-pids-ps.txt" "$OUT/17-pids-proc.txt" | while read -r p; do
  [ -d "/proc/$p" ] && [ -z "$(ps -o pid= -p "$p" 2>/dev/null)" ] && \
    finding HIGH PROZESSE "Versteckter Prozess? PID $p in /proc, aber nicht in ps: $(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | cut -c1-100)"
done

# ===========================================================================
section "Weitere Persistenz- & Integritaetspruefungen"
# Kernel-Bootparameter
grep -oE '(^| )(init|rdinit)=[^ ]+' /proc/cmdline | while read -r o; do finding HIGH PERSIST "Kernel-Bootparameter: $o"; done
grep -oE 'module\.sig_enforce=0|lockdown=none|apparmor=0|selinux=0|security=none|audit=0' /proc/cmdline | while read -r o; do
  finding MED PERSIST "Sicherheitsfunktion per Bootparameter deaktiviert: $o"
done
find /boot/grub /etc/default/grub /etc/default/grub.d /etc/grub.d -type f -mtime -"$DAYS" 2>/dev/null | while read -r f; do
  finding MED PERSIST "Bootloader-Konfiguration kuerzlich geaendert: $f"
done

# Kernel-Module, die nicht aus Paketen stammen
lsmod | awk 'NR>1 {print $1}' | while read -r m; do
  f=$(modinfo -n "$m" 2>/dev/null)
  case "$f" in
    "") finding MED PERSIST "Geladenes Kernel-Modul ohne Datei auf der Platte: $m" ;;
    "(builtin)") ;;
    *) owned "$f" && continue
       case "$f" in */updates/dkms/*|*/extra/*) finding MED PERSIST "Kernel-Modul $m nicht aus Paket (DKMS?): $f" ;;
         *) finding HIGH PERSIST "Kernel-Modul $m nicht aus Paket: $f" ;; esac ;;
  esac
done
[ "$(cat /proc/sys/kernel/modules_disabled 2>/dev/null)" = 1 ] && finding INFO PERSIST "Nachladen von Kernel-Modulen ist gesperrt"

# Bibliotheken, die Authentifizierung/Namensaufloesung beeinflussen
find /lib /lib64 /usr/lib /usr/lib64 -path '*/security/*.so' -type f 2>/dev/null | sort -u | while read -r f; do
  owned "$f" || finding HIGH PERSIST "PAM-Modul nicht aus Paket: $f"
done
find /lib /lib64 /usr/lib /usr/lib64 -name 'libnss_*.so*' -type f 2>/dev/null | sort -u | while read -r f; do
  owned "$f" || finding HIGH PERSIST "NSS-Bibliothek nicht aus Paket: $f"
done
cp /etc/nsswitch.conf "$OUT/18-nsswitch.conf" 2>/dev/null
for f in /etc/ld.so.conf /etc/ld.so.conf.d/*; do
  [ -f "$f" ] || continue
  owned "$f" || finding MED PERSIST "Linker-Konfiguration nicht aus Paket: $f ($(grep -v '^#' "$f" | tr '\n' ' '))"
done

# Weitere Autostart-Mechanismen
for f in /etc/udev/rules.d/* /lib/udev/rules.d/* /usr/lib/udev/rules.d/*; do
  [ -f "$f" ] || continue
  owned "$f" && continue
  if grep -qE 'RUN\+?=|PROGRAM=' "$f"; then finding HIGH PERSIST "udev-Regel nicht aus Paket startet Programme: $f"
  else finding LOW PERSIST "udev-Regel nicht aus Paket: $f"; fi
done
for d in /etc/systemd/system-generators /usr/local/lib/systemd/system-generators /lib/systemd/system-generators \
         /usr/lib/systemd/system-generators /etc/systemd/user-generators /usr/lib/systemd/user-generators; do
  for f in "$d"/*; do
    [ -e "$f" ] || continue
    owned "$f" || finding HIGH PERSIST "systemd-Generator nicht aus Paket: $f"
  done
done
for f in /etc/systemd/system/*.timer /etc/systemd/system/*.path /etc/systemd/system/*.socket \
         /lib/systemd/system/*.timer /lib/systemd/system/*.path /lib/systemd/system/*.socket \
         /usr/lib/systemd/system/*.timer /usr/lib/systemd/system/*.path /usr/lib/systemd/system/*.socket; do
  [ -f "$f" ] || continue
  owned "$f" || finding MED PERSIST "systemd-${f##*.}-Unit nicht aus Paket: $f"
done
for f in /etc/systemd/user/* /usr/lib/systemd/user/* /root/.config/systemd/user/* /home/*/.config/systemd/user/*; do
  [ -f "$f" ] || continue
  owned "$f" || finding MED PERSIST "systemd-User-Unit: $f"
done
for u in /var/lib/systemd/linger/*; do
  [ -e "$u" ] && finding MED PERSIST "Linger aktiv fuer $(basename "$u") (User-Dienste laufen ohne Login)"
done
for f in /etc/xdg/autostart/* /root/.config/autostart/* /home/*/.config/autostart/*; do
  [ -f "$f" ] || continue
  owned "$f" || finding MED PERSIST "XDG-Autostart: $f"
done
for f in /etc/polkit-1/rules.d/* /etc/polkit-1/localauthority/*/* /var/lib/polkit-1/localauthority/*/*; do
  [ -f "$f" ] || continue
  owned "$f" || finding MED PERSIST "polkit-Regel nicht aus Paket: $f"
done
[ -f /etc/inetd.conf ] && grep -vE '^\s*(#|$)' /etc/inetd.conf | grep -q . && finding MED PERSIST "inetd.conf hat aktive Eintraege"
for f in /etc/xinetd.d/*; do
  [ -f "$f" ] || continue
  owned "$f" || finding MED PERSIST "xinetd-Dienst nicht aus Paket: $f"
done
grep -vE '^\s*#' /etc/aliases 2>/dev/null | grep '|' | while read -r l; do finding MED PERSIST "Mail-Alias leitet an Programm weiter: $l"; done
for f in /usr/local/share/ca-certificates/* /usr/local/share/ca-certificates/*/*; do
  [ -f "$f" ] && finding MED PERSIST "Zusaetzliches CA-Zertifikat (TLS-Abfangen moeglich): $f"
done

# SSH-Zusatzmechanismen
[ -e /etc/ssh/sshrc ] && finding MED SSH "/etc/ssh/sshrc existiert (laeuft bei jedem SSH-Login)"
grep -qiE '^permituserenvironment yes' "$OUT/08-sshd-effective.txt" 2>/dev/null && finding MED SSH "PermitUserEnvironment yes"
for h in /root $(awk -F: '{print $6}' /etc/passwd | sort -u); do
  [ -e "$h/.ssh/rc" ] && finding MED SSH "$h/.ssh/rc existiert (laeuft bei jedem SSH-Login)"
  [ -e "$h/.ssh/environment" ] && finding MED SSH "$h/.ssh/environment existiert"
done
grep -E '^(command|environment|from|permitopen|tunnel|no-)' "$OUT/08-authorized-keys.txt" 2>/dev/null | cut -c1-120 | while read -r l; do
  finding MED SSH "authorized_keys-Eintrag mit Optionen: $l"
done
find /etc/ssh -maxdepth 1 -name 'ssh_host_*' -mtime -"$DAYS" 2>/dev/null | while read -r f; do
  finding MED SSH "SSH-Host-Key kuerzlich geaendert: $f"
done
find /etc/ssh/sshd_config /etc/ssh/sshd_config.d -type f -mtime -"$DAYS" 2>/dev/null | while read -r f; do
  finding MED SSH "sshd-Konfiguration kuerzlich geaendert: $f"
done

# Shell-Startdateien der Benutzer
: > "$OUT/18-user-rc-files.txt"
for h in /root /etc/skel $(awk -F: '$3>=1000 && $3<65534 {print $6}' /etc/passwd | sort -u); do
  for f in .bashrc .profile .bash_profile .bash_login .bash_logout .zshrc .zprofile; do
    [ -f "$h/$f" ] || continue
    { echo "== $h/$f"; ls -la "$h/$f"; cat "$h/$f"; echo; } >> "$OUT/18-user-rc-files.txt"
    [ -n "$(find "$h/$f" -mtime -"$DAYS" 2>/dev/null)" ] && finding MED PERSIST "Shell-Startdatei kuerzlich geaendert: $h/$f"
  done
done
for f in /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile /home/*/.zshrc; do
  [ -f "$f" ] || continue
  grep -nE '^\s*alias\s+(sudo|su|ssh|ls|ps|netstat|ss|lsof|top|kill|passwd|cat|find)=' "$f" | while read -r l; do
    finding MED PERSIST "Alias ueberschreibt Systembefehl in $f: $l"
  done
  grep -nE 'PROMPT_COMMAND=|trap .*DEBUG' "$f" | while read -r l; do
    finding MED PERSIST "Shell-Hook in $f: $l"
  done
done

# Unveraenderbare Dateien (chattr +i/+a) - verhindern das Bereinigen
lsattr -R /etc /root /home /usr/bin /usr/sbin /usr/local /var/spool/cron /bin /sbin 2>/dev/null | \
  grep -E '^[-a-zA-Z]{4,} /' | awk '$1 ~ /[ia]/' > "$OUT/18-immutable.txt"
while read -r flags f; do
  finding MED PERSIST "Datei ist immutable/append-only ($flags): $f - mit 'chattr -i' loesbar"
done < <(head -40 "$OUT/18-immutable.txt")

# Auffaellige Dateien in /dev und temporaeren Verzeichnissen
find /dev -type f -not -path '/dev/shm/*' -not -path '/dev/mqueue/*' 2>/dev/null | head -20 | while read -r f; do
  finding MED PERSIST "Normale Datei in /dev: $f"
done
: > "$OUT/18-tmp-suspicious.txt"
for d in /tmp /var/tmp /dev/shm; do
  find "$d" -xdev -type d -name '.*' 2>/dev/null | grep -vE '/\.(X11|ICE|font|XIM|Test)-unix$' | while read -r f; do
    echo "DIR  $f" >> "$OUT/18-tmp-suspicious.txt"; finding MED PERSIST "Verstecktes Verzeichnis: $f"
  done
  find "$d" -xdev -type f 2>/dev/null | while read -r f; do
    if [ "$(head -c 4 "$f" 2>/dev/null | od -An -c | tr -d ' ')" = '177ELF' ]; then
      echo "ELF  $f" >> "$OUT/18-tmp-suspicious.txt"; finding HIGH PERSIST "Programmdatei (ELF) in $d: $f"
    elif [ -x "$f" ]; then
      echo "EXEC $f" >> "$OUT/18-tmp-suspicious.txt"; finding MED PERSIST "Ausfuehrbare Datei in $d: $f"
    fi
  done
done

# Netzwerk-Interfaces
ip -o link 2>/dev/null | grep -q PROMISC && ip -o link | grep PROMISC | awk -F': ' '{print $2}' | while read -r i; do
  finding MED NETZ "Interface im Promiscuous-Modus (mitschneiden?): $i"
done
ip -o link 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -E '^(tun|tap|wg|gre|vxlan|ipip|sit)' | while read -r i; do
  finding MED NETZ "Tunnel-Interface: $i"
done

# Kuerzlich geaenderte Dateien in Anwendungsverzeichnissen
find /opt /srv /var/www /usr/local -xdev -type f -mtime -"$DAYS" -printf '%TY-%Tm-%Td %TH:%TM %u %p\n' 2>/dev/null | sort -r | head -1000 > "$OUT/18-appdirs-recent.txt"
n=$(count "$OUT/18-appdirs-recent.txt")
[ "$n" -gt 0 ] && finding INFO PERSIST "$n Dateien in /opt, /srv, /var/www, /usr/local in den letzten $DAYS Tagen geaendert -> 18-appdirs-recent.txt"

# ===========================================================================
section "Kuerzlich geaenderte Dateien in /etc"
find /etc -xdev -type f -mtime -"$DAYS" -printf '%TY-%Tm-%Td %TH:%TM  %p\n' 2>/dev/null | sort -r > "$OUT/10-etc-recent.txt"
finding INFO DATEIEN "$(count "$OUT/10-etc-recent.txt") Dateien in /etc in den letzten $DAYS Tagen geaendert -> 10-etc-recent.txt"

# ===========================================================================
section "Logs"
SINCE="$(date -d "-$DAYS days" '+%Y-%m-%d')"
run 11-last.txt sh -c 'last -Faiw 2>/dev/null; echo; echo "== lastb"; lastb -Faiw 2>/dev/null | head -200; echo; lastlog 2>/dev/null'
if ls /var/log/auth.log* >/dev/null 2>&1; then
  zgrep -hE 'Accepted|sudo:.*COMMAND|useradd|usermod|groupadd|passwd\[|new user|session opened for user root' /var/log/auth.log* 2>/dev/null > "$OUT/11-auth-events.txt"
else
  journalctl --since "$SINCE" --no-pager -o short-iso _COMM=sshd _COMM=sudo _COMM=useradd _COMM=usermod _COMM=passwd > "$OUT/11-auth-events.txt" 2>&1
fi
grep 'Accepted' "$OUT/11-auth-events.txt" | grep -oE 'for [^ ]+ from [0-9a-fA-F:.]+' | sort | uniq -c | sort -rn > "$OUT/11-ssh-logins-summary.txt"
while read -r c _ u _ ip; do finding INFO LOGS "SSH-Login: $u von $ip (${c}x)"; done < <(head -15 "$OUT/11-ssh-logins-summary.txt")
grep -E 'useradd|new user|usermod|groupadd' "$OUT/11-auth-events.txt" | tail -20 | while IFS= read -r l; do
  finding MED LOGS "Benutzerverwaltung: $l"
done
n=$(grep -c 'sudo:.*COMMAND' "$OUT/11-auth-events.txt" 2>/dev/null || true)
[ "${n:-0}" -gt 0 ] && finding INFO LOGS "$n sudo-Kommandos protokolliert -> 11-auth-events.txt"
run 11-journal-errors.txt journalctl --since "$SINCE" -p err --no-pager -o short-iso
run 11-apt-history.txt sh -c 'zcat -f /var/log/apt/history.log* 2>/dev/null; echo; zcat -f /var/log/dpkg.log* 2>/dev/null | grep -E " install | remove "'
zcat -f /var/log/dpkg.log* 2>/dev/null | awk -v s="$SINCE" '$1>=s && $3=="install" {print $1, $4}' | sort -u | tail -20 | while read -r d p; do
  finding LOW LOGS "Paket installiert am $d: $p"
done
{
  getent passwd | awk -F: '{print $6}' | sort -u | while read -r h; do
    for f in "$h/.bash_history" "$h/.zsh_history" "$h/.mysql_history" "$h/.python_history"; do
      [ -f "$f" ] && { echo "== $f"; ls -la "$f"; cat "$f"; }
    done
  done
} > "$OUT/11-shell-histories.txt" 2>&1
finding INFO LOGS "Shell-Histories gesammelt -> 11-shell-histories.txt"
for h in /root $(awk -F: '$3>=1000 && $3<65534 {print $6}' /etc/passwd); do
  [ -L "$h/.bash_history" ] && finding MED LOGS "$h/.bash_history ist ein Symlink -> $(readlink "$h/.bash_history")"
done
grep -rlE 'HISTFILE=/dev/null|HISTSIZE=0|unset HISTFILE' /etc/profile /etc/profile.d /etc/bash.bashrc /root/.bashrc /home/*/.bashrc 2>/dev/null | while read -r f; do
  finding MED LOGS "History wird deaktiviert in $f"
done
for f in /var/log/auth.log /var/log/syslog /var/log/wtmp /var/log/btmp /var/log/lastlog; do
  [ -e "$f" ] && [ ! -s "$f" ] && finding MED LOGS "Logdatei leer (moeglicherweise geleert): $f"
done
systemctl is-active --quiet rsyslog 2>/dev/null || systemctl is-active --quiet systemd-journald 2>/dev/null || \
  finding HIGH LOGS "Weder rsyslog noch journald laufen"
[ -f /etc/systemd/journald.conf ] && grep -qiE '^\s*Storage=none' /etc/systemd/journald.conf && finding HIGH LOGS "journald Storage=none - es wird nichts geloggt"

# ===========================================================================
section "Externe Audit-Tools (dauert einige Minuten)"
if have rkhunter; then
  # Hinweis: --propupd erzeugt die Baseline vom aktuellen (evtl. manipulierten) Stand
  rkhunter --propupd --sk >/dev/null 2>&1 || true
  rkhunter --check --sk --rwo --nocolors > "$OUT/12-rkhunter.txt" 2>&1
  grep -i 'warning' "$OUT/12-rkhunter.txt" | head -20 | while IFS= read -r l; do finding MED ROOTKIT "rkhunter: $l"; done
fi
if have chkrootkit; then
  chkrootkit -q > "$OUT/13-chkrootkit.txt" 2>&1
  grep -iE 'infected|suspicious' "$OUT/13-chkrootkit.txt" | head -20 | while IFS= read -r l; do finding HIGH ROOTKIT "chkrootkit: $l"; done
fi

# --- Lynis: laufen lassen und Report auswerten ------------------------------
LYNIS_REPORT="$OUT/14-lynis-report.dat"
LYNIS_LOG="$OUT/14-lynis.log"
if have lynis; then
  echo "   Lynis laeuft..."
  lynis audit system --quiet --no-colors --logfile "$LYNIS_LOG" --report-file "$LYNIS_REPORT" > "$OUT/14-lynis.txt" 2>&1
fi
# Falls Lynis schon vorher lief oder hier nicht lief: Standard-Report verwenden
if [ ! -s "$LYNIS_REPORT" ] && [ -s /var/log/lynis-report.dat ]; then
  cp /var/log/lynis-report.dat "$LYNIS_REPORT"; cp /var/log/lynis.log "$LYNIS_LOG" 2>/dev/null
  finding INFO LYNIS "Kein neuer Lauf - vorhandener Report /var/log/lynis-report.dat ausgewertet"
fi

if [ -s "$LYNIS_REPORT" ]; then
  HARDENING_INDEX=$(grep -E '^hardening_index=' "$LYNIS_REPORT" | cut -d= -f2)
  # Format: warning[]=TEST-ID|Text|Details|Loesung|
  : > "$OUT/14-lynis-parsed.txt"
  parse_lynis() { # $1=key $2=Level
    grep -E "^$1\[\]=" "$LYNIS_REPORT" | cut -d= -f2- | while IFS='|' read -r id text detail sol _; do
      local extra=""
      [ -n "$detail" ] && [ "$detail" != "-" ] && extra=" [$detail]"
      finding "$2" LYNIS "$id: $text$extra"
      printf '%-6s %-12s %s%s\n        Loesung: %s\n' "$2" "$id" "$text" "$extra" "${sol:--}" >> "$OUT/14-lynis-parsed.txt"
    done
  }
  parse_lynis warning MED
  # Warnungen zu besonders relevanten Bereichen hochstufen
  awk -F'\t' 'BEGIN{OFS="\t"} $2=="LYNIS" && $1=="MED" && $3 ~ /^(AUTH|SSH|FILE|BOOT|KRNL|ROOT|MALW|PKGS|LOGG|ACCT)-/ {$1="HIGH"} {print}' \
    "$FINDINGS" > "$FINDINGS.tmp" && mv "$FINDINGS.tmp" "$FINDINGS"
  parse_lynis suggestion LOW
  grep -E '^vulnerable_package\[\]=' "$LYNIS_REPORT" | cut -d= -f2- | while read -r p; do
    finding HIGH LYNIS "Verwundbares Paket: $p"
  done
  grep -E '^(expired_certificate|plugin_.*warning)\[\]=' "$LYNIS_REPORT" | cut -d= -f2- | while read -r p; do
    finding MED LYNIS "$p"
  done
  # Zusaetzlich: Auffaelligkeiten aus dem Lynis-Log
  if [ -s "$LYNIS_LOG" ]; then
    grep -E 'Result: (found|FOUND|WARNING|weak|insecure|NOT )|Warning:' "$LYNIS_LOG" \
      | grep -viE 'not found|no .* found|NOT found|nothing found' | sort -u > "$OUT/14-lynis-log-hits.txt"
    n=$(count "$OUT/14-lynis-log-hits.txt")
    [ "$n" -gt 0 ] && finding LOW LYNIS "$n weitere Auffaelligkeiten im Lynis-Log -> 14-lynis-log-hits.txt"
  fi
  case "$HARDENING_INDEX" in
    ''|*[!0-9]*) HARDENING_INDEX="n/a" ;;
    *) [ "$HARDENING_INDEX" -lt 60 ] && finding MED LYNIS "Lynis Hardening-Index niedrig: $HARDENING_INDEX/100" ;;
  esac
else
  finding INFO LYNIS "Kein Lynis-Report vorhanden (Lynis nicht installiert?)"
fi

# ===========================================================================
# GESAMT-SUMMARY
# ===========================================================================
CATS="REPOS TOOLS PAKETE DATEIEN AUTOSTART CUSTOM SVC PERSIST CONTAINER USER SSH NETZ PROZESSE ROOTKIT LOGS LYNIS"
cat_title() {
  case "$1" in
    REPOS) echo "APT-Paketquellen" ;; TOOLS) echo "Tools" ;;
    PAKETE) echo "Paket-Integritaet (manipulierte Dateien)" ;; DATEIEN) echo "Dateien" ;;
    AUTOSTART) echo "Autostart, Dienste, Cron" ;;
    CUSTOM) echo "Custom-Services & ausgehende Verbindungen" ;;
    SVC) echo "Dienste: Manipulation & Verhalten" ;;
    PERSIST) echo "Persistenz (Kernel, PAM/NSS, udev, Shell-Dateien, tmp)" ;;
    CONTAINER) echo "Container (Docker, Podman, LXC, Kubernetes)" ;; USER) echo "Benutzer, sudo, PAM" ;;
    SSH) echo "SSH" ;; NETZ) echo "Netzwerk & Ports" ;; PROZESSE) echo "Prozesse & Kernel" ;;
    ROOTKIT) echo "Rootkit-Scanner" ;; LOGS) echo "Logs & Historie" ;; LYNIS) echo "Lynis-Audit" ;;
    *) echo "$1" ;;
  esac
}

render_summary() { # $1 = 1 -> mit Farben
  local R="" Y="" G="" C="" B="" H="" N=""
  [ "$1" = 1 ] && { R=$RED; Y=$YEL; G=$GRN; C=$CYA; B=$BLU; H=$BLD; N=$RST; }
  local nh nm nl ni
  nh=$(grep -c $'^HIGH\t' "$FINDINGS" || true); nm=$(grep -c $'^MED\t' "$FINDINGS" || true)
  nl=$(grep -c $'^LOW\t' "$FINDINGS" || true);  ni=$(grep -c $'^INFO\t' "$FINDINGS" || true)
  local line="=========================================================================="
  echo
  echo "${H}${line}${N}"
  echo "${H}  BLUE-TEAM AUDIT - GESAMT-SUMMARY${N}"
  echo "  Host: $(hostname)   Zeit: $(date '+%Y-%m-%d %H:%M')   Zeitraum: $DAYS Tage"
  echo "${H}${line}${N}"
  printf '  %sKRITISCH (HIGH): %3s%s   %sPRUEFEN (MED): %3s%s   %sHAERTUNG (LOW): %3s%s   %sINFO: %3s%s\n' \
    "$R" "$nh" "$N" "$Y" "$nm" "$N" "$C" "$nl" "$N" "$G" "$ni" "$N"
  echo "  Lynis Hardening-Index: $HARDENING_INDEX   |   Details: $OUT"
  echo "${H}${line}${N}"

  # Block 1: alle kritischen Funde auf einen Blick
  if [ "$nh" -gt 0 ]; then
    echo
    echo "${R}${H}>>> ZUERST ANSEHEN - alle kritischen Funde <<<${N}"
    awk -F'\t' '$1=="HIGH" {printf "  %-10s %s\n", "["$2"]", $3}' "$FINDINGS" | while IFS= read -r l; do
      echo "${R}${l}${N}"
    done
  fi

  # Block 2: alles nach Kategorie, innerhalb nach Schwere
  local cat n lvl col label
  for cat in $CATS; do
    n=$(awk -F'\t' -v c="$cat" '$2==c && $1!="INFO"' "$FINDINGS" | wc -l)
    local ninfo
    ninfo=$(awk -F'\t' -v c="$cat" '$2==c && $1=="INFO"' "$FINDINGS" | wc -l)
    [ $((n + ninfo)) -eq 0 ] && continue
    echo
    echo "${B}${H}--- $(cat_title "$cat") ($n Probleme) ---${N}"
    for lvl in HIGH MED LOW INFO; do
      case $lvl in HIGH) col=$R; label="HIGH" ;; MED) col=$Y; label="MED " ;; LOW) col=$C; label="LOW " ;; INFO) col=$G; label="INFO" ;; esac
      awk -F'\t' -v c="$cat" -v l="$lvl" '$1==l && $2==c {print $3}' "$FINDINGS" | while IFS= read -r t; do
        printf '  %s%s%s  %s\n' "$col" "$label" "$N" "$t"
      done
    done
  done
  echo
  echo "${H}${line}${N}"
  echo "  Legende: HIGH = sehr wahrscheinlich Manipulation/kritisch, sofort pruefen"
  echo "           MED  = auffaellig, manuell verifizieren"
  echo "           LOW  = Haertungsempfehlung"
  echo "           INFO = Kontext / Bestandsaufnahme"
  echo "  Lynis-Details mit Loesungsvorschlaegen: $OUT/14-lynis-parsed.txt"
  echo "${H}${line}${N}"
}

render_summary 0 > "$SUMMARY"
render_summary 1
echo
echo "Summary gespeichert: $SUMMARY"
