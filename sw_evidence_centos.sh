#!/bin/bash
#
# sw_evidence_centos.sh
#
# Software inventory evidence collection for CentOS 6.10 and CentOS 7.5.
#
# Targets those two releases specifically. It will run on other CentOS/RHEL 6.x
# and 7.x builds and notes the difference in the summary; anything outside the
# 6.x/7.x family is refused rather than half-collected.
#
# Produces a defensible, self-describing evidence package: every installed
# RPM with version and origin, software installed outside RPM (pip/gem/npm),
# executables owned by no package, services, cron/timers, kernel modules,
# update history, configured repositories, and local accounts.
#
# Design decisions that matter for evidence:
#
#   * Nothing is silently dropped. Categories that return nothing still get a
#     file, so an empty result is affirmative evidence rather than a gap.
#   * No network calls. yum/rpm are used only against local databases; no
#     metadata refresh, no repo contact. Safe on isolated hosts.
#   * Incomplete collection is recorded, not hidden. Run without root and it
#     still runs, but the summary is stamped COLLECTION INCOMPLETE.
#   * One file for both releases. CentOS 6.10 (SysV init + upstart, rpm 4.8,
#     bash 4.1) and CentOS 7.5 (systemd, rpm 4.11) differ in service manager,
#     timers and available tooling; all of it is detected at run time, never
#     assumed, and the detected release is recorded in the evidence.
#
# Usage:
#   ./sw_evidence_centos.sh [options]
#
#   -o DIR      output parent directory      (default: /var/tmp)
#   -r TEXT     reference / system name written into the summary
#   -c NAME     collector name               (default: logname or $USER)
#   -p PATHS    colon-separated roots for the unowned-executable scan
#               (default: /usr/local:/opt:/awips:/awips2:/root:/home:/tmp:
#                /var/tmp:/srv - AWIPS trees are large non-RPM installs)
#   -b FILE     approved-software baseline: one package name per line, or a
#               CSV whose first column is the name. Anything installed that is
#               not matched is written to Deviations.csv
#   -V          also run "rpm -Va" package verification  (SLOW: 10-40 min)
#   -S          skip the unowned-executable scan
#   -A          do not create the tar.gz package
#   -h          this help
#
# Run as root. Without it, other users' crontabs, some file trees, and parts
# of the package database are unreadable and the package is stamped
# incomplete.
#
set -u

# Transferring this file through Windows turns the line endings into CRLF,
# which breaks the shebang with a confusing "bad interpreter" error. Best-effort
# check: it only fires when the file is invoked as "bash sw_evidence_centos.sh",
# because a CRLF shebang fails before any of this runs.
if LC_ALL=C grep -q "$(printf '\r')" "$0" 2>/dev/null; then
  echo "FATAL: this file has Windows (CRLF) line endings." >&2
  echo "       Fix with:  dos2unix $0" >&2
  echo "       or:        sed -i 's/\r\$//' $0" >&2
  exit 1
fi

# ------------------------------------------------------------------ setup --

OUT_ROOT="/var/tmp"
REFERENCE=""
COLLECTOR=""
SCAN_PATHS="/usr/local:/opt:/awips:/awips2:/root:/home:/tmp:/var/tmp:/srv"
DO_VERIFY=0
DO_SCAN=1
DO_ARCHIVE=1
BASELINE=""

while getopts "o:r:c:p:b:VSAh" opt 2>/dev/null; do
  case "$opt" in
    o) OUT_ROOT="$OPTARG" ;;
    r) REFERENCE="$OPTARG" ;;
    c) COLLECTOR="$OPTARG" ;;
    p) SCAN_PATHS="$OPTARG" ;;
    b) BASELINE="$OPTARG" ;;
    V) DO_VERIFY=1 ;;
    S) DO_SCAN=0 ;;
    A) DO_ARCHIVE=0 ;;
    h) sed -n '3,40p' "$0"; exit 0 ;;
    *) echo "Invalid option. Use -h for help." >&2; exit 2 ;;
  esac
done

HOSTNAME_S=$(hostname 2>/dev/null || uname -n)
START_LOCAL=$(date '+%Y-%m-%d %H:%M:%S')
START_UTC=$(date -u '+%Y-%m-%d %H:%M:%S')
START_EPOCH=$(date '+%s')
TAG="${HOSTNAME_S}_$(date '+%Y%m%d-%H%M%S')"
OUTDIR="${OUT_ROOT}/SWEvidence_${TAG}"

[ -n "$COLLECTOR" ] || COLLECTOR=$(logname 2>/dev/null || echo "${USER:-${LOGNAME:-unknown}}")

IS_ROOT=0
[ "$(id -u)" -eq 0 ] && IS_ROOT=1

mkdir -p "$OUTDIR" || { echo "Cannot create $OUTDIR" >&2; exit 1; }
TMPD=$(mktemp -d "${TMPDIR:-/tmp}/swev.XXXXXX") || exit 1
trap 'rm -rf "$TMPD"' EXIT INT TERM

# Log the run itself, the way the Windows collector transcribes it. Real stdout
# and stderr are saved on fd 3/4 so the log can be closed before the archive is
# built, otherwise the tarball would contain a truncated copy of its own log.
LOGFILE="${OUTDIR}/CollectionLog_${TAG}.txt"
exec 3>&1 4>&2
exec > >(tee -a "$LOGFILE") 2>&1

WARNINGS="$TMPD/warnings"
: > "$WARNINGS"
warn() { echo " - $*" >> "$WARNINGS"; echo "WARNING: $*" >&2; }

# --------------------------------------------------------------- helpers ---

# csv <field> [field...]  -> one properly quoted/escaped CSV line
csv() {
  local out="" f
  for f in "$@"; do
    f=${f//\"/\"\"}
    f=${f//$'\n'/ }
    f=${f//$'\r'/}
    f=${f//$'\t'/ }
    out="${out}\"${f}\","
  done
  printf '%s\n' "${out%,}"
}

# Output path for a category. Filenames carry host and timestamp exactly as
# the Windows collector does, so packages from many hosts concatenate cleanly
# without relying on the folder name surviving the copy.
F() { echo "${OUTDIR}/${1}_${TAG}.csv"; }

# note an output file and report its record count (data rows, header excluded)
report() {
  local name="$1" file; file=$(F "$1"); local n=0
  if [ -f "$file" ]; then
    n=$(( $(wc -l < "$file") - 1 ))
    [ "$n" -lt 0 ] && n=0
  fi
  printf '  %-32s %6s record(s)\n' "$name" "$n"
}

step() { echo; echo "[ $* ]"; }

have() { command -v "$1" >/dev/null 2>&1; }

# ------------------------------------------------------------- preflight ---

echo "================================================================"
echo " SOFTWARE INVENTORY EVIDENCE COLLECTION"
echo "================================================================"
echo " Host        : $HOSTNAME_S"
echo " Collector   : $COLLECTOR"
echo " Reference   : ${REFERENCE:-(none)}"
echo " Started     : $START_LOCAL local / ${START_UTC}Z"
echo " Running as  : $(id -un) (uid $(id -u))"
echo " Output      : $OUTDIR"
echo "================================================================"

if [ "$IS_ROOT" -eq 0 ]; then
  warn "Collection was NOT run as root - results are incomplete."
  echo
  echo "*** NOT ROOT - other users' crontabs, restricted directories and parts"
  echo "*** of the package database will be missing. Re-run as root."
fi

if ! have rpm; then
  echo "FATAL: rpm not found. This script targets RPM-based systems." >&2
  exit 1
fi

# ------------------------------------------- 1. system identification -----

step "System identification"

REDHAT_RELEASE=$(cat /etc/redhat-release 2>/dev/null || echo "unknown")

# Full release string, e.g. 6.10 or 7.5.1804
OSVERSION=$(echo "$REDHAT_RELEASE" | grep -o '[0-9]\+\.[0-9.]*[0-9]' | head -1)
[ -n "$OSVERSION" ] || OSVERSION=$(sed -n 's/.*el\([0-9]\+\).*/\1/p' <<< "$(uname -r)")
OSMAJOR=${OSVERSION%%.*}

case "$OSMAJOR" in
  6|7) : ;;
  *)
    echo "FATAL: this script targets CentOS 6.x / 7.x." >&2
    echo "       Detected: ${REDHAT_RELEASE} (major '${OSMAJOR:-unknown}')" >&2
    echo "       Refusing to run rather than produce a partial inventory." >&2
    exec 1>&3 2>&4                      # stop teeing before removing the log
    rm -f "$LOGFILE" 2>/dev/null
    rmdir "$OUTDIR" 2>/dev/null         # leave no stub evidence folder behind
    exit 1 ;;
esac

# Named targets are 6.10 and 7.5; anything else in-family still runs but the
# deviation is recorded in the evidence rather than passing silently.
OS_IS_TARGET="yes"
case "$OSVERSION" in
  6.10|7.5|7.5.*) : ;;
  *) OS_IS_TARGET="no"
     warn "Release ${OSVERSION} is not a named target (6.10 / 7.5); collection proceeded on the ${OSMAJOR}.x code path." ;;
esac

# The release decides the init system - CentOS 6 is never systemd and CentOS 7
# always is. Probing for a systemctl binary instead would let a stray or
# leftover binary misroute the whole services/timers collection.
case "$OSMAJOR" in
  6) INIT_SYS="sysv"
     have chkconfig || warn "chkconfig not found on a 6.x host - service enumeration will be thin." ;;
  7) INIT_SYS="systemd"
     have systemctl || warn "systemctl not found on a 7.x host - service enumeration will be thin." ;;
esac

dmi() {
  local f="/sys/class/dmi/id/$1"
  if [ -r "$f" ]; then cat "$f" 2>/dev/null
  elif have dmidecode && [ "$IS_ROOT" -eq 1 ]; then dmidecode -s "$2" 2>/dev/null
  fi
}

SYS_VENDOR=$(dmi sys_vendor system-manufacturer)
SYS_MODEL=$(dmi product_name system-product-name)
SYS_SERIAL=$(dmi product_serial system-serial-number)
BIOS_VER=$(dmi bios_version bios-version)
[ -n "${SYS_SERIAL:-}" ] || SYS_SERIAL="(unreadable - needs root/dmidecode)"

CPU_MODEL=$(awk -F': ' '/^model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null)
CPU_COUNT=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)
MEM_TOTAL_MB=$(awk '/^MemTotal:/{printf "%.0f", $2/1024}' /proc/meminfo 2>/dev/null)
ROOT_USE=$(df -Pk / 2>/dev/null | awk 'NR==2{print $5" used of "$2" KB"}')

SELINUX_STATE=$(getenforce 2>/dev/null || echo "n/a")
MACHINE_ID=$(cat /etc/machine-id 2>/dev/null || cat /var/lib/dbus/machine-id 2>/dev/null || echo "")
# install date: the filesystem package is laid down first on a fresh install
OS_INSTALLED=$(rpm -q --qf '%{INSTALLTIME:date}\n' basesystem 2>/dev/null | head -1)
[ -n "$OS_INSTALLED" ] || OS_INSTALLED=$(rpm -q --qf '%{INSTALLTIME:date}\n' filesystem 2>/dev/null | head -1)

{
  csv ComputerName Collected Reference Collector RanAsRoot Vendor Model Serial \
      BiosVersion OSRelease OSVersion NamedTarget KernelRelease KernelVersion \
      Architecture InitSystem CPUModel CPUCount TotalMemoryMB RootFilesystem \
      SELinux MachineID OSInstalled Uptime RPMVersion BashVersion
  csv "$HOSTNAME_S" "${START_UTC}Z" "$REFERENCE" "$COLLECTOR" "$IS_ROOT" \
      "${SYS_VENDOR:-}" "${SYS_MODEL:-}" "${SYS_SERIAL:-}" "${BIOS_VER:-}" \
      "$REDHAT_RELEASE" "$OSVERSION" "$OS_IS_TARGET" \
      "$(uname -r)" "$(uname -v)" "$(uname -m)" "$INIT_SYS" \
      "${CPU_MODEL:-}" "${CPU_COUNT:-}" "${MEM_TOTAL_MB:-}" "${ROOT_USE:-}" \
      "$SELINUX_STATE" "$MACHINE_ID" "${OS_INSTALLED:-}" \
      "$(uptime 2>/dev/null | sed 's/^ *//')" \
      "$(rpm --version 2>/dev/null | awk '{print $NF}')" "${BASH_VERSION:-}"
} > "$(F SystemIdentification)"

echo "  OS          : $REDHAT_RELEASE  [${OSVERSION}]"
echo "  Kernel      : $(uname -r) ($(uname -m))"
echo "  Init system : $INIT_SYS"
report SystemIdentification

# ----------------------------------------------- 2. installed packages ----

step "Installed packages (RPM database)"

# from_repo lookup out of the yum database, so each package carries the
# repository it was installed from - on an isolated host anything not from a
# local/approved repo is worth a look.
declare -A REPO_OF 2>/dev/null || true
if [ -d /var/lib/yum/yumdb ]; then
  while IFS= read -r d; do
    [ -f "$d/from_repo" ] || continue
    b=$(basename "$d")
    rest=${b#*-}                 # strip leading pkgid checksum
    arch=${rest##*-}
    nvr=${rest%-*}
    REPO_OF["${nvr}.${arch}"]=$(cat "$d/from_repo" 2>/dev/null)
  done < <(find /var/lib/yum/yumdb -mindepth 2 -maxdepth 2 -type d 2>/dev/null)
else
  warn "/var/lib/yum/yumdb not present - package repository origin unavailable."
fi

# The %|TAG?{...}:{...}| conditional picks whichever signature tag is populated.
# A package showing (none) is unsigned - a finding, not a formatting artifact.
RPMFMT='%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{VENDOR}\t%{INSTALLTIME:date}\t%{BUILDTIME:date}\t%{SIZE}\t%{GROUP}\t%{LICENSE}\t%{SOURCERPM}\t%{BUILDHOST}\t%|DSAHEADER?{%{DSAHEADER:pgpsig}}:{%|RSAHEADER?{%{RSAHEADER:pgpsig}}:{%|SIGGPG?{%{SIGGPG:pgpsig}}:{%|SIGPGP?{%{SIGPGP:pgpsig}}:{(none)}|}|}|}|\t%{SUMMARY}\n'

{
  csv ComputerName Collected Name Epoch Version Release Arch NEVRA Vendor \
      InstallTime BuildTime SizeBytes Group License SourceRPM BuildHost \
      Signature Signed FromRepo Summary

  # Tabs are IFS whitespace: bash collapses runs of them, so an empty field
  # (no vendor, no repo) would silently shift every column after it. Translate
  # to US (\037), a non-whitespace delimiter that preserves empty fields.
  rpm -qa --qf "$RPMFMT" 2>/dev/null | tr '\t' '\037' | LC_ALL=C sort -f |
  while IFS=$'\037' read -r name epoch ver rel arch vendor itime btime size grp lic srpm bhost sig summ; do
    [ -n "${name:-}" ] || continue
    [ "$epoch" = "(none)" ] && epoch=""
    nvra="${name}-${ver}-${rel}.${arch}"
    signed="yes"
    case "$sig" in ""|"(none)"|"None") signed="NO" ;; esac
    repo="${REPO_OF[$nvra]:-}"
    # Side file in US-delimited form. Later stages consume this instead of
    # re-parsing the CSV: free-text fields can legitimately contain the
    # sequence '","' and would shift columns in a naive splitter.
    printf '%s\037%s\037%s\037%s\037%s\n' \
        "$name" "${ver}-${rel}" "$vendor" "$repo" "$signed" >> "$TMPD/pkgs.dat"
    csv "$HOSTNAME_S" "${START_UTC}Z" "$name" "$epoch" "$ver" "$rel" "$arch" \
        "$nvra" "$vendor" "$itime" "$btime" "$size" "$grp" "$lic" "$srpm" \
        "$bhost" "$sig" "$signed" "$repo" "$summ"
  done
} > "$(F InstalledPackages)"

report InstalledPackages
PKG_COUNT=$(( $(wc -l < "$(F InstalledPackages)") - 1 ))
UNSIGNED_COUNT=$(awk -F'\037' '$5=="NO"' "$TMPD/pkgs.dat" 2>/dev/null | wc -l)
echo "  -> $UNSIGNED_COUNT package(s) with no GPG signature"

# ------------------------------------ 3. software outside package mgmt ----

step "Software installed outside RPM (language package managers)"

{
  csv ComputerName Collected Manager Name Version Location
  for py in pip pip2 pip3; do
    if have "$py"; then
      loc=$(command -v "$py")
      # NB: braces matter - without them the || binds tighter than the pipe
      # and a successful "pip list" would bypass the parser entirely.
      { "$py" list --format=freeze 2>/dev/null || "$py" freeze 2>/dev/null; } |
        while IFS= read -r line; do
          case "$line" in
            *"=="*)
              printf '%s\037%s\037%s\037%s\n' "$py" "${line%%==*}" "${line##*==}" "$loc" >> "$TMPD/nonrpm.dat"
              csv "$HOSTNAME_S" "${START_UTC}Z" "$py" "${line%%==*}" "${line##*==}" "$loc" ;;
          esac
        done
    fi
  done

  if have gem; then
    loc=$(command -v gem)
    gem list --local 2>/dev/null | while IFS= read -r line; do
      case "$line" in
        *"("*")"*)
          gname=${line%% *}
          gver=${line#*(}; gver=${gver%)*}
          printf '%s\037%s\037%s\037%s\n' "gem" "$gname" "$gver" "$loc" >> "$TMPD/nonrpm.dat"
          csv "$HOSTNAME_S" "${START_UTC}Z" "gem" "$gname" "$gver" "$loc" ;;
      esac
    done
  fi

  if have npm; then
    loc=$(command -v npm)
    npm ls -g --depth=0 --parseable --long 2>/dev/null |
      while IFS= read -r line; do
        case "$line" in
          *":"*)
            pkg=${line#*:}
            case "$pkg" in
              *"@"*)
                printf '%s\037%s\037%s\037%s\n' "npm-global" "${pkg%@*}" "${pkg##*@}" "$loc" >> "$TMPD/nonrpm.dat"
                csv "$HOSTNAME_S" "${START_UTC}Z" "npm-global" "${pkg%@*}" "${pkg##*@}" "$loc" ;;
            esac ;;
        esac
      done
  fi
} > "$(F NonRPMSoftware)"

report NonRPMSoftware

# ------------------------------- 4. executables owned by no package -------

if [ "$DO_SCAN" -eq 1 ]; then
  step "Executables owned by no package"
  echo "  (building package file list, then scanning - this is the slow phase)"

  rpm -qal 2>/dev/null | LC_ALL=C sort -u > "$TMPD/owned.txt"
  echo "  package-owned paths: $(wc -l < "$TMPD/owned.txt")"

  OLDIFS=$IFS; IFS=':'; read -ra SCANV <<< "$SCAN_PATHS"; IFS=$OLDIFS
  EXIST=()
  for p in "${SCANV[@]}"; do [ -d "$p" ] && EXIST+=("$p"); done

  : > "$TMPD/found.txt"
  if [ ${#EXIST[@]} -gt 0 ]; then
    echo "  scanning: ${EXIST[*]}"
    find "${EXIST[@]}" -xdev -type f -perm /111 2>/dev/null |
      LC_ALL=C sort -u > "$TMPD/found.txt"
  fi
  echo "  executable files found: $(wc -l < "$TMPD/found.txt")"

  LC_ALL=C comm -23 "$TMPD/found.txt" "$TMPD/owned.txt" > "$TMPD/unowned.txt"

  {
    csv ComputerName Collected Path SizeBytes Modified Owner Group Mode Setuid FileType
    while IFS= read -r f; do
      [ -e "$f" ] || continue
      info=$(stat -c '%s|%y|%U|%G|%a' "$f" 2>/dev/null) || continue
      sz=${info%%|*};       rest=${info#*|}
      mt=${rest%%|*};       rest=${rest#*|}
      ow=${rest%%|*};       rest=${rest#*|}
      gr=${rest%%|*};       md=${rest##*|}
      mt=${mt%%.*}
      suid="no"
      [ -u "$f" ] && suid="SETUID"
      [ -g "$f" ] && suid="${suid},SETGID"
      ftype=""
      have file && ftype=$(file -b "$f" 2>/dev/null | cut -c1-120)
      printf '%s\037%s\037%s\n' "$f" "$suid" "$ftype" >> "$TMPD/unowned.dat"
      csv "$HOSTNAME_S" "${START_UTC}Z" "$f" "$sz" "$mt" "$ow" "$gr" "$md" "$suid" "$ftype"
    done < "$TMPD/unowned.txt"
  } > "$(F UnownedExecutables)"

  report UnownedExecutables
else
  { csv ComputerName Collected Path SizeBytes Modified Owner Group Mode Setuid FileType; } \
    > "$(F UnownedExecutables)"
  warn "Unowned-executable scan skipped by option -S."
fi

# ------------------------------------------ 5. rpm -Va verification -------

if [ "$DO_VERIFY" -eq 1 ]; then
  step "RPM package verification (rpm -Va)"
  echo "  This compares every packaged file against the RPM database."
  echo "  Expect 10-40 minutes. Config-file differences are normal."
  {
    csv ComputerName Collected Flags FileType Path SizeDiff ModeDiff MD5Diff \
        MtimeDiff OwnerDiff GroupDiff ConfigFile
    rpm -Va 2>/dev/null | while IFS= read -r line; do
      flags=$(echo "$line" | awk '{print $1}')
      rest=$(echo "$line" | sed 's/^[^ ]* *//')
      ftype=""
      case "$rest" in
        c\ *) ftype="config";  rest=${rest#c } ;;
        d\ *) ftype="doc";     rest=${rest#d } ;;
        g\ *) ftype="ghost";   rest=${rest#g } ;;
        l\ *) ftype="license"; rest=${rest#l } ;;
        r\ *) ftype="readme";  rest=${rest#r } ;;
      esac
      sd="";  md="";  m5="";  mt="";  od="";  gd=""
      case "$flags" in *S*) sd="SIZE" ;; esac
      case "$flags" in *M*) md="MODE" ;; esac
      case "$flags" in *5*) m5="MD5"  ;; esac
      case "$flags" in *T*) mt="MTIME";; esac
      case "$flags" in *U*) od="OWNER";; esac
      case "$flags" in *G*) gd="GROUP";; esac
      csv "$HOSTNAME_S" "${START_UTC}Z" "$flags" "$ftype" "$rest" \
          "$sd" "$md" "$m5" "$mt" "$od" "$gd" "$([ "$ftype" = "config" ] && echo yes || echo no)"
    done
  } > "$(F PackageVerification)"
  report PackageVerification
fi

# ------------------------------------------------------- 6. services -----

step "Services"

{
  csv ComputerName Collected Service State Enablement Detail
  if [ "$INIT_SYS" = "systemd" ]; then
    systemctl list-units --type=service --all --no-legend --no-pager 2>/dev/null |
      sed 's/^[[:space:]]*●[[:space:]]*//' |
      while read -r unit load active sub rest; do
        [ -n "${unit:-}" ] || continue
        case "$unit" in *.service) ;; *) continue ;; esac
        en=$(systemctl is-enabled "$unit" 2>/dev/null || echo "unknown")
        csv "$HOSTNAME_S" "${START_UTC}Z" "$unit" "$active/$sub" "$en" "$load ${rest:-}"
      done
  else
    chkconfig --list 2>/dev/null | while IFS= read -r line; do
      case "$line" in
        *"0:"*)
          svc=$(echo "$line" | awk '{print $1}')
          lv=$(echo "$line" | sed 's/^[^ \t]*[ \t]*//')
          st="stopped"
          service "$svc" status >/dev/null 2>&1 && st="running"
          csv "$HOSTNAME_S" "${START_UTC}Z" "$svc" "$st" "$lv" "sysv" ;;
      esac
    done
    for f in /etc/init/*.conf; do
      [ -e "$f" ] || continue
      csv "$HOSTNAME_S" "${START_UTC}Z" "$(basename "$f" .conf)" "n/a" "upstart" "$f"
    done
  fi
} > "$(F Services)"

report Services

# ------------------------------------------- 7. cron and scheduled work ---

step "Scheduled tasks (cron, timers)"

{
  csv ComputerName Collected Source Owner Schedule Command
  for f in /etc/crontab /etc/cron.d/*; do
    [ -f "$f" ] || continue
    while IFS= read -r line; do
      case "$line" in ''|\#*) continue ;; esac
      # skip environment assignments (PATH=, MAILTO=), not commands containing "="
      [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] && continue
      # /etc/crontab and /etc/cron.d have a user field at position 6
      csv "$HOSTNAME_S" "${START_UTC}Z" "$f" \
          "$(echo "$line" | awk '{print $6}')" \
          "$(echo "$line" | awk '{print $1,$2,$3,$4,$5}')" \
          "$(echo "$line" | awk '{for(i=7;i<=NF;i++) printf "%s ", $i}')"
    done < "$f"
  done

  for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    [ -d "$d" ] || continue
    for f in "$d"/*; do
      [ -f "$f" ] || continue
      csv "$HOSTNAME_S" "${START_UTC}Z" "$d" "root" "$(basename "$d")" "$f"
    done
  done

  if [ "$IS_ROOT" -eq 1 ]; then
    for cf in /var/spool/cron/*; do
      [ -f "$cf" ] || continue
      u=$(basename "$cf")
      while IFS= read -r line; do
        case "$line" in ''|\#*) continue ;; esac
        [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] && continue
        # user crontabs have no user field - command starts at position 6
        csv "$HOSTNAME_S" "${START_UTC}Z" "user-crontab" "$u" \
            "$(echo "$line" | awk '{print $1,$2,$3,$4,$5}')" \
            "$(echo "$line" | awk '{for(i=6;i<=NF;i++) printf "%s ", $i}')"
      done < "$cf"
    done
  else
    echo " - Per-user crontabs not read (requires root)." >> "$WARNINGS"
  fi

  if [ "$INIT_SYS" = "systemd" ]; then
    # list-timers has multi-word date columns that defeat positional parsing;
    # list-unit-files is two clean fields and works on systemd 219 (CentOS 7).
    systemctl list-unit-files --type=timer --no-legend --no-pager 2>/dev/null |
      while read -r unit state _rest; do
        [ -n "${unit:-}" ] || continue
        act=$(systemctl show -p Unit "$unit" 2>/dev/null | cut -d= -f2)
        csv "$HOSTNAME_S" "${START_UTC}Z" "systemd-timer" "system" \
            "$unit (${state:-unknown})" "${act:-}"
      done
  fi
} > "$(F ScheduledTasks)"

report ScheduledTasks

# -------------------------------------------------- 8. kernel modules ----

step "Kernel modules"

{
  csv ComputerName Collected Module Size UsedBy Version Signed Path
  if have lsmod; then
    lsmod 2>/dev/null | tail -n +2 | while read -r m sz used rest; do
      ver=""; sgn=""; pth=""
      if have modinfo; then
        pth=$(modinfo -n "$m" 2>/dev/null)
        ver=$(modinfo -F version "$m" 2>/dev/null | head -1)
        sgn=$(modinfo -F signer  "$m" 2>/dev/null | head -1)
      fi
      csv "$HOSTNAME_S" "${START_UTC}Z" "$m" "$sz" "${rest:-}" "$ver" "$sgn" "$pth"
    done
  fi
} > "$(F KernelModules)"

report KernelModules

# ----------------------------------------- 9. update history and repos ---

step "Update history and configured repositories"

{
  csv ComputerName Collected Date Action Package Source
  # /var/log/yum.log exists on both 6 and 7 and needs no yum invocation
  for lf in /var/log/yum.log /var/log/yum.log-*; do
    [ -f "$lf" ] || continue
    while IFS= read -r line; do
      d=$(echo "$line" | awk '{print $1,$2,$3}')
      a=$(echo "$line" | awk '{print $4}')
      p=$(echo "$line" | awk '{print $5}')
      [ -n "${p:-}" ] || continue
      csv "$HOSTNAME_S" "${START_UTC}Z" "$d" "${a%:}" "$p" "$lf"
    done < "$lf"
  done
} > "$(F UpdateHistory)"

report UpdateHistory

{
  csv ComputerName Collected RepoFile RepoID Enabled BaseURL
  for rf in /etc/yum.repos.d/*.repo; do
    [ -f "$rf" ] || continue
    rid=""; en=""; url=""
    while IFS= read -r line; do
      case "$line" in
        \[*\])
          [ -n "$rid" ] && csv "$HOSTNAME_S" "${START_UTC}Z" "$rf" "$rid" "$en" "$url"
          rid=${line#[}; rid=${rid%]}; en=""; url="" ;;
        enabled=*)  en=${line#enabled=} ;;
        baseurl=*)  url=${line#baseurl=} ;;
        mirrorlist=*) [ -n "$url" ] || url=${line#mirrorlist=} ;;
      esac
    done < "$rf"
    [ -n "$rid" ] && csv "$HOSTNAME_S" "${START_UTC}Z" "$rf" "$rid" "$en" "$url"
  done
} > "$(F Repositories)"

report Repositories

# --------------------------------------------------- 10. local accounts --

step "Local accounts"

{
  csv ComputerName Collected User UID GID Home Shell LoginCapable
  while IFS=: read -r u _ uid gid _ home shell; do
    [ -n "${u:-}" ] || continue
    lc="yes"
    case "$shell" in */nologin|*/false|""|*/sync|*/shutdown|*/halt) lc="no" ;; esac
    csv "$HOSTNAME_S" "${START_UTC}Z" "$u" "$uid" "$gid" "$home" "$shell" "$lc"
  done < /etc/passwd
} > "$(F LocalAccounts)"

report LocalAccounts

# ---------------------------- 10b. running processes and network exposure --

step "Running processes"

# Software that is actually executing, resolved back to its owning package
# where one exists. A long-running process from an unowned binary is the
# strongest signal that something is installed outside package management.
{
  csv ComputerName Collected User PID PPID StartTime Command Executable OwningPackage
  ps -eo user=,pid=,ppid=,lstart=,args= 2>/dev/null |
  while read -r usr pid ppid lw lmo ld ltm lyr args; do
    [ -n "${pid:-}" ] || continue
    started="$lw $lmo $ld $ltm $lyr"
    exe=""
    [ -r "/proc/$pid/exe" ] && exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
    [ -n "$exe" ] || exe=$(echo "$args" | awk '{print $1}')
    # every row gets an explicit label: an empty cell would read as "not checked"
    case "$args" in
      \[*\]*) pkg="(kernel thread)" ;;
      *)
        if [ -n "$exe" ] && [ -e "$exe" ]; then
          pkg=$(rpm -qf --qf '%{NAME}' "$exe" 2>/dev/null)
          case "$pkg" in *"not owned"*|*"no package"*|'') pkg="(no package)" ;; esac
        else
          pkg="(binary not on disk)"
        fi ;;
    esac
    csv "$HOSTNAME_S" "${START_UTC}Z" "$usr" "$pid" "$ppid" "$started" \
        "$args" "$exe" "$pkg"
  done
} > "$(F Processes)"

report Processes

step "Listening network services"

# What is exposed, and which program is behind it. ss on 7, netstat on 6.
{
  csv ComputerName Collected Protocol LocalAddress LocalPort State Process
  if have ss; then
    # columns: Netid State Recv-Q Send-Q Local:Port Peer:Port Process
    ss -tulpn 2>/dev/null | tail -n +2 |
    while read -r proto state _recvq _sendq local peer procinfo; do
      [ -n "${local:-}" ] || continue
      port=${local##*:}
      addr=${local%:*}
      csv "$HOSTNAME_S" "${START_UTC}Z" "$proto" "$addr" "$port" \
          "${state:-listen}" "${procinfo:-}"
    done
  elif have netstat; then
    netstat -tulpn 2>/dev/null | grep -iE '^(tcp|udp)' |
    while read -r proto _ _ local peer state procinfo; do
      [ -n "${local:-}" ] || continue
      case "$proto" in udp*) procinfo="$state"; state="listen" ;; esac
      port=${local##*:}
      addr=${local%:*}
      csv "$HOSTNAME_S" "${START_UTC}Z" "$proto" "$addr" "$port" "$state" "${procinfo:-}"
    done
  else
    warn "Neither ss nor netstat present - listening services not enumerated."
  fi
} > "$(F ListeningServices)"

report ListeningServices

# ------------------------------------------- 10c. inetd / xinetd services --

step "inetd / xinetd managed services"

# On 6.x these are real services that never appear in chkconfig --list output
# as running daemons; they are started on demand and are easy to miss.
{
  csv ComputerName Collected Source Service Disabled ServerPath Detail
  if [ -f /etc/inetd.conf ]; then
    while IFS= read -r line; do
      case "$line" in ''|\#*) continue ;; esac
      csv "$HOSTNAME_S" "${START_UTC}Z" "/etc/inetd.conf" \
          "$(echo "$line" | awk '{print $1}')" "no" \
          "$(echo "$line" | awk '{print $7}')" "$line"
    done < /etc/inetd.conf
  fi
  for xf in /etc/xinetd.d/*; do
    [ -f "$xf" ] || continue
    svc=$(basename "$xf")
    dis=$(grep -iE '^[[:space:]]*disable' "$xf" 2>/dev/null | head -1 | awk -F= '{gsub(/ /,"",$2); print $2}')
    srv=$(grep -iE '^[[:space:]]*server[[:space:]]*=' "$xf" 2>/dev/null | head -1 | awk -F= '{gsub(/^ +| +$/,"",$2); print $2}')
    csv "$HOSTNAME_S" "${START_UTC}Z" "/etc/xinetd.d" "$svc" "${dis:-unset}" "${srv:-}" "$xf"
  done
} > "$(F InetdServices)"

report InetdServices

# ------------------------------------------------ 10d. setuid/setgid files --

if [ "$DO_SCAN" -eq 1 ]; then
  step "Setuid / setgid files (system-wide)"

  {
    csv ComputerName Collected Path Mode Owner Group SizeBytes Modified Type OwningPackage
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | LC_ALL=C sort |
    while IFS= read -r f; do
      info=$(stat -c '%a|%U|%G|%s|%y' "$f" 2>/dev/null) || continue
      md=${info%%|*};  rest=${info#*|}
      ow=${rest%%|*};  rest=${rest#*|}
      gr=${rest%%|*};  rest=${rest#*|}
      sz=${rest%%|*};  mt=${rest##*|}
      mt=${mt%%.*}
      typ=""
      [ -u "$f" ] && typ="setuid"
      [ -g "$f" ] && typ="${typ:+$typ,}setgid"
      pkg=$(rpm -qf --qf '%{NAME}' "$f" 2>/dev/null)
      case "$pkg" in *"not owned"*|*"no package"*|'') pkg="(no package)" ;; esac
      csv "$HOSTNAME_S" "${START_UTC}Z" "$f" "$md" "$ow" "$gr" "$sz" "$mt" "$typ" "$pkg"
    done
  } > "$(F SetuidFiles)"

  report SetuidFiles
else
  { csv ComputerName Collected Path Mode Owner Group SizeBytes Modified Type OwningPackage; } \
    > "$(F SetuidFiles)"
fi

# ------------------------------------------------- 10e. version marker files --

if [ "$DO_SCAN" -eq 1 ]; then
  step "Version marker files in local software trees"

  # Locally installed software (AWIPS and friends) usually has no package
  # metadata at all - a VERSION file on disk is often the only version record
  # that exists for it.
  {
    csv ComputerName Collected Path SizeBytes Modified Contents
    OLDIFS=$IFS; IFS=':'; read -ra VPATHS <<< "$SCAN_PATHS"; IFS=$OLDIFS
    VEXIST=()
    for vp in "${VPATHS[@]}"; do [ -d "$vp" ] && VEXIST+=("$vp"); done
    if [ ${#VEXIST[@]} -gt 0 ]; then
      find "${VEXIST[@]}" -xdev -maxdepth 6 -type f \
           \( -iname '*version*' -o -iname '*release*' -o -iname 'VERSION' \) \
           -size -64k 2>/dev/null | LC_ALL=C sort | head -500 |
      while IFS= read -r vf; do
        sz=$(stat -c '%s' "$vf" 2>/dev/null) || continue
        mt=$(stat -c '%y' "$vf" 2>/dev/null); mt=${mt%%.*}
        body=$(head -c 200 "$vf" 2>/dev/null | tr '\n\r\t' '   ')
        printf '%s\037%s\n' "$vf" "$body" >> "$TMPD/vers.dat"
        csv "$HOSTNAME_S" "${START_UTC}Z" "$vf" "$sz" "$mt" "$body"
      done
    fi
  } > "$(F VersionFiles)"

  report VersionFiles
else
  { csv ComputerName Collected Path SizeBytes Modified Contents; } > "$(F VersionFiles)"
fi

# ------------------------------------------------ 10f. mounted filesystems --

step "Mounted filesystems"

# Recorded because every scan in this script uses -xdev: it does not cross
# mount points. This file is what tells a reviewer which filesystems were in
# scope and which were not.
{
  csv ComputerName Collected Device MountPoint FSType Options Scanned
  while read -r dev mnt fstype opts _rest; do
    [ -n "${mnt:-}" ] || continue
    scanned="not scanned (-xdev)"
    [ "$mnt" = "/" ] && scanned="scanned"
    case ":$SCAN_PATHS:" in *":$mnt:"*) scanned="scanned (scan root)" ;; esac
    case "$fstype" in proc|sysfs|devpts|tmpfs|devtmpfs|cgroup|securityfs|debugfs|rpc_pipefs|hugetlbfs|mqueue|selinuxfs|pstore|configfs|autofs|binfmt_misc) scanned="pseudo-fs" ;; esac
    csv "$HOSTNAME_S" "${START_UTC}Z" "$dev" "$mnt" "$fstype" "$opts" "$scanned"
  done < /proc/mounts
} > "$(F Mounts)"

report Mounts

# ------------------------------------------ 11. consolidated rollup ------

step "Consolidated software view"

for d in pkgs nonrpm unowned vers; do [ -f "$TMPD/$d.dat" ] || : > "$TMPD/$d.dat"; done

{
  csv ComputerName Collected Source Name Version Origin Location Flagged

  while IFS=$'\037' read -r nm vr vd rp sg; do
    [ -n "${nm:-}" ] || continue
    fl=""
    [ "${sg:-}" = "NO" ] && fl="UNSIGNED PACKAGE"
    csv "$HOSTNAME_S" "${START_UTC}Z" "RPM" "$nm" "$vr" "${rp:-unknown repo}" "${vd:-}" "$fl"
  done < "$TMPD/pkgs.dat"

  while IFS=$'\037' read -r mg nm vr lc; do
    [ -n "${nm:-}" ] || continue
    csv "$HOSTNAME_S" "${START_UTC}Z" "$mg" "$nm" "$vr" "outside RPM" "$lc" \
        "Not under package management"
  done < "$TMPD/nonrpm.dat"

  while IFS=$'\037' read -r pth su ft; do
    [ -n "${pth:-}" ] || continue
    fl="Owned by no package"
    case "$su" in SETUID*) fl="Owned by no package; $su" ;; esac
    csv "$HOSTNAME_S" "${START_UTC}Z" "File" "$(basename "$pth")" "" "unpackaged" "$pth" "$fl"
  done < "$TMPD/unowned.dat"

  while IFS=$'\037' read -r vf body; do
    [ -n "${vf:-}" ] || continue
    csv "$HOSTNAME_S" "${START_UTC}Z" "Version file" "$(basename "$(dirname "$vf")")" \
        "$(echo "$body" | cut -c1-60)" "local install" "$vf" \
        "Version claimed by file, not by any package"
  done < "$TMPD/vers.dat"
} > "$(F AllSoftware_Consolidated)"

report AllSoftware_Consolidated

# ------------------------------------------------- 11b. baseline compare --

DEV_COUNT=0
if [ -n "$BASELINE" ]; then
  step "Baseline comparison"
  if [ ! -f "$BASELINE" ]; then
    warn "Baseline file not found: $BASELINE"
    { csv ComputerName Collected Name Version Vendor FromRepo Finding; } > "$(F Deviations)"
  else
    # accept a bare list or a CSV whose first column is the package name
    sed -e 's/\r$//' -e 's/^"//' -e 's/".*$//' -e 's/,.*$//' "$BASELINE" 2>/dev/null |
      grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$' |
      LC_ALL=C sort -u -f > "$TMPD/baseline.txt"
    echo "  baseline entries: $(wc -l < "$TMPD/baseline.txt")"

    {
      csv ComputerName Collected Name Version Vendor FromRepo Finding
      while IFS=$'\037' read -r nm vr vd rp _sg; do
        if ! LC_ALL=C grep -qix -- "$nm" "$TMPD/baseline.txt" 2>/dev/null; then
          csv "$HOSTNAME_S" "${START_UTC}Z" "$nm" "$vr" "$vd" "$rp" \
              "Not present on approved software baseline"
        fi
      done < "$TMPD/pkgs.dat"
    } > "$(F Deviations)"

    DEV_COUNT=$(( $(wc -l < "$(F Deviations)") - 1 ))
    [ "$DEV_COUNT" -lt 0 ] && DEV_COUNT=0
    report Deviations
    echo "  $DEV_COUNT package(s) not matched to the baseline"
  fi
fi

# ------------------------------------------------- 12. summary + listing --

step "Summary and package listing"

END_LOCAL=$(date '+%Y-%m-%d %H:%M:%S')
ELAPSED=$(( $(date '+%s') - START_EPOCH ))
NONRPM_COUNT=$(( $(wc -l < "$(F NonRPMSoftware)") - 1 ))
UNOWNED_COUNT=$(( $(wc -l < "$(F UnownedExecutables)") - 1 ))
SETUID_COUNT=$(grep -c 'SETUID' "$(F UnownedExecutables)" 2>/dev/null)
[ -n "$SETUID_COUNT" ] || SETUID_COUNT=0

{
  echo "================================================================"
  echo "        SOFTWARE INVENTORY EVIDENCE - COLLECTION SUMMARY"
  echo "================================================================"
  echo
  echo "Reference          : ${REFERENCE:-(none supplied)}"
  echo "Collector          : $COLLECTOR"
  echo "Host name          : $HOSTNAME_S"
  echo "Vendor/Model       : ${SYS_VENDOR:-} ${SYS_MODEL:-}"
  echo "Serial number      : ${SYS_SERIAL:-}"
  echo "Operating system   : $REDHAT_RELEASE"
  echo "Release / target   : ${OSVERSION} (named target 6.10 or 7.5: $OS_IS_TARGET)"
  echo "Kernel             : $(uname -r) ($(uname -m))"
  echo "Init system        : $INIT_SYS"
  echo "SELinux            : $SELINUX_STATE"
  echo "OS install date    : ${OS_INSTALLED:-unknown}"
  echo
  echo "Collection started : $START_LOCAL local / ${START_UTC}Z"
  echo "Collection ended   : $END_LOCAL local"
  echo "Duration           : $((ELAPSED / 60))m $((ELAPSED % 60))s"
  echo "Ran as root        : $([ "$IS_ROOT" -eq 1 ] && echo yes || echo NO)"
  echo "Method             : RPM database query (rpm -qa), yumdb repository"
  echo "                     origin, language package managers, package-owned"
  echo "                     file list vs file system scan, service manager"
  echo "                     query, cron and timer enumeration, yum log"
  echo "                     history. No network calls, no repo metadata"
  echo "                     refresh, no package state modified."
  echo
  echo "--- COUNTS ---------------------------------------------------------"
  printf "%-38s: %s\n" "Installed RPM packages"        "$PKG_COUNT"
  printf "%-38s: %s\n" "  of which unsigned"           "$UNSIGNED_COUNT"
  printf "%-38s: %s\n" "Software outside RPM"          "$NONRPM_COUNT"
  printf "%-38s: %s\n" "Executables owned by no package" "$UNOWNED_COUNT"
  printf "%-38s: %s\n" "  of which setuid/setgid"      "$SETUID_COUNT"
  printf "%-38s: %s\n" "Running processes"             "$(( $(wc -l < "$(F Processes)") - 1 ))"
  printf "%-38s: %s\n" "  from unpackaged binaries"     "$(grep -c '(no package)' "$(F Processes)" 2>/dev/null)"
  printf "%-38s: %s\n" "Listening network services"     "$(( $(wc -l < "$(F ListeningServices)") - 1 ))"
  printf "%-38s: %s\n" "inetd/xinetd services"          "$(( $(wc -l < "$(F InetdServices)") - 1 ))"
  printf "%-38s: %s\n" "Setuid/setgid files"            "$(( $(wc -l < "$(F SetuidFiles)") - 1 ))"
  printf "%-38s: %s\n" "  owned by no package"          "$(grep -c '(no package)' "$(F SetuidFiles)" 2>/dev/null)"
  printf "%-38s: %s\n" "Version marker files"           "$(( $(wc -l < "$(F VersionFiles)") - 1 ))"
  printf "%-38s: %s\n" "Mounted filesystems"            "$(( $(wc -l < "$(F Mounts)") - 1 ))"
  printf "%-38s: %s\n" "Services"                      "$(( $(wc -l < "$(F Services)") - 1 ))"
  printf "%-38s: %s\n" "Scheduled tasks"               "$(( $(wc -l < "$(F ScheduledTasks)") - 1 ))"
  printf "%-38s: %s\n" "Kernel modules"                "$(( $(wc -l < "$(F KernelModules)") - 1 ))"
  printf "%-38s: %s\n" "Local accounts"                "$(( $(wc -l < "$(F LocalAccounts)") - 1 ))"
  if [ -n "$BASELINE" ]; then
    printf "%-38s: %s\n" "Baseline deviations"          "$DEV_COUNT"
  fi
  echo

  if [ "$IS_ROOT" -eq 0 ]; then
    echo "*** COLLECTION INCOMPLETE ******************************************"
    echo "*** This collection was NOT run as root. It does not represent   ***"
    echo "*** the full software state of the host.                         ***"
    echo "********************************************************************"
    echo
  fi

  if [ -s "$WARNINGS" ]; then
    echo "--- COLLECTION NOTES / LIMITATIONS ---------------------------------"
    cat "$WARNINGS"
    echo
  fi

  echo "--- INSTALLED PACKAGES (name / version-release.arch / repo) ---------"
  echo
  rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null |
    tr '\t' '\037' | LC_ALL=C sort -f | while IFS=$'\037' read -r n vra; do
      printf '%-42s %s\n' "$n" "$vra"
    done
} > "${OUTDIR}/Summary_${TAG}.txt"

# package contents listing
{
  echo "================================================================"
  echo "   EVIDENCE PACKAGE CONTENTS"
  echo "================================================================"
  echo "Reference   : ${REFERENCE:-(none supplied)}"
  echo "Host        : $HOSTNAME_S   Serial: ${SYS_SERIAL:-}"
  echo "Collector   : $COLLECTOR"
  echo "Collected   : $START_LOCAL local / ${START_UTC}Z"
  echo "Ran as root : $([ "$IS_ROOT" -eq 1 ] && echo yes || echo NO)"
  echo
  ls -l "$OUTDIR" | tail -n +2 | awk '{printf "%-52s %12s bytes\n", $NF, $5}'
} > "${OUTDIR}/MANIFEST_${TAG}.txt"

# ------------------------------------------------------- 13. package -----

# stop teeing before the archive is built so the log inside it is complete
exec 1>&3 2>&4
sleep 0.3

ARCHIVE=""
if [ "$DO_ARCHIVE" -eq 1 ]; then
  ARCHIVE="${OUT_ROOT}/SWEvidence_${TAG}.tar.gz"
  if tar -czf "$ARCHIVE" -C "$OUT_ROOT" "SWEvidence_${TAG}" 2>/dev/null; then
    :
  else
    warn "Archive creation failed."
    ARCHIVE=""
  fi
fi

echo
echo "================================================================"
echo " COLLECTION COMPLETE"
echo "================================================================"
echo " RPM packages   : $PKG_COUNT ($UNSIGNED_COUNT unsigned)"
echo " Outside RPM    : $NONRPM_COUNT"
echo " Unowned execs  : $UNOWNED_COUNT"
echo " Duration       : $((ELAPSED / 60))m $((ELAPSED % 60))s"
echo " Folder         : $OUTDIR"
[ -n "$ARCHIVE" ] && echo " Package        : $ARCHIVE"
if [ "$IS_ROOT" -eq 0 ]; then
  echo
  echo " *** COLLECTION INCOMPLETE - not run as root ***"
fi
echo "================================================================"
