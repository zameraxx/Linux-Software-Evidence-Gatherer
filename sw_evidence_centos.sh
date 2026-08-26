#!/bin/bash
#
# sw_evidence_centos.sh
#
# Software inventory evidence collection for RPM-based RHEL/CentOS hosts,
# spanning RHEL Advanced Server 2.1, RHEL 4, CentOS 6.10, CentOS/RHEL 7.5,
# RHEL 7.8, and RHEL 8. The OS is detected at run time and the collector
# adapts its behavior to what that release actually has available - it does
# not assume systemd, associative arrays, modern findutils, yum, or a
# GPG-signature-aware rpm queryformat, because none of those are safe
# assumptions across a 20+ year span of releases. See "OS DETECTION AND
# COMPATIBILITY" below for exactly what differs and why.
#
# Produces a defensible, self-describing evidence package: every installed
# RPM with version and origin, software installed outside RPM (pip/gem/npm),
# executables owned by no package, services, cron/timers, kernel modules,
# update history, configured repositories, local accounts, running
# processes, listening network services, inetd/xinetd services, setuid/
# setgid files, version-marker files in local software trees, and mounted
# filesystems.
#
# OUTPUT: exactly one CSV and one summary text file (plus, optionally, a
# tar.gz of the two). Earlier versions of this script wrote a dozen-plus
# category CSVs into a per-host folder; every one of those categories still
# exists, but now as rows in a single wide table discriminated by a
# RecordType column, matching the same "one CSV, RecordType-tagged" shape
# the Windows counterpart (Get-SoftwareEvidence.ps1) already uses. Nothing
# was dropped to get there - see "OUTPUT FORMAT" below for the column layout.
#
#   <host>_<timestamp>.csv columns:
#     RecordType, ComputerName, Collected, Reference, Collector, RanAsRoot,
#     Vendor, Model, Serial, BiosVersion, OSRelease, OSVersion, NamedTarget,
#     KernelRelease, KernelVersion, Architecture, InitSystem, CPUModel,
#     CPUCount, TotalMemoryMB, RootFilesystem, SELinux, MachineID,
#     OSInstalled, Uptime, RPMVersion, BashVersion,
#     Name, Version, Origin, Path, Flagged, Attributes
#
#   The Vendor..BashVersion block is populated only on the single
#   RecordType=SystemInfo row per host; every other RecordType leaves it
#   blank and uses Name/Version/Origin/Path/Flagged/Attributes instead.
#   Attributes carries whatever is specific to that RecordType as
#   "key=value; key=value; ..." (semicolons and newlines inside a value are
#   sanitized out so the pairs stay unambiguous; split on the FIRST "=" per
#   pair, since a value such as a BaseURL can legitimately contain one).
#
#   RecordType values: SystemInfo (1 row/host), Package, NonRpmPackage,
#   UnownedExecutable, PackageVerification (only with -V), Service,
#   ScheduledTask, KernelModule, UpdateHistory, Repository, LocalAccount,
#   Process, ListeningService, InetdService, SetuidFile, VersionFile,
#   Mount, Deviation (only with -b).
#
#   <host>_<timestamp>_Summary.txt: human-readable run summary (host
#   identity, record counts per category, warnings/limitations) followed by
#   the full installed-package listing and the console transcript of the
#   run itself - everything that used to be a separate CollectionLog and
#   MANIFEST file is folded in here instead.
#
# Design decisions that matter for evidence:
#
#   * Nothing is silently dropped. Categories that return nothing still get
#     rows counted as zero in the summary, so an empty result is affirmative
#     evidence rather than a gap.
#   * No network calls. rpm/yum/dnf are used only against local databases;
#     no metadata refresh, no repo contact. Safe on isolated hosts. (dnf
#     repoquery on RHEL 8 is run with -C / cache-only for the same reason.)
#   * Incomplete collection is recorded, not hidden. Run without root and it
#     still runs, but the summary is stamped COLLECTION INCOMPLETE. A
#     collector-side limitation (old rpm, no stat, no associative arrays,
#     no bash regex) is recorded as a warning in the evidence rather than
#     failing outright or silently producing thinner data.
#   * One script for six releases. Nothing about init system, shell
#     capability, rpm feature set, or package-manager tooling is assumed -
#     all of it is detected at run time and recorded alongside the data it
#     affected.
#
# OS DETECTION AND COMPATIBILITY
# -------------------------------
# Release is read from /etc/redhat-release (falling back to /etc/os-release,
# then a kernel-release heuristic) and OSMAJOR drives these branches:
#
#   OSMAJOR 2  RHEL (Advanced Server) 2.1   - sysv init, bash 2.05b, no
#                                              associative arrays, no bash
#                                              regex (=~), rpm 4.0.x (no
#                                              GPG-signature queryformat
#                                              conditional), no yum/yumdb,
#                                              no /sys (kernel 2.4).
#   OSMAJOR 4  RHEL 4                        - sysv init, bash 3.0 (no
#                                              associative arrays), rpm 4.3,
#                                              no yum by default.
#   OSMAJOR 6  CentOS/RHEL 6.10              - sysv + chkconfig (+ a little
#                                              upstart), bash 4.1, yum/yumdb.
#   OSMAJOR 7  CentOS/RHEL 7.5, RHEL 7.8     - systemd, bash 4.2, yum/yumdb.
#   OSMAJOR 8  RHEL 8                        - systemd, bash 4.4, dnf (no
#                                              yumdb - repo origin is read
#                                              via "dnf repoquery" instead).
#
# Anything outside that set is refused rather than half-collected. A
# version inside the family but not a named target (e.g. RHEL 6.9 or
# RHEL 7.6) still runs on that major version's code path; the deviation
# from the named target is recorded in the evidence rather than passing
# silently.
#
# Portability notes for the ancient end of that range (RHEL AS 2.1 / RHEL 4):
#   - Associative arrays (bash 4+) are used only for the package-repository
#     lookup; on bash <4 that lookup is skipped and FromRepo is left blank
#     rather than risking undefined array behavior. Everything else about
#     the collection is unaffected.
#   - "[[ str =~ regex ]]" needs bash 3.0+; AS 2.1 ships 2.05b. The one place
#     that used it (skipping environment-variable lines in crontabs) is
#     implemented with plain glob/case matching instead, which has always
#     worked in every bash version.
#   - "find -perm /111" (any-bit-set) needs findutils 4.3.3+ and the older
#     "-perm +111" spelling was removed from later findutils - neither
#     spelling is safe across this whole range. "-perm -100 -o -perm -010
#     -o -perm -001" (all-of, tried three ways) has always worked and is
#     used instead.
#   - rpm's GPG-signature queryformat conditional is probed once at start;
#     if unsupported, Signed reports "UNCHECKED" instead of a guessed value.
#
# Usage:
#   ./sw_evidence_centos.sh [options]
#
#   -o DIR      output directory              (default: /var/tmp)
#   -r TEXT     reference / system name written into the summary
#   -c NAME     collector name               (default: logname or $USER)
#   -p PATHS    colon-separated roots for the unowned-executable scan
#               (default: /usr/local:/opt:/awips:/awips2:/root:/home:/tmp:
#                /var/tmp:/srv - AWIPS trees are large non-RPM installs)
#   -b FILE     approved-software baseline: one package name per line, or a
#               CSV whose first column is the name. Anything installed that
#               is not matched becomes a RecordType=Deviation row.
#   -V          also run "rpm -Va" package verification  (SLOW: 10-40 min)
#   -S          skip the unowned-executable / setuid-file filesystem scans
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
    h) sed -n '3,160p' "$0"; exit 0 ;;
    *) echo "Invalid option. Use -h for help." >&2; exit 2 ;;
  esac
done

HOSTNAME_S=$(hostname 2>/dev/null || uname -n)
START_LOCAL=$(date '+%Y-%m-%d %H:%M:%S')
START_UTC=$(date -u '+%Y-%m-%d %H:%M:%S')
START_EPOCH=$(date '+%s')
TAG="${HOSTNAME_S}_$(date '+%Y%m%d-%H%M%S')"

[ -n "$COLLECTOR" ] || COLLECTOR=$(logname 2>/dev/null || echo "${USER:-${LOGNAME:-unknown}}")

IS_ROOT=0
[ "$(id -u)" -eq 0 ] && IS_ROOT=1

mkdir -p "$OUT_ROOT" || { echo "Cannot create $OUT_ROOT" >&2; exit 1; }
TMPD=$(mktemp -d "${TMPDIR:-/tmp}/swev.XXXXXX") || exit 1
trap 'rm -rf "$TMPD"' EXIT INT TERM

CSV_FILE="${OUT_ROOT}/LinuxSoftwareEvidence_${TAG}.csv"
SUMMARY_FILE="${OUT_ROOT}/LinuxSoftwareEvidence_Summary_${TAG}.txt"
CONSOLE_LOG="$TMPD/console.log"

# Real stdout/stderr are saved on fd 3/4 so they can be restored before the
# summary's console-transcript section is appended, and before the archive
# is built (otherwise the tarball would contain a truncated copy of its own
# transcript).
exec 3>&1 4>&2
exec > >(tee -a "$CONSOLE_LOG") 2>&1

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

# attrs k v [k v ...]  -> "k=v; k=v; ..." (empty values dropped; ";" and
# newlines sanitized out of v so the pairs stay unambiguous when split on
# "; " and then on the FIRST "=")
attrs() {
  local out="" k v
  while [ "$#" -ge 2 ]; do
    k=$1; v=$2; shift 2
    [ -n "$v" ] || continue
    v=${v//;/,}
    v=${v//$'\n'/ }
    v=${v//$'\r'/}
    out="${out}${k}=${v}; "
  done
  printf '%s' "${out% }"
}

# row RECORDTYPE NAME VERSION ORIGIN PATH FLAGGED ATTRIBUTES  -> appends one
# data row to the consolidated CSV. The 21-field system-identity block is
# left blank here; only the RecordType=SystemInfo row (emitted directly,
# not through this function) populates it.
row() {
  csv "$1" "$HOSTNAME_S" "${START_UTC}Z" "$REFERENCE" "$COLLECTOR" "$IS_ROOT" \
      "" "" "" "" "" "" "" "" "" "" "" "" "" "" "" "" "" "" "" "" "" \
      "${2:-}" "${3:-}" "${4:-}" "${5:-}" "${6:-}" "${7:-}" >> "$CSV_FILE"
}

# note a RecordType's row count in the console (folded into the summary
# transcript later); counts are read back from the CSV itself so nothing
# needs to be tallied by hand in a subshell-unsafe loop.
count_rt() { LC_ALL=C grep -c "^\"$1\"," "$CSV_FILE" 2>/dev/null; }
report_rt() {
  local n; n=$(count_rt "$1")
  [ -n "$n" ] || n=0
  printf '  %-32s %6s record(s)\n' "${2:-$1}" "$n"
}

step() { echo; echo "[ $* ]"; }

have() { command -v "$1" >/dev/null 2>&1; }

# is_var_assignment LINE -> true if LINE looks like "NAME=..." (a crontab
# environment assignment such as PATH= or MAILTO=, to be skipped rather than
# parsed as a command). Written with plain glob/case matching, not bash's
# "[[ =~ ]]" regex operator, because that operator needs bash 3.0+ and RHEL
# AS 2.1 ships bash 2.05b.
is_var_assignment() {
  local l="$1" lhs
  lhs=${l%%=*}
  [ "$lhs" != "$l" ] || return 1      # no "=" in the line at all
  case "$lhs" in
    ''|[0-9]*)      return 1 ;;       # empty or starts with a digit
    *[!A-Za-z0-9_]*) return 1 ;;      # contains something not ident-safe
    *)               return 0 ;;
  esac
}

# ------------------------------------------------------------- preflight ---

echo "================================================================"
echo " SOFTWARE INVENTORY EVIDENCE COLLECTION"
echo "================================================================"
echo " Host        : $HOSTNAME_S"
echo " Collector   : $COLLECTOR"
echo " Reference   : ${REFERENCE:-(none)}"
echo " Started     : $START_LOCAL local / ${START_UTC}Z"
echo " Running as  : $(id -un) (uid $(id -u))"
echo " Output      : $CSV_FILE"
echo "               $SUMMARY_FILE"
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

# bash 4.0 (2009) introduced associative arrays. RHEL AS 2.1 (bash 2.05b)
# and RHEL 4 (bash 3.0) predate it; CentOS 6.10 onward (bash 4.1+) has it.
BASH_MAJOR=${BASH_VERSINFO[0]:-0}
HAVE_ASSOC=0
[ "$BASH_MAJOR" -ge 4 ] && HAVE_ASSOC=1

HAVE_STAT=1
have stat || { HAVE_STAT=0; warn "'stat' command not found - file metadata (size/owner/mode/modified) will be blank for unowned executables and setuid files."; }

# ------------------------------------------- 1. system identification -----

step "System identification"

REDHAT_RELEASE=$(cat /etc/redhat-release 2>/dev/null)
if [ -z "${REDHAT_RELEASE:-}" ] && [ -r /etc/os-release ]; then
  REDHAT_RELEASE=$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-}")
fi
[ -n "${REDHAT_RELEASE:-}" ] || REDHAT_RELEASE="unknown"

# Prefer the explicit "release N[.N...]" token in /etc/redhat-release - this
# is the one representation that has been stable from RHEL AS 2.1's
# "release 2.1AS" through RHEL 8's "release 8.6" without ever depending on a
# decimal point being present (RHEL 4's "release 4" has none, which is why
# the older grep-for-N.N pattern alone was not enough).
OSVERSION=$(echo "$REDHAT_RELEASE" | grep -oE 'release[[:space:]]+[0-9]+(\.[0-9]+)*' | grep -oE '[0-9]+(\.[0-9]+)*' | head -1)
if [ -z "${OSVERSION:-}" ] && [ -r /etc/os-release ]; then
  OSVERSION=$(. /etc/os-release 2>/dev/null; echo "${VERSION_ID:-}")
fi
if [ -z "${OSVERSION:-}" ]; then
  OSVERSION=$(echo "$REDHAT_RELEASE" | grep -oE '[0-9]+\.[0-9.]*[0-9]' | head -1)
fi
[ -n "${OSVERSION:-}" ] || OSVERSION=$(sed -n 's/.*[Ee][Ll]\([0-9]\+\).*/\1/p' <<< "$(uname -r)")
OSMAJOR=${OSVERSION%%.*}

case "$OSMAJOR" in
  2|4|6|7|8) : ;;
  *)
    echo "FATAL: this script targets RHEL/CentOS releases 2.1, 4, 6.x, 7.x, and 8.x." >&2
    echo "       Detected: ${REDHAT_RELEASE} (major '${OSMAJOR:-unknown}')" >&2
    echo "       Refusing to run rather than produce a partial inventory." >&2
    exec 1>&3 2>&4                      # stop teeing before exiting
    exit 1 ;;
esac

# Named targets are 2.1, 4(.x), 6.10, 7.5, 7.8, and 8(.x); anything else in
# the same major-version family still runs on that family's code path, but
# the deviation is recorded in the evidence rather than passing silently.
OS_IS_TARGET="yes"
TARGET_LABEL=""
case "$OSMAJOR" in
  2)
    case "$OSVERSION" in
      2.1) TARGET_LABEL="RHEL Advanced Server 2.1" ;;
      *) OS_IS_TARGET="no"; TARGET_LABEL="RHEL 2.x (untested minor release)" ;;
    esac ;;
  4)
    TARGET_LABEL="RHEL 4"
    case "$OSVERSION" in 4|4.*) : ;; *) OS_IS_TARGET="no" ;; esac ;;
  6)
    case "$OSVERSION" in
      6.10) TARGET_LABEL="CentOS/RHEL 6.10" ;;
      *) OS_IS_TARGET="no"; TARGET_LABEL="RHEL/CentOS 6.x (untested minor release)" ;;
    esac ;;
  7)
    case "$OSVERSION" in
      7.5|7.5.*) TARGET_LABEL="CentOS/RHEL 7.5" ;;
      7.8|7.8.*) TARGET_LABEL="RHEL 7.8" ;;
      *) OS_IS_TARGET="no"; TARGET_LABEL="RHEL/CentOS 7.x (untested minor release)" ;;
    esac ;;
  8)
    TARGET_LABEL="RHEL 8"
    case "$OSVERSION" in 8|8.*) : ;; *) OS_IS_TARGET="no" ;; esac ;;
esac
if [ "$OS_IS_TARGET" = "no" ]; then
  warn "Release ${OSVERSION} is not a named target (2.1 / 4 / 6.10 / 7.5 / 7.8 / 8); collection proceeded on the ${OSMAJOR}.x code path (${TARGET_LABEL})."
fi

# The major version decides the init system rather than probing for a
# systemctl binary, so a stray or leftover binary can't misroute the whole
# services/timers collection.
case "$OSMAJOR" in
  2|4|6)
    INIT_SYS="sysv"
    have chkconfig || warn "chkconfig not found - service enumeration will be thin." ;;
  7|8)
    INIT_SYS="systemd"
    have systemctl || warn "systemctl not found on a systemd-era host - service enumeration will be thin." ;;
esac

if [ "$HAVE_ASSOC" -eq 0 ]; then
  warn "bash ${BASH_VERSION:-<4} predates associative arrays - package repository origin (FromRepo) will be blank on this host."
fi

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
[ -n "${SYS_SERIAL:-}" ] || SYS_SERIAL="(unreadable - needs root/dmidecode, or predates /sys on this kernel)"

CPU_MODEL=$(awk -F': ' '/^model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null)
CPU_COUNT=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)
MEM_TOTAL_MB=$(awk '/^MemTotal:/{printf "%.0f", $2/1024}' /proc/meminfo 2>/dev/null)
ROOT_USE=$(df -Pk / 2>/dev/null | awk 'NR==2{print $5" used of "$2" KB"}')

SELINUX_STATE=$(getenforce 2>/dev/null || echo "n/a")
MACHINE_ID=$(cat /etc/machine-id 2>/dev/null || cat /var/lib/dbus/machine-id 2>/dev/null || echo "")
# install date: the filesystem package is laid down first on a fresh install
OS_INSTALLED=$(rpm -q --qf '%{INSTALLTIME:date}\n' basesystem 2>/dev/null | head -1)
[ -n "${OS_INSTALLED:-}" ] || OS_INSTALLED=$(rpm -q --qf '%{INSTALLTIME:date}\n' filesystem 2>/dev/null | head -1)

# Header row, then the one SystemInfo row for this host. Every column here
# lines up 1:1 with the fixed layout row() uses for every other RecordType
# (see the "OUTPUT FORMAT" block in the header comment).
csv RecordType ComputerName Collected Reference Collector RanAsRoot \
    Vendor Model Serial BiosVersion OSRelease OSVersion NamedTarget \
    KernelRelease KernelVersion Architecture InitSystem CPUModel CPUCount \
    TotalMemoryMB RootFilesystem SELinux MachineID OSInstalled Uptime \
    RPMVersion BashVersion \
    Name Version Origin Path Flagged Attributes > "$CSV_FILE"

csv "SystemInfo" "$HOSTNAME_S" "${START_UTC}Z" "$REFERENCE" "$COLLECTOR" "$IS_ROOT" \
    "${SYS_VENDOR:-}" "${SYS_MODEL:-}" "${SYS_SERIAL:-}" "${BIOS_VER:-}" \
    "$REDHAT_RELEASE" "$OSVERSION" "$OS_IS_TARGET" \
    "$(uname -r)" "$(uname -v)" "$(uname -m)" "$INIT_SYS" \
    "${CPU_MODEL:-}" "${CPU_COUNT:-}" "${MEM_TOTAL_MB:-}" "${ROOT_USE:-}" \
    "$SELINUX_STATE" "$MACHINE_ID" "${OS_INSTALLED:-}" \
    "$(uptime 2>/dev/null | sed 's/^ *//')" \
    "$(rpm --version 2>/dev/null | awk '{print $NF}')" "${BASH_VERSION:-}" \
    "$HOSTNAME_S" "$OSVERSION" "$TARGET_LABEL" "" "" "" >> "$CSV_FILE"

echo "  OS          : $REDHAT_RELEASE  [${OSVERSION}]  ($TARGET_LABEL)"
echo "  Kernel      : $(uname -r) ($(uname -m))"
echo "  Init system : $INIT_SYS"
report_rt SystemInfo

# ----------------------------------------------- 2. installed packages ----

step "Installed packages (RPM database)"

# from_repo lookup: on 6.x/7.x, out of the yum database, so each package
# carries the repository it was installed from - on an isolated host
# anything not from a local/approved repo is worth a look. On RHEL 8, yumdb
# doesn't exist (dnf keeps its own history store instead), so the same
# lookup is done through "dnf repoquery" against the local rpm database
# only (-C: cache-only, no network/metadata refresh). On hosts predating
# both (2.1, 4) or without bash associative arrays, this is skipped and
# FromRepo is left blank - already warned above.
if [ "$HAVE_ASSOC" -eq 1 ]; then
  declare -A REPO_OF
  if [ -d /var/lib/yum/yumdb ]; then
    while IFS= read -r d; do
      [ -f "$d/from_repo" ] || continue
      b=$(basename "$d")
      rest=${b#*-}                 # strip leading pkgid checksum
      arch=${rest##*-}
      nvr=${rest%-*}
      REPO_OF["${nvr}.${arch}"]=$(cat "$d/from_repo" 2>/dev/null)
    done < <(find /var/lib/yum/yumdb -mindepth 2 -maxdepth 2 -type d 2>/dev/null)
  elif have dnf; then
    while IFS=$'\t' read -r nvra reponame; do
      [ -n "${nvra:-}" ] || continue
      REPO_OF["$nvra"]="$reponame"
    done < <(dnf -C -q repoquery --installed --qf '%{name}-%{version}-%{release}.%{arch}\t%{reponame}' 2>/dev/null)
    [ "${#REPO_OF[@]}" -gt 0 ] || warn "'dnf repoquery' returned no repository data - FromRepo will be blank."
  else
    warn "Neither /var/lib/yum/yumdb nor dnf present - package repository origin unavailable."
  fi
fi

# The %|TAG?{...}:{...}| conditional picks whichever signature tag is
# populated; a package showing (none) is unsigned - a finding, not a
# formatting artifact. That conditional syntax is probed once: rpm 4.0.x
# (RHEL AS 2.1) may not support it, in which case Signed reports UNCHECKED
# rather than a guessed value.
RPMFMT_FULL='%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{VENDOR}\t%{INSTALLTIME:date}\t%{BUILDTIME:date}\t%{SIZE}\t%{GROUP}\t%{LICENSE}\t%{SOURCERPM}\t%{BUILDHOST}\t%|DSAHEADER?{%{DSAHEADER:pgpsig}}:{%|RSAHEADER?{%{RSAHEADER:pgpsig}}:{%|SIGGPG?{%{SIGGPG:pgpsig}}:{%|SIGPGP?{%{SIGPGP:pgpsig}}:{(none)}|}|}|}|\t%{SUMMARY}\n'
RPMFMT_BASIC='%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{VENDOR}\t%{INSTALLTIME:date}\t%{BUILDTIME:date}\t%{SIZE}\t%{GROUP}\t%{LICENSE}\t%{SOURCERPM}\t%{BUILDHOST}\t(unchecked)\t%{SUMMARY}\n'
RPMFMT="$RPMFMT_FULL"
if ! rpm -q rpm --qf "$RPMFMT_FULL" >/dev/null 2>&1; then
  RPMFMT="$RPMFMT_BASIC"
  warn "This rpm version does not support the GPG-signature queryformat conditional - Signed reports UNCHECKED rather than a verified yes/no. Run 'rpm -K *.rpm' separately if per-package signature status is required."
fi

{
  # Tabs are IFS whitespace: bash collapses runs of them, so an empty field
  # (no vendor, no repo) would silently shift every column after it. Translate
  # to US (\037), a non-whitespace delimiter that preserves empty fields.
  rpm -qa --qf "$RPMFMT" 2>/dev/null | tr '\t' '\037' | LC_ALL=C sort -f |
  while IFS=$'\037' read -r name epoch ver rel arch vendor itime btime size grp lic srpm bhost sig summ; do
    [ -n "${name:-}" ] || continue
    [ "$epoch" = "(none)" ] && epoch=""
    nvra="${name}-${ver}-${rel}.${arch}"
    signed="yes"
    case "$sig" in
      ""|"(none)"|"None") signed="NO" ;;
      "(unchecked)")       signed="UNCHECKED" ;;
    esac
    repo=""
    [ "$HAVE_ASSOC" -eq 1 ] && repo="${REPO_OF[$nvra]:-}"
    # Side file in US-delimited form, reused by the baseline-deviation step
    # below without re-parsing the CSV (free-text fields can legitimately
    # contain the sequence '","' and would shift columns in a naive splitter).
    printf '%s\037%s\037%s\037%s\037%s\n' \
        "$name" "${ver}-${rel}" "$vendor" "$repo" "$signed" >> "$TMPD/pkgs.dat"
    fl=""
    case "$signed" in
      NO) fl="UNSIGNED PACKAGE" ;;
      UNCHECKED) fl="SIGNATURE NOT VERIFIED (legacy rpm)" ;;
    esac
    row "Package" "$name" "${ver}-${rel}.${arch}" "$repo" "$srpm" "$fl" \
      "$(attrs Epoch "$epoch" Vendor "$vendor" InstallTime "$itime" BuildTime "$btime" \
               SizeBytes "$size" Group "$grp" License "$lic" BuildHost "$bhost" \
               Signature "$sig" Signed "$signed" Summary "$summ")"
  done
}

report_rt Package "Installed packages"
PKG_COUNT=$(count_rt Package)
UNSIGNED_COUNT=$(awk -F'\037' '$5=="NO"' "$TMPD/pkgs.dat" 2>/dev/null | wc -l)
UNCHECKED_COUNT=$(awk -F'\037' '$5=="UNCHECKED"' "$TMPD/pkgs.dat" 2>/dev/null | wc -l)
echo "  -> $UNSIGNED_COUNT package(s) with no GPG signature"
[ "$UNCHECKED_COUNT" -gt 0 ] && echo "  -> $UNCHECKED_COUNT package(s) with unchecked signature (legacy rpm)"

# ------------------------------------ 3. software outside package mgmt ----

step "Software installed outside RPM (language package managers)"

for py in pip pip2 pip3; do
  if have "$py"; then
    loc=$(command -v "$py")
    # NB: braces matter - without them the || binds tighter than the pipe
    # and a successful "pip list" would bypass the parser entirely.
    { "$py" list --format=freeze 2>/dev/null || "$py" freeze 2>/dev/null; } |
      while IFS= read -r line; do
        case "$line" in
          *"=="*) row "NonRpmPackage" "${line%%==*}" "${line##*==}" "$py" "$loc" "" "" ;;
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
        row "NonRpmPackage" "$gname" "$gver" "gem" "$loc" "" "" ;;
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
            *"@"*) row "NonRpmPackage" "${pkg%@*}" "${pkg##*@}" "npm-global" "$loc" "" "" ;;
          esac ;;
      esac
    done
fi

report_rt NonRpmPackage "Software outside RPM"

# ------------------------------------ 4. executables owned by no package -----

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
    # "-perm /111" needs findutils 4.3.3+ and the older "-perm +111" spelling
    # was later removed - neither is safe across RHEL AS 2.1 through RHEL 8.
    # "-perm -100 -o -perm -010 -o -perm -001" (any execute bit set, tried
    # three ways) has worked in every findutils release.
    find "${EXIST[@]}" -xdev -type f \( -perm -100 -o -perm -010 -o -perm -001 \) 2>/dev/null |
      LC_ALL=C sort -u > "$TMPD/found.txt"
  fi
  echo "  executable files found: $(wc -l < "$TMPD/found.txt")"

  LC_ALL=C comm -23 "$TMPD/found.txt" "$TMPD/owned.txt" > "$TMPD/unowned.txt"

  while IFS= read -r f; do
    [ -e "$f" ] || continue
    sz=""; mt=""; ow=""; gr=""; md=""
    if [ "$HAVE_STAT" -eq 1 ]; then
      info=$(stat -c '%s|%y|%U|%G|%a' "$f" 2>/dev/null) || continue
      sz=${info%%|*};       rest=${info#*|}
      mt=${rest%%|*};       rest=${rest#*|}
      ow=${rest%%|*};       rest=${rest#*|}
      gr=${rest%%|*};       md=${rest##*|}
      mt=${mt%%.*}
    fi
    suid="no"
    [ -u "$f" ] && suid="SETUID"
    [ -g "$f" ] && suid="${suid},SETGID"
    ftype=""
    have file && ftype=$(file -b "$f" 2>/dev/null | cut -c1-120)
    fl=""
    case "$suid" in SETUID*) fl="$suid" ;; esac
    row "UnownedExecutable" "$(basename "$f")" "" "unpackaged" "$f" "$fl" \
      "$(attrs SizeBytes "$sz" Modified "$mt" Owner "$ow" Group "$gr" Mode "$md" FileType "$ftype")"
  done < "$TMPD/unowned.txt"

  report_rt UnownedExecutable
else
  warn "Unowned-executable scan skipped by option -S."
fi

# ------------------------------------------ 5. rpm -Va verification -------

if [ "$DO_VERIFY" -eq 1 ]; then
  step "RPM package verification (rpm -Va)"
  echo "  This compares every packaged file against the RPM database."
  echo "  Expect 10-40 minutes. Config-file differences are normal."
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
    row "PackageVerification" "" "" "" "$rest" "" \
      "$(attrs Flags "$flags" FileType "$ftype" SizeDiff "$sd" ModeDiff "$md" MD5Diff "$m5" \
               MtimeDiff "$mt" OwnerDiff "$od" GroupDiff "$gd" \
               ConfigFile "$([ "$ftype" = "config" ] && echo yes || echo no)")"
  done
  report_rt PackageVerification
fi

# ------------------------------------------------------- 6. services -----

step "Services"

if [ "$INIT_SYS" = "systemd" ]; then
  systemctl list-units --type=service --all --no-legend --no-pager 2>/dev/null |
    sed 's/^[[:space:]]*●[[:space:]]*//' |
    while read -r unit load active sub rest; do
      [ -n "${unit:-}" ] || continue
      case "$unit" in *.service) ;; *) continue ;; esac
      en=$(systemctl is-enabled "$unit" 2>/dev/null || echo "unknown")
      row "Service" "$unit" "" "systemd" "" "" "$(attrs State "$active/$sub" Enablement "$en" Detail "$load ${rest:-}")"
    done
else
  chkconfig --list 2>/dev/null | while IFS= read -r line; do
    case "$line" in
      *"0:"*)
        svc=$(echo "$line" | awk '{print $1}')
        lv=$(echo "$line" | sed 's/^[^ \t]*[ \t]*//')
        st="stopped"
        service "$svc" status >/dev/null 2>&1 && st="running"
        row "Service" "$svc" "" "sysv" "" "" "$(attrs State "$st" Enablement "$lv")" ;;
    esac
  done
  for f in /etc/init/*.conf; do
    [ -e "$f" ] || continue
    row "Service" "$(basename "$f" .conf)" "" "upstart" "$f" "" "$(attrs State "n/a")"
  done
fi

report_rt Service

# ------------------------------------------- 7. cron and scheduled work ---

step "Scheduled tasks (cron, timers)"

for f in /etc/crontab /etc/cron.d/*; do
  [ -f "$f" ] || continue
  while IFS= read -r line; do
    case "$line" in ''|\#*) continue ;; esac
    # skip environment assignments (PATH=, MAILTO=), not commands containing "="
    is_var_assignment "$line" && continue
    # /etc/crontab and /etc/cron.d have a user field at position 6
    owner=$(echo "$line" | awk '{print $6}')
    sched=$(echo "$line" | awk '{print $1,$2,$3,$4,$5}')
    cmd=$(echo "$line" | awk '{for(i=7;i<=NF;i++) printf "%s ", $i}')
    row "ScheduledTask" "$cmd" "" "$f" "$f" "" "$(attrs Owner "$owner" Schedule "$sched")"
  done < "$f"
done

for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
  [ -d "$d" ] || continue
  for f in "$d"/*; do
    [ -f "$f" ] || continue
    row "ScheduledTask" "$(basename "$f")" "" "$d" "$f" "" "$(attrs Owner root Schedule "$(basename "$d")")"
  done
done

if [ "$IS_ROOT" -eq 1 ]; then
  for cf in /var/spool/cron/*; do
    [ -f "$cf" ] || continue
    u=$(basename "$cf")
    while IFS= read -r line; do
      case "$line" in ''|\#*) continue ;; esac
      is_var_assignment "$line" && continue
      # user crontabs have no user field - command starts at position 6
      sched=$(echo "$line" | awk '{print $1,$2,$3,$4,$5}')
      cmd=$(echo "$line" | awk '{for(i=6;i<=NF;i++) printf "%s ", $i}')
      row "ScheduledTask" "$cmd" "" "user-crontab" "$cf" "" "$(attrs Owner "$u" Schedule "$sched")"
    done < "$cf"
  done
else
  echo " - Per-user crontabs not read (requires root)." >> "$WARNINGS"
fi

if [ "$INIT_SYS" = "systemd" ]; then
  # list-timers has multi-word date columns that defeat positional parsing;
  # list-unit-files is two clean fields and works from systemd 219 (RHEL 7) on.
  systemctl list-unit-files --type=timer --no-legend --no-pager 2>/dev/null |
    while read -r unit state _rest; do
      [ -n "${unit:-}" ] || continue
      act=$(systemctl show -p Unit "$unit" 2>/dev/null | cut -d= -f2)
      row "ScheduledTask" "$unit" "" "systemd-timer" "" "" "$(attrs Owner system Schedule "${state:-unknown}" Target "${act:-}")"
    done
fi

report_rt ScheduledTask

# -------------------------------------------------- 8. kernel modules ----

step "Kernel modules"

if have lsmod; then
  lsmod 2>/dev/null | tail -n +2 | while read -r m sz used rest; do
    ver=""; sgn=""; pth=""
    if have modinfo; then
      pth=$(modinfo -n "$m" 2>/dev/null)
      ver=$(modinfo -F version "$m" 2>/dev/null | head -1)
      sgn=$(modinfo -F signer  "$m" 2>/dev/null | head -1)
    fi
    row "KernelModule" "$m" "$ver" "" "$pth" "" "$(attrs SizeBytes "$sz" UsedBy "${rest:-}" Signed "$sgn")"
  done
fi

report_rt KernelModule

# ----------------------------------------- 9. update history and repos ---

step "Update history and configured repositories"

# /var/log/yum.log exists on 6.x/7.x and needs no yum invocation. RHEL 8's
# dnf keeps history in a sqlite database instead of a flat log; that history
# is readable offline via "dnf history" without contacting any repo.
for lf in /var/log/yum.log /var/log/yum.log-*; do
  [ -f "$lf" ] || continue
  while IFS= read -r line; do
    d=$(echo "$line" | awk '{print $1,$2,$3}')
    a=$(echo "$line" | awk '{print $4}')
    p=$(echo "$line" | awk '{print $5}')
    [ -n "${p:-}" ] || continue
    row "UpdateHistory" "$p" "" "$lf" "$lf" "" "$(attrs Date "$d" Action "${a%:}")"
  done < "$lf"
done

if have dnf; then
  dnf -C -q history list 2>/dev/null | tail -n +3 | while IFS='|' read -r hid cmdline daterun actions rest; do
    hid=$(echo "${hid:-}" | tr -d ' ')
    [ -n "$hid" ] && [ "$hid" != "ID" ] || continue
    row "UpdateHistory" "$(echo "${cmdline:-}" | sed 's/^ *//;s/ *$//')" "" "dnf history" "" "" \
      "$(attrs Date "$(echo "${daterun:-}" | sed 's/^ *//;s/ *$//')" Action "$(echo "${actions:-}" | sed 's/^ *//;s/ *$//')" HistoryID "$hid")"
  done
fi

if [ -f /var/log/up2date ]; then
  warn "/var/log/up2date is present (pre-yum update history) but its format is not machine-parsed here - review it manually if update history predating yum/dnf matters for this host."
fi

report_rt UpdateHistory

for rf in /etc/yum.repos.d/*.repo; do
  [ -f "$rf" ] || continue
  rid=""; en=""; url=""
  while IFS= read -r line; do
    case "$line" in
      \[*\])
        [ -n "$rid" ] && row "Repository" "$rid" "" "" "$rf" "$en" "$(attrs BaseURL "$url")"
        rid=${line#[}; rid=${rid%]}; en=""; url="" ;;
      enabled=*)  en=${line#enabled=} ;;
      baseurl=*)  url=${line#baseurl=} ;;
      mirrorlist=*) [ -n "$url" ] || url=${line#mirrorlist=} ;;
    esac
  done < "$rf"
  [ -n "$rid" ] && row "Repository" "$rid" "" "" "$rf" "$en" "$(attrs BaseURL "$url")"
done

report_rt Repository

# --------------------------------------------------- 10. local accounts --

step "Local accounts"

while IFS=: read -r u _ uid gid _ home shell; do
  [ -n "${u:-}" ] || continue
  lc="yes"
  case "$shell" in */nologin|*/false|""|*/sync|*/shutdown|*/halt) lc="no" ;; esac
  row "LocalAccount" "$u" "" "" "$home" "" "$(attrs UID "$uid" GID "$gid" Shell "$shell" LoginCapable "$lc")"
done < /etc/passwd

report_rt LocalAccount

# ---------------------------- 10b. running processes and network exposure --

step "Running processes"

# Software that is actually executing, resolved back to its owning package
# where one exists. A long-running process from an unowned binary is the
# strongest signal that something is installed outside package management.
# "ps -o lstart=" needs a procps new enough to support it; probe once so a
# host too old for it (plausible on RHEL AS 2.1) degrades to no start-time
# column instead of every row silently failing to parse.
PS_HAS_LSTART=1
ps -eo lstart= >/dev/null 2>&1 || PS_HAS_LSTART=0

if [ "$PS_HAS_LSTART" -eq 1 ]; then
  ps -eo user=,pid=,ppid=,lstart=,args= 2>/dev/null |
  while read -r usr pid ppid lw lmo ld ltm lyr args; do
    [ -n "${pid:-}" ] || continue
    started="$lw $lmo $ld $ltm $lyr"
    exe=""
    [ -r "/proc/$pid/exe" ] && exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
    [ -n "$exe" ] || exe=$(echo "$args" | awk '{print $1}')
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
    row "Process" "$args" "" "" "$exe" "" "$(attrs User "$usr" PID "$pid" PPID "$ppid" StartTime "$started" OwningPackage "$pkg")"
  done
else
  warn "'ps -o lstart=' not supported by this host's ps - process start time will be blank."
  ps -eo user=,pid=,ppid=,etime=,args= 2>/dev/null |
  while read -r usr pid ppid etm args; do
    [ -n "${pid:-}" ] || continue
    exe=""
    [ -r "/proc/$pid/exe" ] && exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
    [ -n "$exe" ] || exe=$(echo "$args" | awk '{print $1}')
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
    row "Process" "$args" "" "" "$exe" "" "$(attrs User "$usr" PID "$pid" PPID "$ppid" Elapsed "$etm" OwningPackage "$pkg")"
  done
fi

report_rt Process

step "Listening network services"

# What is exposed, and which program is behind it. ss on 7/8, netstat on
# 2.1/4/6 (ss may be present but is not assumed).
if have ss; then
  # columns: Netid State Recv-Q Send-Q Local:Port Peer:Port Process
  ss -tulpn 2>/dev/null | tail -n +2 |
  while read -r proto state _recvq _sendq local peer procinfo; do
    [ -n "${local:-}" ] || continue
    port=${local##*:}
    addr=${local%:*}
    row "ListeningService" "${procinfo:-}" "" "$proto" "" "" "$(attrs LocalAddress "$addr" LocalPort "$port" State "${state:-listen}")"
  done
elif have netstat; then
  netstat -tulpn 2>/dev/null | grep -iE '^(tcp|udp)' |
  while read -r proto _ _ local peer state procinfo; do
    [ -n "${local:-}" ] || continue
    case "$proto" in udp*) procinfo="$state"; state="listen" ;; esac
    port=${local##*:}
    addr=${local%:*}
    row "ListeningService" "${procinfo:-}" "" "$proto" "" "" "$(attrs LocalAddress "$addr" LocalPort "$port" State "$state")"
  done
else
  warn "Neither ss nor netstat present - listening services not enumerated."
fi

report_rt ListeningService

# ------------------------------------------- 10c. inetd / xinetd services --

step "inetd / xinetd managed services"

# On sysv-era hosts (2.1, 4, 6) these are real services that never appear in
# chkconfig --list output as running daemons; they are started on demand and
# are easy to miss. RHEL AS 2.1 in particular relies on inetd/xinetd for a
# meaningful share of its network-facing services.
if [ -f /etc/inetd.conf ]; then
  while IFS= read -r line; do
    case "$line" in ''|\#*) continue ;; esac
    svc=$(echo "$line" | awk '{print $1}')
    srv=$(echo "$line" | awk '{print $7}')
    row "InetdService" "$svc" "" "/etc/inetd.conf" "$srv" "no" "$(attrs Detail "$line")"
  done < /etc/inetd.conf
fi
for xf in /etc/xinetd.d/*; do
  [ -f "$xf" ] || continue
  svc=$(basename "$xf")
  dis=$(grep -iE '^[[:space:]]*disable' "$xf" 2>/dev/null | head -1 | awk -F= '{gsub(/ /,"",$2); print $2}')
  srv=$(grep -iE '^[[:space:]]*server[[:space:]]*=' "$xf" 2>/dev/null | head -1 | awk -F= '{gsub(/^ +| +$/,"",$2); print $2}')
  row "InetdService" "$svc" "" "/etc/xinetd.d" "${srv:-$xf}" "${dis:-unset}" "$(attrs SourceFile "$xf")"
done

report_rt InetdService

# ------------------------------------------------ 10d. setuid/setgid files --

if [ "$DO_SCAN" -eq 1 ]; then
  step "Setuid / setgid files (system-wide)"

  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | LC_ALL=C sort |
  while IFS= read -r f; do
    md=""; ow=""; gr=""; sz=""; mt=""
    if [ "$HAVE_STAT" -eq 1 ]; then
      info=$(stat -c '%a|%U|%G|%s|%y' "$f" 2>/dev/null) || continue
      md=${info%%|*};  rest=${info#*|}
      ow=${rest%%|*};  rest=${rest#*|}
      gr=${rest%%|*};  rest=${rest#*|}
      sz=${rest%%|*};  mt=${rest##*|}
      mt=${mt%%.*}
    fi
    typ=""
    [ -u "$f" ] && typ="setuid"
    [ -g "$f" ] && typ="${typ:+$typ,}setgid"
    pkg=$(rpm -qf --qf '%{NAME}' "$f" 2>/dev/null)
    case "$pkg" in *"not owned"*|*"no package"*|'') pkg="(no package)" ;; esac
    row "SetuidFile" "$(basename "$f")" "" "" "$f" "$typ" \
      "$(attrs Mode "$md" Owner "$ow" Group "$gr" SizeBytes "$sz" Modified "$mt" OwningPackage "$pkg")"
  done

  report_rt SetuidFile
else
  warn "Setuid/setgid file scan skipped by option -S."
fi

# ------------------------------------------------- 10e. version marker files --

if [ "$DO_SCAN" -eq 1 ]; then
  step "Version marker files in local software trees"

  # Locally installed software (AWIPS and friends) usually has no package
  # metadata at all - a VERSION file on disk is often the only version
  # record that exists for it.
  OLDIFS=$IFS; IFS=':'; read -ra VPATHS <<< "$SCAN_PATHS"; IFS=$OLDIFS
  VEXIST=()
  for vp in "${VPATHS[@]}"; do [ -d "$vp" ] && VEXIST+=("$vp"); done
  if [ ${#VEXIST[@]} -gt 0 ]; then
    find "${VEXIST[@]}" -xdev -maxdepth 6 -type f \
         \( -iname '*version*' -o -iname '*release*' -o -iname 'VERSION' \) \
         -size -64k 2>/dev/null | LC_ALL=C sort | head -500 |
    while IFS= read -r vf; do
      sz=""; mt=""
      if [ "$HAVE_STAT" -eq 1 ]; then
        sz=$(stat -c '%s' "$vf" 2>/dev/null) || continue
        mt=$(stat -c '%y' "$vf" 2>/dev/null); mt=${mt%%.*}
      fi
      body=$(head -c 200 "$vf" 2>/dev/null | tr '\n\r\t' '   ')
      row "VersionFile" "$(basename "$(dirname "$vf")")" "" "local install" "$vf" "" \
        "$(attrs SizeBytes "$sz" Modified "$mt" Contents "$body")"
    done
  fi

  report_rt VersionFile
fi

# ------------------------------------------------ 10f. mounted filesystems --

step "Mounted filesystems"

# Recorded because every scan in this script uses -xdev: it does not cross
# mount points. This is what tells a reviewer which filesystems were in
# scope and which were not.
while read -r dev mnt fstype opts _rest; do
  [ -n "${mnt:-}" ] || continue
  scanned="not scanned (-xdev)"
  [ "$mnt" = "/" ] && scanned="scanned"
  case ":$SCAN_PATHS:" in *":$mnt:"*) scanned="scanned (scan root)" ;; esac
  case "$fstype" in proc|sysfs|devpts|tmpfs|devtmpfs|cgroup|securityfs|debugfs|rpc_pipefs|hugetlbfs|mqueue|selinuxfs|pstore|configfs|autofs|binfmt_misc) scanned="pseudo-fs" ;; esac
  row "Mount" "$mnt" "" "" "$dev" "" "$(attrs FSType "$fstype" Options "$opts" Scanned "$scanned")"
done < /proc/mounts

report_rt Mount

# ------------------------------------------------- 11. baseline compare --

DEV_COUNT=0
if [ -n "$BASELINE" ]; then
  step "Baseline comparison"
  if [ ! -f "$BASELINE" ]; then
    warn "Baseline file not found: $BASELINE"
  else
    # accept a bare list or a CSV whose first column is the package name
    sed -e 's/\r$//' -e 's/^"//' -e 's/".*$//' -e 's/,.*$//' "$BASELINE" 2>/dev/null |
      grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$' |
      LC_ALL=C sort -u -f > "$TMPD/baseline.txt"
    echo "  baseline entries: $(wc -l < "$TMPD/baseline.txt")"

    while IFS=$'\037' read -r nm vr vd rp _sg; do
      if ! LC_ALL=C grep -qix -- "$nm" "$TMPD/baseline.txt" 2>/dev/null; then
        row "Deviation" "$nm" "$vr" "$rp" "" "" "$(attrs Vendor "$vd" Finding "Not present on approved software baseline")"
      fi
    done < "$TMPD/pkgs.dat"

    DEV_COUNT=$(count_rt Deviation)
    report_rt Deviation
    echo "  $DEV_COUNT package(s) not matched to the baseline"
  fi
fi

# ------------------------------------------------- 12. summary -----------

step "Summary"

END_LOCAL=$(date '+%Y-%m-%d %H:%M:%S')
ELAPSED=$(( $(date '+%s') - START_EPOCH ))
NONRPM_COUNT=$(count_rt NonRpmPackage)
UNOWNED_COUNT=$(count_rt UnownedExecutable)
SETUID_COUNT=$(grep "^\"UnownedExecutable\"," "$CSV_FILE" 2>/dev/null | grep -c 'SETUID')
PROC_COUNT=$(count_rt Process)
PROC_UNPKG=$(grep "^\"Process\"," "$CSV_FILE" 2>/dev/null | grep -c '(no package)')
SETUIDFILE_COUNT=$(count_rt SetuidFile)
SETUIDFILE_UNPKG=$(grep "^\"SetuidFile\"," "$CSV_FILE" 2>/dev/null | grep -c '(no package)')

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
  echo "Release / target   : ${OSVERSION} (${TARGET_LABEL}; named target: $OS_IS_TARGET)"
  echo "Kernel             : $(uname -r) ($(uname -m))"
  echo "Init system        : $INIT_SYS"
  echo "SELinux            : $SELINUX_STATE"
  echo "OS install date    : ${OS_INSTALLED:-unknown}"
  echo
  echo "Collection started : $START_LOCAL local / ${START_UTC}Z"
  echo "Collection ended   : $END_LOCAL local"
  echo "Duration           : $((ELAPSED / 60))m $((ELAPSED % 60))s"
  echo "Ran as root        : $([ "$IS_ROOT" -eq 1 ] && echo yes || echo NO)"
  echo "Method             : RPM database query (rpm -qa), yumdb/dnf repository"
  echo "                     origin, language package managers, package-owned"
  echo "                     file list vs file system scan, service manager"
  echo "                     query, cron and timer enumeration, yum/dnf update"
  echo "                     history. No network calls, no repo metadata"
  echo "                     refresh, no package state modified."
  echo "Output format      : one consolidated CSV (RecordType-tagged rows) plus"
  echo "                     this summary. See the script header comment for"
  echo "                     the full column layout and RecordType list."
  echo
  echo "--- COUNTS ---------------------------------------------------------"
  printf "%-38s: %s\n" "Installed RPM packages"        "$PKG_COUNT"
  printf "%-38s: %s\n" "  of which unsigned"           "$UNSIGNED_COUNT"
  [ "$UNCHECKED_COUNT" -gt 0 ] && printf "%-38s: %s\n" "  of which signature unchecked" "$UNCHECKED_COUNT"
  printf "%-38s: %s\n" "Software outside RPM"          "$NONRPM_COUNT"
  printf "%-38s: %s\n" "Executables owned by no package" "$UNOWNED_COUNT"
  printf "%-38s: %s\n" "  of which setuid/setgid"      "$SETUID_COUNT"
  printf "%-38s: %s\n" "Running processes"             "$PROC_COUNT"
  printf "%-38s: %s\n" "  from unpackaged binaries"     "$PROC_UNPKG"
  printf "%-38s: %s\n" "Listening network services"     "$(count_rt ListeningService)"
  printf "%-38s: %s\n" "inetd/xinetd services"          "$(count_rt InetdService)"
  printf "%-38s: %s\n" "Setuid/setgid files"            "$SETUIDFILE_COUNT"
  printf "%-38s: %s\n" "  owned by no package"          "$SETUIDFILE_UNPKG"
  printf "%-38s: %s\n" "Version marker files"           "$(count_rt VersionFile)"
  printf "%-38s: %s\n" "Mounted filesystems"            "$(count_rt Mount)"
  printf "%-38s: %s\n" "Services"                      "$(count_rt Service)"
  printf "%-38s: %s\n" "Scheduled tasks"               "$(count_rt ScheduledTask)"
  printf "%-38s: %s\n" "Kernel modules"                "$(count_rt KernelModule)"
  printf "%-38s: %s\n" "Update history entries"        "$(count_rt UpdateHistory)"
  printf "%-38s: %s\n" "Configured repositories"        "$(count_rt Repository)"
  printf "%-38s: %s\n" "Local accounts"                "$(count_rt LocalAccount)"
  [ "$DO_VERIFY" -eq 1 ] && printf "%-38s: %s\n" "Package verification mismatches" "$(count_rt PackageVerification)"
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
} > "$SUMMARY_FILE"

# ------------------------------------------------------- 13. package -----

# stop teeing before appending the console transcript / building the
# archive, so both are of the final, complete output.
exec 1>&3 2>&4
sleep 0.3

{
  echo
  echo "================================================================"
  echo "   CONSOLE OUTPUT / RUN TRANSCRIPT"
  echo "================================================================"
  cat "$CONSOLE_LOG" 2>/dev/null
} >> "$SUMMARY_FILE"

ARCHIVE=""
if [ "$DO_ARCHIVE" -eq 1 ]; then
  ARCHIVE="${OUT_ROOT}/LinuxSoftwareEvidence_${TAG}.tar.gz"
  if tar -czf "$ARCHIVE" -C "$OUT_ROOT" \
        "$(basename "$CSV_FILE")" "$(basename "$SUMMARY_FILE")" 2>/dev/null; then
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
echo " CSV            : $CSV_FILE"
echo " Summary        : $SUMMARY_FILE"
[ -n "$ARCHIVE" ] && echo " Package        : $ARCHIVE"
if [ "$IS_ROOT" -eq 0 ]; then
  echo
  echo " *** COLLECTION INCOMPLETE - not run as root ***"
fi
echo "================================================================"
