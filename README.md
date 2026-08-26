# Linux Software Evidence Gatherer

`sw_evidence_centos.sh` is a single, offline, root-preferred bash script that
collects a defensible software-inventory evidence package from an RPM-based
RHEL/CentOS host — everything installed, where it came from, what's running,
what's listening, and what doesn't belong to any package — and writes it out
as **one CSV and one summary text file**.

It makes no network calls. `rpm`/`yum`/`dnf` are only queried against local
databases; nothing is refreshed, nothing is installed or changed.

## Supported operating systems

The OS is detected at run time from `/etc/redhat-release` (or `/etc/os-release`
as a fallback) — there's nothing to configure per host.

| Release | Init system | Notes |
|---|---|---|
| RHEL Advanced Server 2.1 | SysV | bash 2.05b / rpm 4.0.x era — several compatibility fallbacks kick in (see below) |
| RHEL 4 | SysV | pre-yum; no associative-array support in its bash |
| CentOS / RHEL 6.10 | SysV + chkconfig | |
| CentOS / RHEL 7.5 | systemd | |
| RHEL 7.8 | systemd | |
| RHEL 8 | systemd | repo-of-origin read via `dnf repoquery` (no yumdb on 8) |

A version inside one of these major-version families but not an exact named
target (e.g. RHEL 6.9, RHEL 7.6) still runs on that family's code path — the
script just records that it wasn't a named target rather than failing or
silently treating it as identical. Anything outside major versions 2, 4, 6,
7, or 8 (Fedora, SUSE, Ubuntu, RHEL 5/9, etc.) is refused outright: the
script would rather do nothing than produce a partial inventory it can't
vouch for.

### Why this range needs special handling

RHEL Advanced Server 2.1 (2002) and RHEL 4 (2005) predate a lot of what
later scripting on Linux takes for granted. This script specifically avoids:

- **bash associative arrays** (introduced in bash 4.0) for the
  package-repository lookup — on bash 2.05b/3.0 that lookup is skipped and
  the repo-of-origin column is left blank rather than risking undefined
  behavior.
- **bash's `[[ str =~ regex ]]` operator** (bash 3.0+) — the one place that
  used it (skipping `PATH=`/`MAILTO=`-style lines in crontabs) is done with
  plain glob/`case` matching instead, which has always worked.
- **`find -perm /111` or `-perm +111`** — the `/MODE` "any bit" syntax needs
  findutils 4.3.3+, and the older `+MODE` syntax was later removed; neither
  spelling is safe across this whole span. `-perm -100 -o -perm -010 -o
  -perm -001` (tried three ways) has always worked.
- **rpm's GPG-signature queryformat conditional** — probed once at startup;
  if unsupported (rpm 4.0.x), the `Signed` column reports `UNCHECKED`
  instead of guessing.
- **`ps -o lstart=`** — probed once; falls back to elapsed time if
  unsupported.

Every one of these fallbacks is recorded as a warning in the evidence itself
(in the summary's "COLLECTION NOTES / LIMITATIONS" section), not hidden.

## Requirements

- Bash (ships on all six targets above).
- `rpm` (the script refuses to run without it).
- Run as **root**. It will still run without root, but the summary is
  stamped `COLLECTION INCOMPLETE` because other users' crontabs, some file
  trees, and parts of the package database are unreadable otherwise.

## Getting it onto the target host

Because this script is edited/stored on Windows, transferring it can leave
Windows (CRLF) line endings, which breaks the shebang with a confusing
`bad interpreter` error. The script detects this itself and tells you how to
fix it:

```
FATAL: this file has Windows (CRLF) line endings.
       Fix with:  dos2unix sw_evidence_centos.sh
       or:        sed -i 's/\r$//' sw_evidence_centos.sh
```

A `.gitattributes` in this repo forces LF line endings for `*.sh` files
regardless of a Windows clone's `core.autocrlf` setting, so a plain
`git clone` / `git pull` on Windows won't reintroduce the problem — it's
really only a risk if the file is copied some other way (email, a zip, a
Windows-native SCP client with text-mode translation, etc.).

## Running it

```bash
chmod +x sw_evidence_centos.sh
sudo ./sw_evidence_centos.sh
```

That's the common case: run as root, defaults everywhere, output lands in
`/var/tmp`.

### Options

```
-o DIR      output directory              (default: /var/tmp)
-r TEXT     reference / system name written into the summary
-c NAME     collector name                (default: logname or $USER)
-p PATHS    colon-separated roots for the unowned-executable scan
            (default: /usr/local:/opt:/awips:/awips2:/root:/home:/tmp:
             /var/tmp:/srv - AWIPS trees are large non-RPM installs)
-b FILE     approved-software baseline: one package name per line, or a
            CSV whose first column is the name. Anything installed that
            is not matched becomes a RecordType=Deviation row.
-V          also run "rpm -Va" package verification  (SLOW: 10-40 min)
-S          skip the unowned-executable / setuid-file filesystem scans
-A          do not create the tar.gz package
-h          help
```

### Examples

```bash
# Standard collection, tagged with a system name, dropped in a shared folder
sudo ./sw_evidence_centos.sh -o /mnt/evidence -r "PROD-DB01 / Case 2026-114"

# Quick pass without the filesystem scans (much faster on hosts with huge trees)
sudo ./sw_evidence_centos.sh -S

# Full pass including rpm -Va verification and a baseline diff
sudo ./sw_evidence_centos.sh -V -b approved_packages.csv
```

Run it once per host. Filenames are stamped with the hostname and a
timestamp, so output from many hosts can be dropped into the same directory
without colliding or needing a per-host subfolder.

## Output

Every run produces exactly two files (plus, unless `-A` is given, a
`.tar.gz` of the two):

```
LinuxSoftwareEvidence_<host>_<timestamp>.csv
LinuxSoftwareEvidence_Summary_<host>_<timestamp>.txt
LinuxSoftwareEvidence_<host>_<timestamp>.tar.gz     (unless -A)
```

### The CSV

One wide table, one row per piece of evidence, discriminated by a
`RecordType` column — the same shape used by this project's Windows
counterpart (`Get-SoftwareEvidence.ps1`), so both platforms' output loads
the same way into a downstream tool.

Columns:

```
RecordType, ComputerName, Collected, Reference, Collector, RanAsRoot,
Vendor, Model, Serial, BiosVersion, OSRelease, OSVersion, NamedTarget,
KernelRelease, KernelVersion, Architecture, InitSystem, CPUModel, CPUCount,
TotalMemoryMB, RootFilesystem, SELinux, MachineID, OSInstalled, Uptime,
RPMVersion, BashVersion,
Name, Version, Origin, Path, Flagged, Attributes
```

The `Vendor` .. `BashVersion` block is populated only on the single
`RecordType=SystemInfo` row for that host; every other row leaves it blank
and uses `Name`/`Version`/`Origin`/`Path`/`Flagged`/`Attributes` instead.
`Attributes` carries whatever is specific to that row's `RecordType` as
`key=value; key=value; ...` — split on `"; "` and then on the **first** `=`
in each pair, since a value (a repository base URL, for example) can itself
contain `=`.

`RecordType` values, one section of the old per-category output each:

| RecordType | What it is |
|---|---|
| `SystemInfo` | one row per host: identity, OS, kernel, hardware, credential status |
| `Package` | every installed RPM: version, vendor, repo origin, signature status |
| `NonRpmPackage` | pip/pip2/pip3/gem/npm-global packages, outside RPM |
| `UnownedExecutable` | executable files owned by no package |
| `PackageVerification` | `rpm -Va` mismatches (only with `-V`) |
| `Service` | systemd units or SysV/upstart services, with state and enablement |
| `ScheduledTask` | crontab, cron.d, cron.{hourly,daily,weekly,monthly}, systemd timers |
| `KernelModule` | loaded kernel modules |
| `UpdateHistory` | yum log / dnf history entries |
| `Repository` | configured yum repos (id, enabled, base URL) |
| `LocalAccount` | `/etc/passwd` accounts |
| `Process` | running processes, resolved back to an owning package where possible |
| `ListeningService` | listening TCP/UDP sockets and the process behind them |
| `InetdService` | inetd/xinetd-managed services |
| `SetuidFile` | setuid/setgid files system-wide |
| `VersionFile` | version-marker files found in local (non-package) software trees |
| `Mount` | mounted filesystems, and whether each was in scope for the `-xdev` scans |
| `Deviation` | installed packages not matched to an approved-software baseline (only with `-b`) |

Nothing that used to be its own CSV was dropped — every category above
existed as a separate file in earlier versions of this script. They're just
rows now.

### The summary

Human-readable: host identity, record counts per category, any collection
warnings/limitations (not-root, old-bash/old-rpm fallbacks, etc.), the full
installed-package listing, and the console transcript of the run itself.

## Feeding this into an evidence-compilation tool

If you're loading this output into a downstream compiler (this repo was
built to pair with one — "Palisade" — that turns scan/evidence exports into
STIG/PPSM/software-baseline artifacts), just drop the `.csv` file in; it's
recognized automatically by its `RecordType`/`ComputerName` header and
treated as credentialed evidence for that host. Multiple hosts' CSVs can be
dropped in together and merge into one dataset.
