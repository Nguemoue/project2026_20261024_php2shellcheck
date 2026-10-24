# php2shellcheck

**Are you actually on the PHP2Shell fix?** One PHP file. No Composer. No network. No exploit.

Le 21 octobre 2026, PHP a publié deux failles critiques :
[CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
et
[CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).
Les correctifs upstream sont **8.2.35**, **8.3.36**, **8.4.27** et **8.5.12**.
`php -v` ne suffit pas : Ubuntu, Debian et RHEL backportent souvent sans changer ce numéro.
Ce script refuse de dire « patched » tant que le numéro n’est pas celui du correctif, et il ne traite jamais un réglage `php.ini` comme un correctif.

Annonce officielle : [php.net, 21 Oct 2026](https://www.php.net/archive/2026.php#2026-10-21-5).

## Install

```bash
curl -fsSL -o php2shellcheck.php \
  https://raw.githubusercontent.com/Nguemoue/project2026_20261024_php2shellcheck/main/php2shellcheck.php
php php2shellcheck.php
```

PHP 8.1 or newer. The file is also valid on older CLI binaries, so you can check a host that has not been upgraded yet.

## Usage

```bash
php php2shellcheck.php
php php2shellcheck.php --ini=/etc/php/8.3/fpm/php.ini --sapi=fpm-fcgi
php php2shellcheck.php --version=8.3.6 --json
php php2shellcheck.php --discover
php php2shellcheck.php --self-test
```

`--version` checks the number only. It does not borrow the `php.ini` of the PHP that launches the script. The CLI SAPI is not php-fpm and not Apache: pass `--ini` with the web file.

Exit codes: `0` patched upstream, `1` bad arguments, `2` update / end of life / not proven. CI should fail on `2`.

## How to read it

| Verdict | Meaning |
|---|---|
| `PATCHED` | The version is the upstream fix, or newer, on that branch. Not a pre-release. |
| `UPDATE` | The number is below the fix. Install it and restart every worker. |
| `NO UPSTREAM FIX` | PHP 8.1 and older have no official release for these CVEs. Upgrade, or prove a vendor backport. |
| `UNKNOWN` | Newer than 8.5, or a pre-release past the floor. This script will not guess. |

`confidence: medium` plus `backport possible` means the number is still unpatched **and** the string looks like a distro package. Look at the changelog. If it does not name both CVEs, you are not patched.

```bash
apt changelog php8.3-fpm | grep -E '109618|109619'
# rpm: dnf updateinfo info php-fpm | grep -E '109618|109619'
```

Pasting the `share` line is the point. Example, from a real 8.4.23 CLI that is below the floor:

```text
php2shellcheck 8.4.23 cli UPDATE->8.4.27 CVE-2026-109618 CVE-2026-109619
```

Ubuntu-style number, still not a pass:

```text
php2shellcheck 8.3.6-1ubuntu1 fpm-fcgi UPDATE->8.3.36 CVE-2026-109618 CVE-2026-109619
```

Fixed upstream:

```text
php2shellcheck 8.3.36 fpm-fcgi PATCHED CVE-2026-109618 CVE-2026-109619
```

## What “exposure” means

The advisory lists settings that **reduce** some paths. They are printed so you can see them. They never change the verdict.

- `memory_limit=-1`, enforced where the app cannot turn it back on, only removes the controllable limit for CVE-2026-109618. An allocator failure can still reach the bug. Do **not** use `RLIMIT_AS` or `RLIMIT_DATA`.
- `session.upload_progress.enabled=0` in real `php.ini` or the FPM pool (not `ini_set()`, not `.user.ini`) blocks the documented CVE-2026-109619 path. Restart the workers.
- A smaller `post_max_size`, plus proxy limits, reduces how much PHP will parse. It is not a patch.

## What this will not do

- No request is sent. Nothing is exploited, crashed, or demonstrated.
- A green mitigation is not a green version.
- `php -v` on Debian, Ubuntu, or RHEL is not treated as proof of a missing backport. It is also not treated as proof of a backport.
- PHP 8.6 and newer are `UNKNOWN` until the floors in this file are updated. The floors are the 2026-10-21 advisory, nothing else.

## CI

```yaml
- run: php php2shellcheck.php --self-test
- run: php php2shellcheck.php --ini=/etc/php/8.3/fpm/php.ini --sapi=fpm-fcgi
```

The second command exits `2` until that binary’s version is the fix. That is what you want.

## License

MIT. Not affiliated with the PHP project.
