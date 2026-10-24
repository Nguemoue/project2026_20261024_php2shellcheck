#!/usr/bin/env php
<?php
/**
 * php2shellcheck — is this PHP build on the PHP2Shell fix?
 *
 * CVE-2026-109618 and CVE-2026-109619, fixed upstream on 2026-10-21 in
 * 8.2.35, 8.3.36, 8.4.27 and 8.5.12.
 *
 * One file. No Composer. No network. No exploit.
 * A mitigation never changes the verdict. A distro can backport the fix
 * without moving the version number, so a lower number is not proof
 * that the package is still vulnerable — only that you have not proved
 * it is patched.
 *
 * https://www.php.net/archive/2026.php#2026-10-21-5
 */

if (PHP_SAPI !== 'cli') {
    echo "php2shellcheck is a command-line tool.\n";
    exit(1);
}

/**
 * Upstream patch floors from the 2026-10-21 PHP security advisory.
 * Anything at or above the floor on that minor, and not a pre-release, is the fix.
 */
function php2shell_floors()
{
    return array(
        2 => 35,
        3 => 36,
        4 => 27,
        5 => 12,
    );
}

function php2shell_split_version($version)
{
    $version = trim((string) $version);
    if (!preg_match('/^(\d+)\.(\d+)\.(\d+)(.*)$/', $version, $m)) {
        return null;
    }
    $rest = $m[4];
    $prerelease = false;
    if ($rest !== '' && preg_match('/^(?:[-_.])?(?:dev|alpha|beta|a|b|rc)(?:[-_.]?\d+)?/i', $rest)) {
        $prerelease = true;
    }
    $distro = false;
    if ($rest !== '' && preg_match('/ubuntu|debian|\+deb|dfsg|\.el\d|fc\d{1,2}|alpine|amzn|rhel/i', $rest)) {
        $distro = true;
    }
    return array(
        'major' => (int) $m[1],
        'minor' => (int) $m[2],
        'patch' => (int) $m[3],
        'rest' => $rest,
        'prerelease' => $prerelease,
        'distro_suffix' => $distro,
        'normalized' => $m[1] . '.' . $m[2] . '.' . $m[3],
    );
}

function php2shell_ini_bool($value)
{
    if ($value === null || $value === false) {
        return null;
    }
    $s = strtolower(trim((string) $value));
    if ($s === '') {
        return null;
    }
    if ($s === '1' || $s === 'on' || $s === 'true' || $s === 'yes') {
        return true;
    }
    if ($s === '0' || $s === 'off' || $s === 'false' || $s === 'no' || $s === 'none') {
        return false;
    }
    return null;
}

function php2shell_mitigations(array $in, $parsed)
{
    $items = array();

    $mem = array_key_exists('memory_limit', $in) ? $in['memory_limit'] : null;
    if ($mem === null || $mem === false || trim((string) $mem) === '') {
        $memState = 'unknown';
        $memNote = 'memory_limit was not provided. A finite limit is the controllable path for CVE-2026-109618.';
        $memValue = null;
    } elseif (trim((string) $mem) === '-1') {
        $memState = 'reduced';
        $memNote = 'memory_limit=-1 removes the controllable PHP limit. It is not complete: a real allocator failure can still reach the bug, and only if the web SAPI keeps it. The app must not be able to set a finite limit again.';
        $memValue = '-1';
    } else {
        $memState = 'open';
        $memNote = 'A finite memory_limit is the controllable out-of-memory path described for CVE-2026-109618.';
        $memValue = trim((string) $mem);
    }
    $items[] = array(
        'id' => 'memory_limit',
        'cve' => 'CVE-2026-109618',
        'value' => $memValue,
        'state' => $memState,
        'note' => $memNote,
    );

    $up = array_key_exists('upload_progress', $in) ? $in['upload_progress'] : null;
    $upBool = php2shell_ini_bool($up);
    if ($upBool === null) {
        $upState = 'unknown';
        $upNote = 'session.upload_progress.enabled was not provided. Off blocks the documented CVE-2026-109619 path. Set it in php.ini or the FPM pool, then restart workers. ini_set() and .user.ini are too late.';
    } elseif ($upBool === false) {
        $upState = 'reduced';
        $upNote = 'Upload progress is off. That blocks the documented CVE-2026-109619 path. It does not fix CVE-2026-109618.';
    } else {
        $upState = 'open';
        $upNote = 'Upload progress is on. The advisory recommends session.upload_progress.enabled=0 until the fixed release is installed. That is not a fix for CVE-2026-109618.';
    }
    $items[] = array(
        'id' => 'session.upload_progress.enabled',
        'cve' => 'CVE-2026-109619',
        'value' => ($up === null || $up === false) ? null : (string) $up,
        'state' => $upState,
        'note' => $upNote,
    );

    $handler = array_key_exists('serialize_handler', $in) ? $in['serialize_handler'] : null;
    if ($handler === null || $handler === false || trim((string) $handler) === '') {
        $hNote = 'session.serialize_handler was not provided.';
        $hValue = null;
    } else {
        $hValue = trim((string) $handler);
        $hl = strtolower($hValue);
        if ($hl === 'php_binary' || $hl === 'php_serialize') {
            $hNote = 'serialize_handler is ' . $hl . '. CVE-2026-109619 also needs a runtime ini_set() back to "php" before session_start(), and upload progress still enabled. That combination is unusual. It is not CVE-2026-109618.';
        } else {
            $hNote = 'serialize_handler is ' . $hl . '. Apps that never switch it at runtime are outside the narrow CVE-2026-109619 setup. CVE-2026-109618 does not depend on it.';
        }
    }
    $items[] = array(
        'id' => 'session.serialize_handler',
        'cve' => 'CVE-2026-109619',
        'value' => $hValue,
        'state' => 'info',
        'note' => $hNote,
    );

    $post = array_key_exists('post_max_size', $in) ? $in['post_max_size'] : null;
    $items[] = array(
        'id' => 'post_max_size',
        'cve' => 'CVE-2026-109618',
        'value' => ($post === null || $post === false || trim((string) $post) === '') ? null : trim((string) $post),
        'state' => 'info',
        'note' => 'A smaller post_max_size reduces how large a request PHP will parse. Also cap decoded size, field count and multipart parts at the proxy. Not a patch.',
    );

    $showFatal = is_array($parsed) && $parsed['major'] === 8 && $parsed['minor'] >= 5;
    if ($showFatal) {
        $fb = array_key_exists('fatal_error_backtraces', $in) ? $in['fatal_error_backtraces'] : null;
        $fbBool = php2shell_ini_bool($fb);
        if ($fbBool === false) {
            $fbState = 'reduced';
            $fbNote = 'fatal_error_backtraces=0 blocks one documented PHP 8.5 path for CVE-2026-109619. Not a fix.';
        } elseif ($fbBool === true) {
            $fbState = 'open';
            $fbNote = 'fatal_error_backtraces is on. On PHP 8.5 the advisory says 0 blocks one path only.';
        } else {
            $fbState = 'unknown';
            $fbNote = 'fatal_error_backtraces was not provided.';
        }
        $items[] = array(
            'id' => 'fatal_error_backtraces',
            'cve' => 'CVE-2026-109619',
            'value' => ($fb === null || $fb === false || trim((string) $fb) === '') ? null : trim((string) $fb),
            'state' => $fbState,
            'note' => $fbNote,
        );
    }

    return $items;
}

function php2shell_share(array $report)
{
    $labels = array(
        'patched' => 'PATCHED',
        'update' => 'UPDATE',
        'eol' => 'NO_UPSTREAM_FIX',
        'unknown' => 'UNKNOWN',
    );
    $label = isset($labels[$report['verdict']]) ? $labels[$report['verdict']] : 'UNKNOWN';
    $fixed = '';
    if (!empty($report['fixed_in']) && $report['verdict'] !== 'patched') {
        $fixed = '->' . $report['fixed_in'];
    }
    return 'php2shellcheck '
        . $report['version']
        . ' '
        . $report['sapi']
        . ' '
        . $label
        . $fixed
        . ' CVE-2026-109618 CVE-2026-109619';
}

/**
 * @param array $in version, sapi, memory_limit, upload_progress, serialize_handler,
 *                  post_max_size, fatal_error_backtraces, ini, backport_possible
 */
function php2shell_assess(array $in)
{
    $versionRaw = isset($in['version']) ? trim((string) $in['version']) : '';
    $sapi = (isset($in['sapi']) && trim((string) $in['sapi']) !== '') ? trim((string) $in['sapi']) : 'cli';
    $parsed = php2shell_split_version($versionRaw);
    $backport = !empty($in['backport_possible']);

    $report = array(
        'schema' => 1,
        'tool' => 'php2shellcheck',
        'advisory_date' => '2026-10-21',
        'advisory_url' => 'https://www.php.net/archive/2026.php#2026-10-21-5',
        'advisories' => array(
            'https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w',
            'https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp',
        ),
        'cves' => array('CVE-2026-109618', 'CVE-2026-109619'),
        'version' => $versionRaw,
        'parsed' => null,
        'sapi' => $sapi,
        'ini' => isset($in['ini']) ? $in['ini'] : null,
        'fixed_in' => null,
        'verdict' => 'unknown',
        'confidence' => 'low',
        'might_be_backported' => $backport,
        'notes' => array(),
        'mitigations' => array(),
        'limitations' => array(
            'A version at or above the upstream floor (and not a pre-release) is treated as patched.',
            'A lower number is not proof a distro failed to backport. The package changelog has to name both CVEs.',
            'Mitigations never change the verdict.',
            'The CLI php.ini is not the web SAPI php.ini.',
            'This tool does not send the version anywhere and does not try the bug.',
        ),
        'exit_code' => 2,
        'share' => '',
    );

    if ($parsed !== null && $parsed['distro_suffix']) {
        $report['might_be_backported'] = true;
    }

    if ($parsed === null) {
        $report['notes'][] = 'Version string is not MAJOR.MINOR.PATCH. Example: 8.3.6.';
    } else {
        $report['parsed'] = $parsed['normalized'];
        $major = $parsed['major'];
        $minor = $parsed['minor'];
        $patch = $parsed['patch'];
        $floors = php2shell_floors();

        if ($major < 8 || ($major === 8 && $minor < 2)) {
            $report['verdict'] = 'eol';
            $report['confidence'] = 'high';
            $report['notes'][] = $parsed['normalized'] . ' is outside the branches that received an official fix (8.2.35, 8.3.36, 8.4.27, 8.5.12).';
            $report['notes'][] = 'There is no official tarball for these CVEs on PHP 8.1 and older. Some vendors ship a backport. Unless the package changelog names CVE-2026-109618 and CVE-2026-109619, move to a fixed 8.2, 8.3, 8.4 or 8.5 release.';
        } elseif ($major > 8 || ($major === 8 && !isset($floors[$minor]))) {
            $report['verdict'] = 'unknown';
            $report['confidence'] = 'low';
            $report['notes'][] = $parsed['normalized'] . ' is newer than the branches named in the 2026-10-21 advisory (8.2 through 8.5).';
            $report['notes'][] = 'This script will not call it patched on a guess. Confirm the build was cut from a tree that contains the fix.';
        } else {
            $floor = $floors[$minor];
            $fixed = '8.' . $minor . '.' . $floor;
            $report['fixed_in'] = $fixed;
            $backported = !empty($report['might_be_backported']);

            if ($patch > $floor && $parsed['prerelease']) {
                $report['verdict'] = 'unknown';
                $report['confidence'] = 'medium';
                $report['notes'][] = $versionRaw . ' is past ' . $fixed . ' but it is a pre-release, not a release. Confirm the 2026-10-21 fix is in this build before you trust it.';
            } elseif ($patch > $floor || ($patch === $floor && !$parsed['prerelease'])) {
                $report['verdict'] = 'patched';
                $report['confidence'] = 'high';
                $report['exit_code'] = 0;
                if ($parsed['normalized'] === $fixed) {
                    $report['notes'][] = $parsed['normalized'] . ' is the upstream fix for both CVEs on this branch.';
                } else {
                    $report['notes'][] = $parsed['normalized'] . ' is newer than ' . $fixed . ' on this branch, so it includes the upstream fix for both CVEs.';
                }
                if ($backported) {
                    $report['notes'][] = 'The version number itself is the fix. A distro suffix does not undo that.';
                }
            } elseif ($patch === $floor && $parsed['prerelease']) {
                $report['verdict'] = 'update';
                $report['confidence'] = 'high';
                $report['notes'][] = $versionRaw . ' is a pre-release of ' . $fixed . ', not the release. Treat it as unpatched.';
            } elseif ($backported) {
                $report['verdict'] = 'update';
                $report['confidence'] = 'medium';
                $report['notes'][] = $parsed['normalized'] . ' is older than the upstream fix ' . $fixed . '.';
                $report['notes'][] = 'Debian, Ubuntu and RHEL sometimes backport without changing php -v. If a package manager owns this binary, confirm the changelog names both CVEs before you call it patched. Until then, treat it as unpatched.';
            } else {
                $report['verdict'] = 'update';
                $report['confidence'] = 'high';
                $report['notes'][] = $parsed['normalized'] . ' is older than the upstream fix ' . $fixed . '.';
                $report['notes'][] = 'Nothing in the version string indicates a vendor backport. Install ' . $fixed . ' or newer from this branch, then restart every PHP worker.';
            }
        }
    }

    $report['notes'][] = 'memory_limit, post_max_size and session.upload_progress.enabled only reduce exposure. None of them is a fix. Do not use RLIMIT_AS or RLIMIT_DATA as a mitigation.';
    if (strtolower($sapi) === 'cli') {
        $report['notes'][] = 'This reading is the CLI SAPI. php-fpm and Apache use a different php.ini. Pass --ini with the web ini, or this does not describe the process that serves requests.';
    }

    $report['mitigations'] = php2shell_mitigations($in, $parsed);
    $report['share'] = php2shell_share($report);
    return $report;
}

function php2shell_read_ini_keys($path)
{
    $lines = @file($path, FILE_IGNORE_NEW_LINES);
    if ($lines === false) {
        return null;
    }
    $keys = array();
    foreach ($lines as $line) {
        $trim = trim($line);
        if ($trim === '' || $trim[0] === ';' || $trim[0] === '#' || $trim[0] === '[') {
            continue;
        }
        if (!preg_match('/^([A-Za-z0-9_.]+)\s*=\s*(.*)$/', $trim, $m)) {
            continue;
        }
        $val = trim($m[2]);
        if ($val !== '' && ($val[0] === '"' || $val[0] === "'")) {
            $q = $val[0];
            if (substr($val, -1) === $q && strlen($val) >= 2) {
                $val = substr($val, 1, -1);
            }
        } else {
            $stripped = preg_replace('/\s*[;#].*$/', '', $val);
            $val = trim((string) $stripped);
        }
        $keys[strtolower($m[1])] = $val;
    }
    return $keys;
}

function php2shell_os_id()
{
    if (!is_readable('/etc/os-release')) {
        return null;
    }
    $text = @file_get_contents('/etc/os-release');
    if (!is_string($text)) {
        return null;
    }
    if (preg_match('/^ID=(.+)$/m', $text, $m)) {
        return strtolower(trim($m[1], " \t\"'"));
    }
    return null;
}

function php2shell_is_backport_distro($id)
{
    if ($id === null || $id === '') {
        return false;
    }
    $ids = array(
        'ubuntu', 'debian', 'linuxmint', 'pop', 'raspbian',
        'fedora', 'rhel', 'centos', 'rocky', 'almalinux', 'amzn', 'ol',
        'alpine', 'opensuse-leap', 'sles',
    );
    return in_array(strtolower($id), $ids, true);
}

function php2shell_distro_owns_binary($binary)
{
    if (!function_exists('exec') || !is_string($binary) || $binary === '' || !file_exists($binary)) {
        return false;
    }
    $disabled = ini_get('disable_functions');
    if (is_string($disabled) && stripos($disabled, 'exec') !== false) {
        return false;
    }
    $bin = escapeshellarg($binary);
    $checks = array(
        'command -v dpkg-query >/dev/null 2>&1 && dpkg-query -S ' . $bin . ' >/dev/null 2>&1',
        'command -v rpm >/dev/null 2>&1 && rpm -qf ' . $bin . ' >/dev/null 2>&1',
        'command -v apk >/dev/null 2>&1 && apk info --who-owns ' . $bin . ' >/dev/null 2>&1',
    );
    foreach ($checks as $cmd) {
        $out = array();
        $code = 1;
        @exec($cmd, $out, $code);
        if ((int) $code === 0) {
            return true;
        }
    }
    return false;
}

function php2shell_discover_ini_files()
{
    $patterns = array(
        '/etc/php/*/fpm/php.ini',
        '/etc/php/*/apache2/php.ini',
        '/etc/php/*/cli/php.ini',
        '/usr/local/etc/php/php.ini',
        '/usr/local/etc/php/*/php.ini',
        '/opt/homebrew/etc/php/*/php.ini',
        '/etc/php.ini',
    );
    $found = array();
    foreach ($patterns as $pattern) {
        $hits = glob($pattern);
        if (!is_array($hits)) {
            continue;
        }
        foreach ($hits as $hit) {
            if (is_file($hit)) {
                $found[$hit] = true;
            }
        }
    }
    $keys = array_keys($found);
    sort($keys);
    return $keys;
}

function php2shell_sapi_from_ini_path($path)
{
    $p = str_replace('\\', '/', (string) $path);
    if (strpos($p, '/fpm/') !== false) {
        return 'fpm-fcgi';
    }
    if (strpos($p, '/apache2/') !== false) {
        return 'apache2handler';
    }
    if (strpos($p, '/cli/') !== false) {
        return 'cli';
    }
    return 'unknown';
}

function php2shell_verdict_label($verdict)
{
    if ($verdict === 'patched') {
        return 'PATCHED';
    }
    if ($verdict === 'update') {
        return 'UPDATE';
    }
    if ($verdict === 'eol') {
        return 'NO UPSTREAM FIX';
    }
    return 'UNKNOWN';
}

function php2shell_wrap($text, $width, $indent)
{
    $text = trim(preg_replace('/\s+/', ' ', (string) $text));
    if ($text === '') {
        return '';
    }
    $wrapped = wordwrap($text, $width, "\n", true);
    $lines = explode("\n", $wrapped);
    $out = array();
    foreach ($lines as $line) {
        $out[] = $indent . $line;
    }
    return implode("\n", $out);
}

function php2shell_render(array $report)
{
    $lines = array();
    $lines[] = 'php2shellcheck';
    $lines[] = 'CVE-2026-109618  CVE-2026-109619';
    $lines[] = 'advisory 2026-10-21 · no network · no exploit';
    $lines[] = '';
    $lines[] = sprintf('%-12s %s', 'PHP', $report['version'] === '' ? '(empty)' : $report['version']);
    $lines[] = sprintf('%-12s %s', 'SAPI', $report['sapi']);
    $lines[] = sprintf('%-12s %s', 'ini', $report['ini'] ? $report['ini'] : '(none loaded)');
    $lines[] = sprintf('%-12s %s', 'upstream', $report['fixed_in'] ? $report['fixed_in'] : '(none on this branch)');
    $lines[] = '';
    $lines[] = sprintf('%-12s %s', 'VERDICT', php2shell_verdict_label($report['verdict']));
    $lines[] = sprintf('%-12s %s', 'confidence', $report['confidence']);
    if (!empty($report['might_be_backported'])) {
        $lines[] = sprintf('%-12s %s', 'backport', 'possible — changelog still required');
    }
    $lines[] = '';
    foreach ($report['notes'] as $note) {
        $lines[] = php2shell_wrap($note, 68, '');
        $lines[] = '';
    }
    $lines[] = 'exposure    reduces risk, never a patch';
    foreach ($report['mitigations'] as $item) {
        $value = $item['value'] === null ? '-' : $item['value'];
        $lines[] = sprintf('  %-36s %-8s %s', $item['id'], $value, $item['state']);
        $lines[] = php2shell_wrap($item['note'], 64, '    ');
    }
    $lines[] = '';
    $lines[] = 'Only the fixed release, or a vendor backport of that same fix,';
    $lines[] = 'closes both CVEs. Restart every worker after you patch.';
    $lines[] = '';
    $lines[] = 'share';
    $lines[] = $report['share'];
    $lines[] = '';
    return implode("\n", $lines);
}

function php2shell_help()
{
    return <<<'TXT'
php2shellcheck — are you on the PHP2Shell fix?

CVE-2026-109618 and CVE-2026-109619 were fixed on 2026-10-21 in
PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12. This script compares a
version to those floors and reads the ini values the advisory
mentions. It does not exploit anything and it does not use the network.

A mitigation never flips the verdict to patched. On Debian, Ubuntu
and RHEL, php -v often stays on the original number after a backport,
so a lower number means "not proven patched", not "proven vulnerable".

Usage
  php php2shellcheck.php
  php php2shellcheck.php --ini=/etc/php/8.3/fpm/php.ini --sapi=fpm-fcgi
  php php2shellcheck.php --version=8.3.6 --json
  php php2shellcheck.php --discover
  php php2shellcheck.php --self-test

Options
  --version=VER              Check this version instead of the running one
  --sapi=NAME                Label the SAPI (cli, fpm-fcgi, apache2handler)
  --ini=FILE                 Read exposure settings from this php.ini
  --memory-limit=VALUE       Override memory_limit
  --post-max-size=VALUE      Override post_max_size
  --upload-progress=0|1      Override session.upload_progress.enabled
  --serialize-handler=NAME   Override session.serialize_handler
  --fatal-error-backtraces=0|1
  --os-id=ubuntu             Force the distro-backport caveat
  --no-os                    Do not look at /etc/os-release or the package manager
  --discover                 Also grade php.ini files in common locations
  --json                     Machine-readable report
  --self-test                Run the built-in checks
  -h, --help

Exit codes
  0  upstream version is the fix (or newer) on a maintained branch
  1  bad arguments
  2  update, end of life, or not enough information

TXT;
}

function php2shell_parse_args(array $argv)
{
    $o = array(
        'help' => false,
        'self_test' => false,
        'json' => false,
        'discover' => false,
        'no_os' => false,
        'version' => null,
        'sapi' => null,
        'memory_limit' => null,
        'memory_limit_set' => false,
        'post_max_size' => null,
        'post_max_size_set' => false,
        'upload_progress' => null,
        'upload_progress_set' => false,
        'serialize_handler' => null,
        'serialize_handler_set' => false,
        'fatal_error_backtraces' => null,
        'fatal_error_backtraces_set' => false,
        'ini' => null,
        'os_id' => null,
        'error' => null,
    );
    $map = array(
        '--version' => 'version',
        '--sapi' => 'sapi',
        '--memory-limit' => 'memory_limit',
        '--post-max-size' => 'post_max_size',
        '--upload-progress' => 'upload_progress',
        '--serialize-handler' => 'serialize_handler',
        '--fatal-error-backtraces' => 'fatal_error_backtraces',
        '--ini' => 'ini',
        '--os-id' => 'os_id',
    );
    $n = count($argv);
    for ($i = 1; $i < $n; $i++) {
        $a = $argv[$i];
        if ($a === '--help' || $a === '-h') {
            $o['help'] = true;
            continue;
        }
        if ($a === '--self-test') {
            $o['self_test'] = true;
            continue;
        }
        if ($a === '--json') {
            $o['json'] = true;
            continue;
        }
        if ($a === '--discover') {
            $o['discover'] = true;
            continue;
        }
        if ($a === '--no-os') {
            $o['no_os'] = true;
            continue;
        }
        $matched = false;
        foreach ($map as $flag => $key) {
            if ($a === $flag) {
                if ($i + 1 >= $n) {
                    $o['error'] = 'Missing value for ' . $flag;
                    return $o;
                }
                $i++;
                $o[$key] = $argv[$i];
                $o[$key . '_set'] = true;
                $matched = true;
                break;
            }
            $prefix = $flag . '=';
            if (strlen($a) >= strlen($prefix) && substr($a, 0, strlen($prefix)) === $prefix) {
                $o[$key] = substr($a, strlen($prefix));
                $o[$key . '_set'] = true;
                $matched = true;
                break;
            }
        }
        if (!$matched) {
            $o['error'] = 'Unknown argument: ' . $a;
            return $o;
        }
    }
    return $o;
}

function php2shell_input_from_runtime(array $o)
{
    $iniPath = null;
    $fileKeys = array();
    if ($o['ini'] !== null) {
        if (!is_file($o['ini']) || !is_readable($o['ini'])) {
            fwrite(STDERR, "Cannot read ini file: " . $o['ini'] . "\n");
            return null;
        }
        $fileKeys = php2shell_read_ini_keys($o['ini']);
        if ($fileKeys === null) {
            fwrite(STDERR, "Cannot read ini file: " . $o['ini'] . "\n");
            return null;
        }
        $iniPath = $o['ini'];
    }

    $pick = function ($flagSet, $flagValue, $iniKey, $runtime) use ($o, $fileKeys) {
        if ($o[$flagSet]) {
            return $flagValue;
        }
        if ($iniKey !== null && isset($fileKeys[$iniKey])) {
            return $fileKeys[$iniKey];
        }
        if ($o['ini'] !== null) {
            return null;
        }
        $value = $runtime;
        if ($value === false || $value === '') {
            return null;
        }
        return $value;
    };

    $version = $o['version'] !== null ? $o['version'] : PHP_VERSION;
    $foreignVersion = $o['version'] !== null && $o['ini'] === null;
    if ($o['sapi'] !== null) {
        $sapi = $o['sapi'];
    } elseif ($foreignVersion) {
        $sapi = 'unspecified';
    } else {
        $sapi = PHP_SAPI;
    }

    $backport = false;
    if ($o['os_id'] !== null) {
        $backport = php2shell_is_backport_distro($o['os_id']);
    } elseif (!$o['no_os'] && $o['version'] === null) {
        $os = php2shell_os_id();
        if (php2shell_is_backport_distro($os) && php2shell_distro_owns_binary(PHP_BINARY)) {
            $backport = true;
        }
    }

    $iniLabel = $iniPath;
    if ($iniLabel === null && !$foreignVersion) {
        $loaded = php_ini_loaded_file();
        $iniLabel = ($loaded !== false && $loaded !== '') ? $loaded : null;
    }

    return array(
        'version' => $version,
        'sapi' => $sapi,
        'ini' => $iniLabel,
        'memory_limit' => $pick('memory_limit_set', $o['memory_limit'], 'memory_limit', $foreignVersion ? null : ini_get('memory_limit')),
        'post_max_size' => $pick('post_max_size_set', $o['post_max_size'], 'post_max_size', $foreignVersion ? null : ini_get('post_max_size')),
        'upload_progress' => $pick('upload_progress_set', $o['upload_progress'], 'session.upload_progress.enabled', $foreignVersion ? null : ini_get('session.upload_progress.enabled')),
        'serialize_handler' => $pick('serialize_handler_set', $o['serialize_handler'], 'session.serialize_handler', $foreignVersion ? null : ini_get('session.serialize_handler')),
        'fatal_error_backtraces' => $pick('fatal_error_backtraces_set', $o['fatal_error_backtraces'], 'fatal_error_backtraces', $foreignVersion ? null : ini_get('fatal_error_backtraces')),
        'backport_possible' => $backport,
    );
}

function php2shell_assert($cond, $message, array &$failures)
{
    if (!$cond) {
        $failures[] = $message;
    }
}

function php2shell_self_test()
{
    $failures = array();
    $check = function ($version, $extra) {
        $in = array_merge(array(
            'version' => $version,
            'sapi' => 'fpm-fcgi',
            'memory_limit' => null,
            'upload_progress' => null,
            'serialize_handler' => null,
            'post_max_size' => null,
            'fatal_error_backtraces' => null,
            'ini' => null,
            'backport_possible' => false,
        ), $extra);
        return php2shell_assess($in);
    };

    $r = $check('8.2.34', array());
    php2shell_assert($r['verdict'] === 'update' && $r['fixed_in'] === '8.2.35' && $r['exit_code'] === 2 && $r['confidence'] === 'high', '8.2.34 should update to 8.2.35', $failures);

    $r = $check('8.2.35', array());
    php2shell_assert($r['verdict'] === 'patched' && $r['exit_code'] === 0 && $r['confidence'] === 'high', '8.2.35 should be patched', $failures);

    $r = $check('8.2.35RC1', array());
    php2shell_assert($r['verdict'] === 'update' && $r['exit_code'] === 2, '8.2.35RC1 is not the release', $failures);

    $r = $check('8.2.35-dev', array());
    php2shell_assert($r['verdict'] === 'update' && $r['exit_code'] === 2, '8.2.35-dev is not the release', $failures);

    $r = $check('8.2.36', array());
    php2shell_assert($r['verdict'] === 'patched' && $r['exit_code'] === 0, '8.2.36 should be patched', $failures);

    $r = $check('8.3.6', array());
    php2shell_assert($r['verdict'] === 'update' && $r['fixed_in'] === '8.3.36' && $r['confidence'] === 'high' && $r['might_be_backported'] === false, '8.3.6 must not be compared as a string (6 < 36)', $failures);

    $r = $check('8.3.6-1ubuntu1', array());
    php2shell_assert($r['verdict'] === 'update' && $r['confidence'] === 'medium' && $r['might_be_backported'] === true && $r['exit_code'] === 2, 'ubuntu suffix is a backport caveat, not a pass', $failures);

    $r = $check('8.3.6', array('backport_possible' => true));
    php2shell_assert($r['verdict'] === 'update' && $r['confidence'] === 'medium' && $r['might_be_backported'] === true, 'explicit backport flag stays unpatched', $failures);

    $r = $check('8.3.35', array());
    php2shell_assert($r['verdict'] === 'update' && $r['fixed_in'] === '8.3.36', '8.3.35 is one below the floor', $failures);

    $r = $check('8.3.36', array());
    php2shell_assert($r['verdict'] === 'patched' && $r['exit_code'] === 0, '8.3.36 should be patched', $failures);

    $r = $check('8.3.36-1ubuntu1', array());
    php2shell_assert($r['verdict'] === 'patched' && $r['exit_code'] === 0 && $r['might_be_backported'] === true, 'distro build of the fixed number stays patched', $failures);

    $r = $check('8.3.36RC1', array());
    php2shell_assert($r['verdict'] === 'update' && $r['exit_code'] === 2, '8.3.36RC1 is not the release', $failures);

    $r = $check('8.3.37-dev', array());
    php2shell_assert($r['verdict'] === 'unknown' && $r['exit_code'] === 2 && $r['fixed_in'] === '8.3.36', 'pre-release above the floor is not an automatic pass', $failures);

    $r = $check('8.4.9', array());
    php2shell_assert($r['verdict'] === 'update' && $r['fixed_in'] === '8.4.27', '8.4.9 is below 8.4.27 numerically', $failures);

    $r = $check('8.4.26', array());
    php2shell_assert($r['verdict'] === 'update' && $r['fixed_in'] === '8.4.27', '8.4.26 should update', $failures);

    $r = $check('8.4.27', array('memory_limit' => '128M', 'upload_progress' => '1'));
    php2shell_assert($r['verdict'] === 'patched' && $r['exit_code'] === 0, 'finite memory_limit must not unpatch a fixed version', $failures);
    $mem = null;
    foreach ($r['mitigations'] as $item) {
        if ($item['id'] === 'memory_limit') {
            $mem = $item;
        }
    }
    php2shell_assert(is_array($mem) && $mem['state'] === 'open', '128M memory_limit is the open path', $failures);

    $r = $check('8.2.34', array('memory_limit' => '-1', 'upload_progress' => '0', 'sapi' => 'fpm-fcgi'));
    php2shell_assert($r['verdict'] === 'update' && $r['exit_code'] === 2, 'mitigations must not flip the verdict', $failures);
    $states = array();
    foreach ($r['mitigations'] as $item) {
        $states[$item['id']] = $item['state'];
    }
    php2shell_assert(isset($states['memory_limit']) && $states['memory_limit'] === 'reduced', 'memory_limit=-1 is reduced, not a fix', $failures);
    php2shell_assert(isset($states['session.upload_progress.enabled']) && $states['session.upload_progress.enabled'] === 'reduced', 'upload progress off is reduced', $failures);
    php2shell_assert(!isset($states['fatal_error_backtraces']), 'fatal_error_backtraces is 8.5+ only', $failures);

    $r = $check('8.5.11', array());
    php2shell_assert($r['verdict'] === 'update' && $r['fixed_in'] === '8.5.12', '8.5.11 should update', $failures);
    $hasFatal = false;
    foreach ($r['mitigations'] as $item) {
        if ($item['id'] === 'fatal_error_backtraces') {
            $hasFatal = true;
        }
    }
    php2shell_assert($hasFatal, '8.5 should report fatal_error_backtraces', $failures);

    $r = $check('8.5.12', array('fatal_error_backtraces' => '0'));
    php2shell_assert($r['verdict'] === 'patched' && $r['exit_code'] === 0, '8.5.12 should be patched', $failures);

    $r = $check('8.5.13', array());
    php2shell_assert($r['verdict'] === 'patched' && $r['exit_code'] === 0, '8.5.13 should be patched', $failures);

    $r = $check('8.1.34', array());
    php2shell_assert($r['verdict'] === 'eol' && $r['fixed_in'] === null && $r['exit_code'] === 2, '8.1 has no upstream fix', $failures);

    $r = $check('8.0.30', array());
    php2shell_assert($r['verdict'] === 'eol' && $r['exit_code'] === 2, '8.0 is end of life', $failures);

    $r = $check('7.4.33', array());
    php2shell_assert($r['verdict'] === 'eol' && $r['exit_code'] === 2, '7.4 is end of life', $failures);

    $r = $check('8.6.0', array());
    php2shell_assert($r['verdict'] === 'unknown' && $r['exit_code'] === 2, '8.6 is outside the advisory', $failures);

    $r = $check('9.0.0', array());
    php2shell_assert($r['verdict'] === 'unknown' && $r['exit_code'] === 2, 'PHP 9 is outside the advisory', $failures);

    $r = $check('', array());
    php2shell_assert($r['verdict'] === 'unknown' && $r['exit_code'] === 2, 'empty version is unknown', $failures);

    $r = $check('8.3', array());
    php2shell_assert($r['verdict'] === 'unknown' && $r['exit_code'] === 2, 'two-part version is unknown', $failures);

    $r = $check('8.4.27', array('sapi' => 'cli'));
    $joined = implode("\n", $r['notes']);
    php2shell_assert(strpos($joined, 'CLI SAPI') !== false, 'cli sapi warns that it is not the web ini', $failures);

    $r = $check('8.4.27', array('sapi' => 'fpm-fcgi'));
    $joined = implode("\n", $r['notes']);
    php2shell_assert(strpos($joined, 'CLI SAPI') === false, 'fpm sapi must not warn about CLI', $failures);

    $renderedUpdate = php2shell_render($check('8.3.6', array('sapi' => 'fpm-fcgi')));
    php2shell_assert(strpos($renderedUpdate, 'VERDICT      UPDATE') !== false, 'render shows UPDATE', $failures);
    php2shell_assert(strpos($renderedUpdate, '8.3.36') !== false, 'render shows the floor', $failures);
    php2shell_assert(strpos($renderedUpdate, 'VERDICT      PATCHED') === false, 'update render must not say PATCHED', $failures);
    php2shell_assert(strpos($renderedUpdate, 'you are safe') === false, 'render must not say you are safe', $failures);

    $renderedOk = php2shell_render($check('8.5.12', array()));
    php2shell_assert(strpos($renderedOk, 'VERDICT      PATCHED') !== false, 'render shows PATCHED', $failures);

    $share = $check('8.3.6', array('sapi' => 'fpm-fcgi'));
    php2shell_assert($share['share'] === 'php2shellcheck 8.3.6 fpm-fcgi UPDATE->8.3.36 CVE-2026-109618 CVE-2026-109619', 'share line', $failures);

    $tmp = tempnam(sys_get_temp_dir(), 'p2s');
    if ($tmp === false) {
        $failures[] = 'tempnam failed';
    } else {
        $ini = $tmp . '.ini';
        @unlink($tmp);
        $body = "; comment\nmemory_limit = 256M ; inline\npost_max_size = 32M\nsession.upload_progress.enabled = Off\nsession.serialize_handler = \"php\"\n";
        if (file_put_contents($ini, $body) === false) {
            $failures[] = 'failed to write temp ini';
        } else {
            $keys = php2shell_read_ini_keys($ini);
            php2shell_assert(is_array($keys) && isset($keys['memory_limit']) && $keys['memory_limit'] === '256M', 'ini parser strips inline comments', $failures);
            php2shell_assert(isset($keys['session.upload_progress.enabled']) && $keys['session.upload_progress.enabled'] === 'Off', 'ini parser keeps dotted keys', $failures);
            php2shell_assert(isset($keys['session.serialize_handler']) && $keys['session.serialize_handler'] === 'php', 'ini parser strips quotes', $failures);
            @unlink($ini);
        }
    }

    php2shell_assert(php2shell_is_backport_distro('ubuntu') === true, 'ubuntu is a backport distro', $failures);
    php2shell_assert(php2shell_is_backport_distro('arch') === false, 'arch is not treated as a backport distro', $failures);
    php2shell_assert(php2shell_sapi_from_ini_path('/etc/php/8.3/fpm/php.ini') === 'fpm-fcgi', 'fpm path', $failures);
    php2shell_assert(is_array(php2shell_discover_ini_files()), 'discover returns a list', $failures);

    $json = json_encode($check('8.4.27', array()));
    $decoded = json_decode((string) $json, true);
    php2shell_assert(is_array($decoded) && isset($decoded['cves'][0]) && $decoded['cves'][0] === 'CVE-2026-109618', 'json keeps the CVE id', $failures);
    php2shell_assert(isset($decoded['limitations']) && count($decoded['limitations']) >= 4, 'json includes limitations', $failures);

    if (function_exists('exec')) {
        $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__FILE__) . ' --version=8.4.26 --sapi=fpm-fcgi --no-os --memory-limit=128M --upload-progress=1 --json';
        $out = array();
        $code = 1;
        @exec($cmd, $out, $code);
        $payload = json_decode(implode("\n", $out), true);
        php2shell_assert((int) $code === 2 && is_array($payload) && $payload['verdict'] === 'update' && $payload['fixed_in'] === '8.4.27', 'CLI json exit 2 for 8.4.26', $failures);

        $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__FILE__) . ' --version=8.5.12 --sapi=fpm-fcgi --no-os --json';
        $out = array();
        $code = 1;
        @exec($cmd, $out, $code);
        $payload = json_decode(implode("\n", $out), true);
        php2shell_assert((int) $code === 0 && is_array($payload) && $payload['verdict'] === 'patched', 'CLI json exit 0 for 8.5.12', $failures);

        $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__FILE__) . ' --not-a-flag';
        $out = array();
        $code = 0;
        @exec($cmd . ' 2>/dev/null', $out, $code);
        php2shell_assert((int) $code === 1, 'unknown flag exits 1', $failures);

        $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__FILE__) . ' --version=8.3.6 --no-os --json';
        $out = array();
        $code = 0;
        @exec($cmd, $out, $code);
        $payload = json_decode(implode("\n", $out), true);
        $borrowed = false;
        if (is_array($payload)) {
            foreach ($payload['mitigations'] as $item) {
                if ($item['id'] === 'memory_limit' && $item['value'] !== null) {
                    $borrowed = true;
                }
            }
        }
        php2shell_assert((int) $code === 2 && is_array($payload) && $payload['verdict'] === 'update' && $payload['sapi'] === 'unspecified' && $borrowed === false, '--version must not borrow the running php.ini', $failures);

        $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__FILE__) . ' --help';
        $out = array();
        $code = 1;
        @exec($cmd, $out, $code);
        $help = implode("\n", $out);
        php2shell_assert((int) $code === 0 && strpos($help, '--self-test') !== false, 'help exits 0', $failures);
    } else {
        $failures[] = 'exec() is disabled; CLI checks could not run';
    }

    if (count($failures) > 0) {
        fwrite(STDERR, "FAIL " . count($failures) . "\n");
        foreach ($failures as $failure) {
            fwrite(STDERR, "  - " . $failure . "\n");
        }
        return 1;
    }
    fwrite(STDOUT, "ok self-test\n");
    return 0;
}

function php2shell_main(array $argv)
{
    $o = php2shell_parse_args($argv);
    if ($o['error'] !== null) {
        fwrite(STDERR, $o['error'] . "\n");
        fwrite(STDERR, "Try --help\n");
        return 1;
    }
    if ($o['help']) {
        fwrite(STDOUT, php2shell_help());
        return 0;
    }
    if ($o['self_test']) {
        return php2shell_self_test();
    }

    $input = php2shell_input_from_runtime($o);
    if ($input === null) {
        return 1;
    }
    $report = php2shell_assess($input);

    if ($o['discover']) {
        $files = php2shell_discover_ini_files();
        $extra = array();
        foreach ($files as $file) {
            $keys = php2shell_read_ini_keys($file);
            if (!is_array($keys)) {
                continue;
            }
            $copy = $input;
            $copy['sapi'] = $o['sapi'] !== null ? $o['sapi'] : php2shell_sapi_from_ini_path($file);
            $copy['ini'] = $file;
            if (!$o['memory_limit_set'] && isset($keys['memory_limit'])) {
                $copy['memory_limit'] = $keys['memory_limit'];
            }
            if (!$o['post_max_size_set'] && isset($keys['post_max_size'])) {
                $copy['post_max_size'] = $keys['post_max_size'];
            }
            if (!$o['upload_progress_set'] && isset($keys['session.upload_progress.enabled'])) {
                $copy['upload_progress'] = $keys['session.upload_progress.enabled'];
            }
            if (!$o['serialize_handler_set'] && isset($keys['session.serialize_handler'])) {
                $copy['serialize_handler'] = $keys['session.serialize_handler'];
            }
            if (!$o['fatal_error_backtraces_set'] && isset($keys['fatal_error_backtraces'])) {
                $copy['fatal_error_backtraces'] = $keys['fatal_error_backtraces'];
            }
            $extra[] = php2shell_assess($copy);
        }
        if ($o['json']) {
            $report['discovered'] = $extra;
        } else {
            fwrite(STDOUT, php2shell_render($report));
            if (count($extra) === 0) {
                fwrite(STDOUT, "discover    no extra php.ini in the usual locations\n\n");
            }
            foreach ($extra as $one) {
                fwrite(STDOUT, "----\n");
                fwrite(STDOUT, php2shell_render($one));
            }
            return (int) $report['exit_code'];
        }
    }

    if ($o['json']) {
        fwrite(STDOUT, json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
    } else {
        fwrite(STDOUT, php2shell_render($report));
    }
    return (int) $report['exit_code'];
}

if (isset($argv[0]) && @realpath((string) $argv[0]) === realpath(__FILE__)) {
    exit(php2shell_main($argv));
}
