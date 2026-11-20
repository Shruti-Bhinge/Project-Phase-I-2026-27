<?php
// liveness.php - checks that URLs / email domains really exist before they are trusted.
// States returned by the checkers: 'live', 'dead', 'blocked'

function isPublicIp(string $ip): bool
{
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
}

function resolveHostIps(string $host): array
{
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        return [$host];
    }
    $ips = [];
    foreach ((@dns_get_record($host, DNS_A) ?: []) as $r) {
        if (!empty($r['ip'])) $ips[] = $r['ip'];
    }
    foreach ((@dns_get_record($host, DNS_AAAA) ?: []) as $r) {
        if (!empty($r['ipv6'])) $ips[] = $r['ipv6'];
    }
    if (!$ips) {
        $fallback = @gethostbynamel($host);
        if (is_array($fallback)) $ips = $fallback;
    }
    return array_values(array_unique($ips));
}

// Second opinion from a public DNS-over-HTTPS service, for when this PC's own resolver fails.
// Returns a list of IPs (empty = the domain has no address) or null when the service could not be reached.
function dohLookup(string $host): ?array
{
    if (!function_exists('curl_init') || !preg_match('/^[a-z0-9.-]+$/i', $host)) {
        return null;
    }
    foreach (['https://dns.google/resolve', 'https://cloudflare-dns.com/dns-query'] as $endpoint) {
        $ips = [];
        $reached = false;
        foreach ([[1, 'A'], [28, 'AAAA']] as [$typeNumber, $typeName]) {
            $ch = curl_init($endpoint . '?name=' . rawurlencode($host) . '&type=' . $typeName);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 4,
                CURLOPT_CONNECTTIMEOUT => 3,
                CURLOPT_HTTPHEADER     => ['Accept: application/dns-json'],
                CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS,
            ]);
            $body = curl_exec($ch);
            $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            $json = is_string($body) && $code === 200 ? json_decode($body, true) : null;
            if (!is_array($json) || !isset($json['Status'])) {
                continue;
            }
            $reached = true;
            foreach (($json['Answer'] ?? []) as $answer) {
                if ((int) ($answer['type'] ?? 0) === $typeNumber && !empty($answer['data'])) {
                    $ips[] = $answer['data'];
                }
            }
        }
        if ($reached) {
            return array_values(array_unique($ips));
        }
    }
    return null;
}

// True when this server can resolve a well-known domain, i.e. an "empty" answer for another host is believable.
function localDnsWorks(): bool
{
    static $works = null;
    if ($works === null) {
        $works = false;
        foreach (['example.com', 'google.com'] as $probe) {
            if (resolveHostIps($probe)) {
                $works = true;
                break;
            }
        }
    }
    return $works;
}

// Looks a host up and says whether a negative result can be trusted.
// 'inconclusive' => true means "we could not find out", NOT "the domain does not exist".
function lookupHost(string $host): array
{
    $ips = resolveHostIps($host);
    if ($ips) {
        return ['ips' => $ips, 'inconclusive' => false];
    }
    $doh = dohLookup($host);
    if ($doh !== null) {
        return ['ips' => $doh, 'inconclusive' => false];
    }
    return ['ips' => [], 'inconclusive' => !localDnsWorks()];
}

// One HTTP request pinned to a pre-validated IP (stops DNS-rebinding / SSRF). Redirects are NOT followed here.
function httpProbe(string $url, string $host, int $port, string $ip, bool $useGet): array
{
    $ch = curl_init($url);
    $opts = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER         => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_TIMEOUT        => 6,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_USERAGENT      => 'Mozilla/5.0 (compatible; PhishShieldBot/1.0)',
        CURLOPT_RESOLVE        => ["{$host}:{$port}:{$ip}"],
        CURLOPT_PROTOCOLS      => CURLPROTO_HTTP | CURLPROTO_HTTPS,
    ];
    if ($useGet) {
        $opts[CURLOPT_HTTPGET] = true;
        $opts[CURLOPT_RANGE]   = '0-1023';
    } else {
        $opts[CURLOPT_NOBODY] = true;
    }
    curl_setopt_array($ch, $opts);
    $raw   = curl_exec($ch);
    $code  = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $errno = curl_errno($ch);
    curl_close($ch);

    $location = '';
    if (is_string($raw) && preg_match('/^Location:\s*(\S+)/im', $raw, $m)) {
        $location = trim($m[1]);
    }
    return ['code' => $code, 'errno' => $errno, 'location' => $location];
}

function checkUrlLive(string $input, int $maxRedirects = 3): array
{
    $input = trim($input);
    if ($input === '' || preg_match('/\s/', $input)) {
        return ['state' => 'dead', 'detail' => 'This is not a valid web address (it contains spaces or extra words).', 'code' => 0, 'final_url' => $input];
    }
    $hasScheme = (bool) preg_match('~^[a-z][a-z0-9+.-]*://~i', $input);
    if ($hasScheme && !preg_match('~^https?://~i', $input)) {
        return ['state' => 'dead', 'detail' => 'Only http and https links are accepted.', 'code' => 0, 'final_url' => $input];
    }
    // No scheme typed: try https first, then http.
    $candidates = $hasScheme ? [$input] : ['https://' . $input, 'http://' . $input];
    $last = ['state' => 'dead', 'detail' => 'The website could not be reached.', 'code' => 0, 'final_url' => $input];

    foreach ($candidates as $start) {
        $last = followAndProbe($start, $maxRedirects);
        if ($last['state'] !== 'dead' || $last['detail'] === 'The domain does not exist.') {
            if ($last['state'] !== 'dead') return $last;
        }
    }
    return $last;
}

function followAndProbe(string $url, int $maxRedirects): array
{
    for ($hop = 0; $hop <= $maxRedirects; $hop++) {
        $parts = parse_url($url);
        $host  = strtolower($parts['host'] ?? '');
        $scheme = strtolower($parts['scheme'] ?? '');
        if ($host === '' || !in_array($scheme, ['http', 'https'], true)) {
            return ['state' => 'dead', 'detail' => 'The link is not a valid web address.', 'code' => 0, 'final_url' => $url];
        }
        // localhost / 127.0.0.1 is your own XAMPP server: it is really probed, so wrong paths are caught.
        $isLoopback = in_array($host, ['localhost', '127.0.0.1'], true);
        if (!$isLoopback && !filter_var($host, FILTER_VALIDATE_IP) && strpos($host, '.') === false) {
            return ['state' => 'dead', 'detail' => 'The host name is not a real domain.', 'code' => 0, 'final_url' => $url];
        }
        $port = (int) ($parts['port'] ?? ($scheme === 'https' ? 443 : 80));
        if (!in_array($port, [80, 443, 8080, 8443], true)) {
            return ['state' => 'blocked', 'detail' => 'Unusual port; not probed.', 'code' => 0, 'final_url' => $url];
        }

        $lookup = $isLoopback ? ['ips' => ['127.0.0.1'], 'inconclusive' => false] : lookupHost($host);
        $ips = $lookup['ips'];
        if (!$ips) {
            if ($lookup['inconclusive']) {
                return ['state' => 'blocked', 'detail' => 'The domain could not be looked up from this server (DNS unavailable), so it was not verified.', 'code' => 0, 'final_url' => $url];
            }
            return ['state' => 'dead', 'detail' => 'The domain does not exist.', 'code' => 0, 'final_url' => $url];
        }
        foreach ($ips as $ip) {
            if (!$isLoopback && !isPublicIp($ip)) {
                return ['state' => 'blocked', 'detail' => 'The address points to a private or reserved network; not probed.', 'code' => 0, 'final_url' => $url];
            }
        }
        if (!function_exists('curl_init')) {
            // DNS resolved but we cannot probe HTTP; accept domain existence only.
            return ['state' => 'live', 'detail' => 'Domain exists (HTTP probe unavailable: enable php_curl).', 'code' => 0, 'final_url' => $url];
        }

        $probe = httpProbe($url, $host, $port, $ips[0], false);
        if ($probe['code'] === 0 || $probe['code'] === 405 || $probe['code'] >= 400) {
            $get = httpProbe($url, $host, $port, $ips[0], true);
            if ($get['code'] !== 0) $probe = $get;
        }
        $code = $probe['code'];

        if ($code === 0) {
            // TLS certificate problems still prove the host exists.
            $tlsErrors = [35, 51, 53, 54, 58, 59, 60, 64, 66, 77, 83, 90, 91];
            if (in_array($probe['errno'], $tlsErrors, true)) {
                return ['state' => 'live', 'detail' => 'Host exists but its TLS certificate could not be verified.', 'code' => 0, 'final_url' => $url];
            }
            return ['state' => 'dead', 'detail' => 'The domain resolves but no web server answered.', 'code' => 0, 'final_url' => $url];
        }
        if ($code >= 300 && $code < 400 && $probe['location'] !== '') {
            $loc = $probe['location'];
            if (preg_match('~^https?://~i', $loc)) {
                $url = $loc;
            } elseif (strpos($loc, '//') === 0) {
                $url = $scheme . ':' . $loc;
            } else {
                $url = $scheme . '://' . $parts['host'] . ($loc[0] === '/' ? '' : '/') . $loc;
            }
            continue;
        }
        if ($code === 404 || $code === 410) {
            return ['state' => 'dead', 'detail' => 'The server answered but this page does not exist (HTTP ' . $code . ').', 'code' => $code, 'final_url' => $url];
        }
        if ($code >= 500) {
            return ['state' => 'dead', 'detail' => 'The server is failing (HTTP ' . $code . ').', 'code' => $code, 'final_url' => $url];
        }
        // 2xx/3xx, and 401/403/429 (server exists but blocks bots) count as live.
        return ['state' => 'live', 'detail' => 'The website responded (HTTP ' . $code . ').', 'code' => $code, 'final_url' => $url];
    }
    return ['state' => 'dead', 'detail' => 'Too many redirects.', 'code' => 0, 'final_url' => $url];
}

function checkEmailDomainLive(string $email): array
{
    $email = strtolower(trim($email));
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return ['state' => 'dead', 'detail' => 'Not a valid email address.'];
    }
    $domain = substr(strrchr($email, '@'), 1);
    if (@checkdnsrr($domain, 'MX') || @checkdnsrr($domain, 'A') || @checkdnsrr($domain, 'AAAA')) {
        return ['state' => 'live', 'detail' => 'The email domain exists and can receive mail.'];
    }
    return ['state' => 'dead', 'detail' => 'The email domain does not exist.'];
}

// Gathers everything worth checking (max 3 URLs + 2 email domains to keep the request fast).
function collectLivenessChecks(string $type, string $content): array
{
    $checks = [];
    if ($type === 'url') {
        $checks[] = ['kind' => 'url', 'target' => $content, 'result' => checkUrlLive($content)];
        return $checks;
    }
    preg_match_all('~(?:https?://|www\.)[^\s<>"\']+~i', $content, $m);
    $urls = array_slice(array_values(array_unique(array_map(
        static function ($u) { return rtrim($u, '.,;:!?)]}'); },
        $m[0] ?? []
    ))), 0, 3);
    foreach ($urls as $u) {
        $host = strtolower((string) parse_url(preg_match('~^https?://~i', $u) ? $u : 'http://' . $u, PHP_URL_HOST));
        if (in_array($host, ['localhost', '127.0.0.1', '::1'], true)) continue;
        $checks[] = ['kind' => 'url', 'target' => $u, 'result' => checkUrlLive($u)];
    }
    preg_match_all('/[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}/i', $content, $e);
    foreach (array_slice(array_values(array_unique(array_map('strtolower', $e[0] ?? []))), 0, 2) as $addr) {
        $checks[] = ['kind' => 'email', 'target' => $addr, 'result' => checkEmailDomainLive($addr)];
    }
    return $checks;
}

// How serious each kind of "does not exist" problem is (higher = more clearly fake).
function deadWeight(string $detail, string $kind): int
{
    if ($kind === 'email') {
        return stripos($detail, 'does not exist') !== false ? 85 : 80;
    }
    if (stripos($detail, 'domain does not exist') !== false) return 90;
    if (stripos($detail, 'not a valid web address') !== false || stripos($detail, 'not a real domain') !== false || stripos($detail, 'Only http') !== false) return 90;
    if (stripos($detail, 'no web server answered') !== false) return 75;
    if (stripos($detail, 'page does not exist') !== false) return 60;
    if (stripos($detail, 'failing') !== false) return 55;
    if (stripos($detail, 'redirect') !== false) return 45;
    return 70;
}

function probToRisk(float $p): float
{
    $x = (min(0.97, max(0.02, $p)) - 0.02) / 0.96;
    return 15 * $x / (1 - $x);
}

function riskToProb(float $r): float
{
    return min(0.98, max(0.02, 0.02 + 0.96 * ($r / ($r + 15))));
}

function hostOfUrl(string $url): string
{
    $normalized = preg_match('~^[a-z][a-z0-9+.-]*://~i', $url) ? $url : 'http://' . $url;
    return strtolower((string) (parse_url($normalized, PHP_URL_HOST) ?: ''));
}

// "example.co.in" => "example.co.in", "mail.example.com" => "example.com"
function registrableDomain(string $host): string
{
    $labels = explode('.', $host);
    $n = count($labels);
    if ($n < 2) {
        return $host;
    }
    $secondLevel = ['co', 'com', 'ac', 'org', 'net', 'gov', 'edu'];
    if ($n >= 3 && strlen($labels[$n - 1]) === 2 && in_array($labels[$n - 2], $secondLevel, true)) {
        return implode('.', array_slice($labels, -3));
    }
    return implode('.', array_slice($labels, -2));
}

// Real-time reputation signal: how many days ago the domain was registered (public RDAP data).
// Returns null when it cannot be found. Answers are cached for 7 days to keep scans fast.
function domainAgeDays(string $host): ?int
{
    $domain = registrableDomain($host);
    if (!function_exists('curl_init') || !preg_match('/^[a-z0-9.-]+\.[a-z]{2,}$/', $domain) || filter_var($domain, FILTER_VALIDATE_IP)) {
        return null;
    }
    $cache = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'phishshield_rdap_' . md5($domain) . '.json';
    if (is_file($cache) && filemtime($cache) > time() - 7 * 86400) {
        $saved = json_decode((string) @file_get_contents($cache), true);
        if (is_array($saved) && isset($saved['registered'])) {
            return max(0, intdiv(time() - (int) $saved['registered'], 86400));
        }
    }
    $ch = curl_init('https://rdap.org/domain/' . rawurlencode($domain));
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 3,
        CURLOPT_TIMEOUT        => 5,
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_HTTPHEADER     => ['Accept: application/rdap+json'],
        CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
    ]);
    $body = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    $json = is_string($body) && $code === 200 ? json_decode($body, true) : null;
    if (!is_array($json)) {
        return null;
    }
    foreach (($json['events'] ?? []) as $event) {
        if (($event['eventAction'] ?? '') === 'registration' && !empty($event['eventDate'])) {
            $registered = strtotime((string) $event['eventDate']);
            if ($registered !== false && $registered > 0) {
                @file_put_contents($cache, json_encode(['registered' => $registered]));
                return max(0, intdiv(time() - $registered, 86400));
            }
        }
    }
    return null;
}

// Adds graded indicators from the live check and re-scores the result (no fixed values).
function applyLiveness(array $result, array $checks): array
{
    $extra = 0;
    $urlChecks = 0;
    $establishedUrls = 0;
    foreach ($checks as $c) {
        $state = $c['result']['state'];
        $detail = (string) ($c['result']['detail'] ?? '');
        $label = ($c['kind'] === 'email' ? 'Email ' : 'URL ') . $c['target'] . ': ' . $detail;
        $trustedTarget = $c['kind'] === 'url' && isTrustedDomain(hostOfUrl($c['target']));
        $networkSide = stripos($detail, 'domain does not exist') !== false
            || stripos($detail, 'no web server answered') !== false
            || stripos($detail, 'not a real domain') !== false
            || stripos($detail, 'could not be reached') !== false;
        if ($state === 'dead' && $trustedTarget && $networkSide) {
            // A well-known site that this server cannot reach is a network problem here, not a fake site.
            $extra += 5;
            $result['indicators'][] = ['rule' => 'unverified_trusted', 'weight' => 5,
                'detail' => hostOfUrl($c['target']) . ' is a well-known domain, but it could not be reached from this server just now.'];
        } elseif ($state === 'dead') {
            $weight = deadWeight($detail, $c['kind']);
            $extra += $weight;
            $result['indicators'][] = [
                'rule' => $c['kind'] === 'email' ? 'email_domain_not_found' : 'url_not_live',
                'weight' => $weight, 'detail' => $label,
            ];
        } elseif ($state === 'blocked') {
            $extra += 15;
            $result['indicators'][] = ['rule' => 'unprobed_target', 'weight' => 15, 'detail' => $label];
        } elseif ($state === 'live' && $c['kind'] === 'url') {
            $urlChecks++;
            $tlsProblem = stripos($detail, 'TLS certificate could not be verified') !== false;
            if ($tlsProblem) {
                $extra += 15;
                $result['indicators'][] = ['rule' => 'invalid_tls', 'weight' => 15, 'detail' => 'The site\'s security certificate could not be verified.'];
            }
            $finalUrl = (string) ($c['result']['final_url'] ?? '');
            $from = registrableName(hostOfUrl($c['target']));
            $to = registrableName(hostOfUrl($finalUrl));
            if ($from !== '' && $to !== '' && $from !== $to && !isTrustedDomain(hostOfUrl($finalUrl))) {
                $extra += 10;
                $result['indicators'][] = ['rule' => 'redirects_elsewhere', 'weight' => 10, 'detail' => 'The link redirects to a different website (' . hostOfUrl($finalUrl) . ').'];
            }

            // Evidence of a real, established site (works for ANY website, not only a fixed list).
            $startHost = hostOfUrl($c['target']);
            $liveHost = hostOfUrl($finalUrl !== '' ? $finalUrl : $c['target']);
            $isTrusted = isTrustedDomain($startHost) || isTrustedDomain($liveHost);
            $ageDays = $isTrusted ? null : domainAgeDays($liveHost);
            if ($ageDays !== null && $ageDays < 30) {
                $extra += 40;
                $result['indicators'][] = ['rule' => 'newly_registered', 'weight' => 40, 'detail' => $liveHost . ' was registered only ' . $ageDays . ' day(s) ago. Brand-new domains are a common sign of phishing.'];
            } elseif ($ageDays !== null && $ageDays < 180) {
                $extra += 15;
                $result['indicators'][] = ['rule' => 'young_domain', 'weight' => 15, 'detail' => $liveHost . ' was registered about ' . max(1, (int) round($ageDays / 30)) . ' month(s) ago, so it has little history.'];
            } elseif ($ageDays !== null && $ageDays >= 730) {
                $result['indicators'][] = ['rule' => 'established_domain', 'weight' => 0, 'detail' => $liveHost . ' has been registered for about ' . (int) floor($ageDays / 365) . ' years, which points to an established site.'];
            }
            if (!$tlsProblem && stripos($finalUrl, 'https://') === 0) {
                $result['indicators'][] = ['rule' => 'valid_https', 'weight' => 0, 'detail' => $liveHost . ' is online and its HTTPS certificate is valid.'];
            }
            if (!$tlsProblem && ($isTrusted || ($ageDays !== null && $ageDays >= 365))) {
                $establishedUrls++;
            }

            // A long-established live site that only has a similar-sounding name is most likely a different, real business.
            if ($ageDays !== null && $ageDays >= 1095 && !$tlsProblem) {
                foreach ($result['indicators'] as &$indicator) {
                    if ($indicator['rule'] === 'similar_name_domain' && strpos($indicator['detail'], '"' . $startHost . '"') !== false) {
                        $extra += 6 - $indicator['weight'];
                        $indicator['weight'] = 6;
                        $indicator['detail'] = '"' . $startHost . '" has a name similar to a famous brand, but it is a long-established site (registered about ' . (int) floor($ageDays / 365) . ' years ago). Make sure it is the site you meant.';
                    }
                }
                unset($indicator);
            }
        }
    }

    $prob = (float) $result['phishing_probability'];
    $changed = false;
    if ($extra !== 0) {
        $prob = riskToProb(max(0.0, probToRisk($prob) + $extra));
        $changed = true;
    }
    // Every link goes to a live, established site and nothing serious was found: do not over-warn.
    $serious = false;
    foreach ($result['indicators'] as $indicator) {
        if ($indicator['weight'] >= 20) {
            $serious = true;
            break;
        }
    }
    if ($urlChecks > 0 && $establishedUrls === $urlChecks && !$serious && $prob > 0.12) {
        $prob = 0.12;
        $changed = true;
    }
    if ($changed) {
        $result['phishing_probability'] = $prob;
        $result['percentage'] = (int) round($prob * 100);
        $result['score'] = $result['percentage'];
        $result['label'] = $prob >= 0.75 ? 'phishing' : ($prob >= 0.30 ? 'caution' : 'safe');
        $result['confidence'] = min(0.96, 0.55 + abs($prob - 0.5) * 0.85);
    }
    usort($result['indicators'], static function ($a, $b) { return $b['weight'] <=> $a['weight']; });
    $result['liveness'] = $checks;
    return $result;
}