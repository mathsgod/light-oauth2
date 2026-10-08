<?php
declare(strict_types=1);
namespace Light\OAuth2\ClientMetadata;

/** Bounded, certificate-verified fetch pinned to a validated public DNS address. */
final class HttpsMetadataFetcher implements MetadataFetcher
{
    public const MAX_BYTES = 65536;

    public static function validateUrl(string $url): array
    {
        $parts = parse_url($url);
        if (strlen($url) > 2048 || preg_match('/[^\x21-\x7E]/', $url) || str_contains($url, '\\') || !$parts
            || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host']) || empty($parts['path'])
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])
            || !preg_match('/\A[a-zA-Z0-9.-]+\z/', $parts['host'])) {
            throw new \InvalidArgumentException('Invalid CIMD client URL');
        }
        foreach (explode('/', rawurldecode($parts['path'])) as $segment) {
            if ($segment === '.' || $segment === '..') throw new \InvalidArgumentException('Invalid CIMD path');
        }
        return $parts;
    }

    public static function isPublicAddress(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE | FILTER_FLAG_GLOBAL_RANGE) === false) return false;
        // Exclude transition addresses whose embedded IPv4 could reach private networks.
        $packed = inet_pton($ip);
        return strlen($packed) === 4 || ((ord($packed[0]) & 0xe0) === 0x20
            && !str_starts_with(bin2hex($packed), '2002') && !str_starts_with(bin2hex($packed), '20010000'));
    }

    /** Only the chosen, validated address is pinned to the connection. */
    public static function selectPublicAddress(array $addresses): string
    {
        foreach ($addresses as $ip) {
            if (is_string($ip) && self::isPublicAddress($ip)) return $ip;
        }
        throw new \RuntimeException('CIMD requires public IP addresses');
    }

    public function fetch(string $url): array
    {
        $parts = self::validateUrl($url);
        if (!extension_loaded('curl')) throw new \RuntimeException('CIMD requires ext-curl');
        $host = $parts['host'];
        $addresses = filter_var($host, FILTER_VALIDATE_IP) ? [$host] : [];
        if (!$addresses) {
            foreach (dns_get_record($host, DNS_A | DNS_AAAA) ?: [] as $entry) {
                if (isset($entry['ip'])) $addresses[] = $entry['ip'];
                if (isset($entry['ipv6'])) $addresses[] = $entry['ipv6'];
            }
        }
        if (!$addresses) throw new \RuntimeException('CIMD DNS lookup failed');
        $ip = self::selectPublicAddress($addresses);
        $port = $parts['port'] ?? 443;
        $body = '';
        $handle = curl_init($url);
        try {
            curl_setopt_array($handle, [
                CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_PROXY => '', // Do not let a proxy re-resolve a vetted hostname.
                CURLOPT_RESOLVE => [$host . ':' . $port . ':' . (str_contains($ip, ':') ? '[' . $ip . ']' : $ip)],
                CURLOPT_CONNECTTIMEOUT => 3,
                CURLOPT_TIMEOUT => 5,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_HTTPHEADER => ['Accept: application/json'],
                CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$body): int {
                    if (strlen($body) + strlen($chunk) > self::MAX_BYTES) return 0;
                    $body .= $chunk;
                    return strlen($chunk);
                },
            ]);
            if (curl_exec($handle) === false || curl_getinfo($handle, CURLINFO_RESPONSE_CODE) !== 200) {
                throw new \RuntimeException('Unable to fetch CIMD document');
            }
            $type = strtolower(explode(';', curl_getinfo($handle, CURLINFO_CONTENT_TYPE) ?: '')[0]);
            if ($type !== 'application/json' && !preg_match('~\Aapplication/[a-z0-9.+-]+\+json\z~', $type)) {
                throw new \RuntimeException('CIMD document must be JSON');
            }
            $document = json_decode($body, true, 32, JSON_THROW_ON_ERROR);
            if (!is_array($document) || array_is_list($document)) throw new \RuntimeException('Invalid CIMD document');
            return $document;
        } finally {
            curl_close($handle);
        }
    }
}
