<?php
declare(strict_types=1);

namespace Sentinel;

/** The bundle or its signature could not be downloaded (as opposed to failing verification). */
final class RulesFetchException extends \RuntimeException
{
}

final class RulesUpdater
{
    private $config;
    private $state;
    private $http;
    private $self;

    public function __construct(Config $config, State $state, HttpClient $http, SelfCheck $self)
    {
        $this->config = $config;
        $this->state = $state;
        $this->http = $http;
        $this->self = $self;
    }

    /**
     * @return string[] output lines
     * @throws \RuntimeException when the bundle cannot be fetched, verified or installed
     */
    public function update(): array
    {
        $url = $this->config->rulesUrl;
        if ($url === '') {
            throw new \RuntimeException('rules_url is not set in the config; set it to the address of a rules.json bundle');
        }
        $bundle = $this->fetch($url, 'rules bundle');
        $lines = [];

        if (function_exists('sodium_crypto_sign_verify_detached') && $this->config->rulesPublicKey !== '') {
            $sig = base64_decode(trim($this->fetch($url . '.sig', 'rules signature')), true);
            $key = base64_decode($this->config->rulesPublicKey, true);
            if ($sig === false || $key === false
                || strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES
                || strlen($key) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
                || !sodium_crypto_sign_verify_detached($sig, $bundle, $key)) {
                throw new \RuntimeException('rules signature verification FAILED; the bundle was discarded');
            }
            $lines[] = 'signature verified';
        } elseif ($this->config->allowUnsignedRules) {
            $expected = strtolower((string)strtok(trim($this->fetch($url . '.sha256', 'rules checksum')), " \t\r\n"));
            if (!hash_equals($expected, hash('sha256', $bundle))) {
                throw new \RuntimeException('rules checksum mismatch; the bundle was discarded');
            }
            $lines[] = 'WARNING: only the SHA-256 checksum was checked. That protects against corruption but NOT against a compromised rules server. Set rules_public_key and install the sodium extension for signed bundles.';
        } else {
            throw new \RuntimeException('refusing to install unsigned rules: the sodium extension and rules_public_key are required (or set allow_unsigned_rules to true to accept the weaker SHA-256 check)');
        }

        $data = json_decode($bundle, true);
        if (!is_array($data)) {
            throw new \RuntimeException('the rules bundle is not valid JSON');
        }
        $new = Rules::fromArray($data);

        $file = $this->state->path('rules.json');
        $installed = -1;
        if (is_file($file)) {
            try {
                $installed = Rules::load($file)->version;
            } catch (\Throwable $e) {
                $installed = -1;
            }
        }
        if ($new->version < $installed) {
            throw new \RuntimeException(sprintf('refusing to install rules version %d: older than the installed version %d', $new->version, $installed));
        }
        if ($new->version === $installed) {
            return array_merge($lines, [sprintf('rules already up to date (version %d)', $installed)]);
        }

        $tmp = $file . '.tmp';
        if (file_put_contents($tmp, $bundle) === false) {
            throw new \RuntimeException('cannot write ' . $tmp);
        }
        @chmod($tmp, 0600);
        if (!rename($tmp, $file)) {
            @unlink($tmp);
            throw new \RuntimeException('cannot install ' . $file);
        }
        $this->self->record();
        $lines[] = sprintf('installed rules version %d (%d pattern(s), %d known-bad hash(es))', $new->version, count($new->patterns), count($new->hashes));
        return $lines;
    }

    private function fetch(string $url, string $what): string
    {
        $r = $this->http->request('GET', $url, '', [], 30);
        if ($r['status'] !== 200) {
            throw new RulesFetchException(sprintf('could not download the %s (%s)', $what, $r['status'] === 0 ? 'network error' : 'HTTP ' . $r['status']));
        }
        return $r['body'];
    }
}
