<?php declare(strict_types=1);

namespace EdgeTelemetrics\React\Dns;

use Exception;
use InvalidArgumentException;
use Psr\Http\Message\ResponseInterface;
use React\Dns\Model\Message;
use React\Dns\Protocol\BinaryDumper;
use React\Dns\Protocol\Parser;
use React\Dns\Query\ExecutorInterface;
use React\Dns\Query\Query;
use React\EventLoop\Loop;
use React\EventLoop\LoopInterface;
use React\Http\Browser;
use React\Promise;
use React\Promise\Deferred;
use React\Socket\ConnectionInterface;
use React\Socket\Connector;
use RuntimeException;
use function parse_url;
use function strlen;
use function strtolower;
use function substr_count;

class DohExecutor implements ExecutorInterface {

    private string $nameserver;
    private LoopInterface $loop;
    private Parser $parser;
    private BinaryDumper $dumper;

    private string $method;

    private bool $ipv6address = false;

    private Promise\PromiseInterface $browserResolution;

    const METHOD_GET = 'get';
    const METHOD_POST = 'post';

    const FINGERPRINT_HASH_METHOD = 'sha256';

    /**
     * @param string $nameserver
     * @param string $method
     * @param ?LoopInterface $loop
     */
    public function __construct(string $nameserver, string $method = self::METHOD_GET, LoopInterface $loop = null)
    {
        if (!class_exists('\React\Http\Browser')) {
            throw new RuntimeException('DNS over HTTPS support requires reactphp/http library'); //@codeCoverageIgnore
        }

        if (!str_contains($nameserver, '[') && substr_count($nameserver, ':') >= 2 && !str_contains($nameserver, '://')) {
            // several colons, but not enclosed in square brackets => enclose IPv6 address in square brackets
            $nameserver = '[' . $nameserver . ']';
        }

        $parts = parse_url((!str_contains($nameserver, '://') ? 'https://' : '') . $nameserver);
        if (!isset($parts['scheme'], $parts['host']) || $parts['scheme'] !== 'https') {
            throw new InvalidArgumentException('Invalid nameserver address given');
        }

        if (filter_var(trim($parts['host'], '[]'), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $this->ipv6address = true;
        }

        $method = strtolower($method);
        if (!in_array($method, [self::METHOD_GET, self::METHOD_POST], true)) {
            throw new InvalidArgumentException('Invalid HTTP request method given');
        }

        $this->nameserver = 'https://' . $parts['host'] . ':' . ($parts['port'] ?? 443 . '/dns-query');
        $this->loop = $loop ?: Loop::get();
        $this->parser = new Parser();
        $this->dumper = new BinaryDumper();
        $this->method = $method;
    }

    public function query(Query $query)
    {
        return $this->getBrowser()->then(function($browser) use ($query) {
            $request = Message::createRequestForQuery($query);

            $queryData = $this->dumper->toBinary($request);
            $length = strlen($queryData);

            if ($length > 0xffff) {
                return Promise\reject(new RuntimeException(
                    'DNS query for ' . $query->describe() . ' failed: Query too large for HTTPS transport'
                ));
            }

            if ($this->method === self::METHOD_GET) {
                $requestUrl = $this->nameserver . '?' . http_build_query(['dns' => $this->urlsafeBase64($queryData)]);
                $request = $browser->get($requestUrl);
            } else {
                $requestUrl = $this->nameserver;
                $request = $browser->post($requestUrl, [
                    'accept' => 'application/dns-message',
                    'content-type' => 'application/dns-message'
                ], $queryData);
            }

            return $request->then(function (ResponseInterface $response) {
                $response = $this->parser->parseMessage((string)$response->getBody());
                return Promise\resolve($response);
            }, function (Exception $e) use ($query) {
                return Promise\reject(new RuntimeException(
                    'DNS query for ' . $query->describe() . ' failed: ' . $e->getMessage()
                ));
            });
        }, function($e) use ($query) {
            return Promise\reject(new RuntimeException(
                'DNS query for ' . $query->describe() . ' failed: ' . $e->getMessage()
            ));
        });
    }

    /**
     * @param string $data
     * @return string
     */
    private function urlsafeBase64(string $data) : string {
        // @codeCoverageIgnoreStart
        if (function_exists('sodium_bin2base64')) {
            try {
                return sodium_bin2base64($data, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
            } catch (\SodiumException $ex) { /* Allow fallthrough to non sodium method */}
        }
        return rtrim( strtr( base64_encode( $data ), '+/', '-_'), '=');
        //@codeCoverageIgnoreEnd
    }

    private function getBrowser() : Promise\PromiseInterface {
        if (!isset($this->browserResolution)) {
            $deferred = new Deferred();
            $this->browserResolution = $deferred->promise();
            if ($this->ipv6address) {
                // PHP does not validate IPv6 addresses contained in the SAN fields of a certificate
                // To support IPv6 we download the certificate on the first connect and manually verify our nameserver IPv6 IP
                // is listed in the SAN fields. We then construct a Browser instance with verify_peer_name set to false but with the peer_fingerprint set to our verified certificate.
                // This doesn't always work because the server may use different front end certificates (SIGH!)
                $address = str_replace('https://', 'tls://', $this->nameserver);
                $connector = new Connector([
                    'tcp' => [
                        'tcp_nodelay' => true,
                        ],
                    'tls' => [
                        'verify_peer_name' => false,
                        'capture_peer_cert' => true
                    ],
                    'dns' => false,
                ], $this->loop);
                $connector->connect($address)->then(function (ConnectionInterface $connection) use ($deferred) {
                    $response = stream_context_get_params($connection->stream); //Using @internal stream
                    $connection->end();
                    $certificatePem = $response['options']['ssl']['peer_certificate'];

                    $certificateFields = openssl_x509_parse($certificatePem);
                    $additionalDomains = explode(', ', $certificateFields['extensions']['subjectAltName'] ?? '');

                    $ip = inet_pton(trim(parse_url($this->nameserver, PHP_URL_HOST), '[]'));
                    if ($ip !== false) {
                        foreach ($additionalDomains as $subAltName) {
                            $subAltName = trim(strtolower($subAltName));
                            if (str_starts_with($subAltName, 'ip address:')) {
                                $compare = inet_pton(str_replace('ip address:', '', $subAltName));
                                if ($compare === $ip) {
                                    $fingerprint = openssl_x509_fingerprint($certificatePem, self::FINGERPRINT_HASH_METHOD);
                                    $browser = (new Browser(new Connector([
                                        'tcp' => [
                                            'tcp_nodelay' => true,
                                            ],
                                        'tls' => [
                                            'verify_peer_name' => false,
                                            'peer_fingerprint'=>[
                                                self::FINGERPRINT_HASH_METHOD => $fingerprint,
                                            ],
                                        ],
                                    ], $this->loop), $this->loop));
                                    $deferred->resolve($browser);
                                    return;
                                }
                            }
                        }
                    }
                    $deferred->reject(new RuntimeException('IPv6 IP Address Connection Failed. Unable to Validate Peer Certificate'));

                }, function($ex) use ($deferred) {
                    $deferred->reject(new RuntimeException('IPv6 IP Address Connection Failed. ' . $ex->getMessage()));
                });
            } else {
                $browser = (new Browser(new Connector([
                    'tcp' => [
                        'tcp_nodelay' => true,
                        ],
                    ]
                ), $this->loop));
                $deferred->resolve($browser);
            }
        }
        return $this->browserResolution;
    }
}