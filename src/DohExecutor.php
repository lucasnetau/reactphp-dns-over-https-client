<?php declare(strict_types=1);

namespace EdgeTelemetrics\React\Dns;

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
use React\Socket\Connector;
use RuntimeException;

class DohExecutor implements ExecutorInterface {

    private $nameserver;
    private $loop;
    private $parser;
    private $dumper;

    private $method;

    private $browser;

    const METHOD_GET = 'get';
    const METHOD_POST = 'post';

    /**
     * @param string         $nameserver
     * @param ?LoopInterface $loop
     */
    public function __construct($nameserver, $method, LoopInterface $loop = null)
    {
        if (!class_exists('\React\Http\Browser')) {
            throw new RuntimeException('DNS over HTTPS support requires reactphp/http library'); //@codeCoverageIgnore
        }

        if (!str_contains($nameserver, '[') && \substr_count($nameserver, ':') >= 2 && !str_contains($nameserver, '://')) {
            // several colons, but not enclosed in square brackets => enclose IPv6 address in square brackets
            $nameserver = '[' . $nameserver . ']';
        }

        $parts = \parse_url((!str_contains($nameserver, '://') ? 'https://' : '') . $nameserver);
        if (!isset($parts['scheme'], $parts['host']) || $parts['scheme'] !== 'https' || @\inet_pton(\trim($parts['host'], '[]')) === false) {
            throw new \InvalidArgumentException('Invalid nameserver address given');
        }

        $method = \strtolower($method);
        if (!in_array($method, [self::METHOD_GET, self::METHOD_POST], true)) {
            throw new \InvalidArgumentException('Invalid HTTP request method given');
        }

        $this->nameserver = 'https://' . $parts['host'] . ':' . ($parts['port'] ?? 443 . '/dns-query');
        $this->loop = $loop ?: Loop::get();
        $this->parser = new Parser();
        $this->dumper = new BinaryDumper();
        $this->method = $method;
        $this->browser = (new Browser(new Connector(['tcp_nodelay' => true,]), $this->loop));
    }

    public function query(Query $query)
    {
        $request = Message::createRequestForQuery($query);

        $queryData = $this->dumper->toBinary($request);
        $length = \strlen($queryData);

        if ($length > 0xffff) {
            return Promise\reject(new \RuntimeException(
                'DNS query for ' . $query->describe() . ' failed: Query too large for HTTPS transport'
            ));
        }

        if ($this->method === self::METHOD_GET) {
            $requestUrl = $this->nameserver . '?' . http_build_query(['dns' => $this->urlsafeBase64($queryData)]);
            $request = $this->browser->get($requestUrl);
        } else {
            $requestUrl = $this->nameserver;
            $request = $this->browser->post($requestUrl, [
                'accept' => 'application/dns-message',
                'content-type' => 'application/dns-message'
            ], $queryData);
        }

        return $request->then(function (ResponseInterface $response) {
            $response = $this->parser->parseMessage((string)$response->getBody());
            return Promise\resolve($response);
        }, function (\Exception $e) use ($query) {
            return Promise\reject(new \RuntimeException(
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
            return sodium_bin2base64($data, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } else {
            return rtrim( strtr( base64_encode( $data ), '+/', '-_'), '=');
        }
        //@codeCoverageIgnoreEnd
    }
}