<?php declare(strict_types=1);

namespace EdgeTelemetrics\React\Dns\Tests;

use EdgeTelemetrics\React\Dns\DohExecutor;
use PHPUnit\Framework\TestCase;
use React\Dns\Model\Message;
use React\Dns\Query\Query;
use React\EventLoop\Loop;

/**
 * IPv6 Tests
 */
class IPv6Test extends TestCase
{
    protected function setUp(): void
    {
        if (!(defined("AF_INET6") && @\stream_socket_client('udp://[::1]:8888') !== false)) {
            $this->markTestSkipped('IPv6 Unavailable');
        }
        $context = stream_context_create();
        stream_context_set_option($context, 'ssl', 'verify_host', false);
        stream_context_set_option($context, 'ssl', 'verify_peer_name', false);

        $dns = 'tls://[2001:4860:4860::8888]:443';

        $socket = @\stream_socket_client($dns, $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $context);
        if ($socket === false) {
            $this->markTestSkipped('IPv6 not routable');
        }
    }

    public function testResolveGoogleViaIPv6HostResolves()
    {
        $executor = new DohExecutor('https://dns64.dns.google/dns-query');
        $query = new Query('google.com', Message::TYPE_A, Message::CLASS_IN);
        $promise = $executor->query($query);

        $answer = null;
        $exception = null;
        $promise->then(function ($message) use (&$answer) {
            $answer = $message;
        }, function($reason) use (&$exception) {
            $exception = $reason;
        });

        Loop::run();

        $this->assertNull($exception);
        $this->assertNotNull($answer);
        $this->assertEquals(Message::RCODE_OK, $answer->rcode);
    }

    public function testResolveGoogleViaIPv6IpResolves()
    {
        $executor = new DohExecutor('https://[2001:4860:4860::8888]/dns-query');
        $query = new Query('google.com', Message::TYPE_A, Message::CLASS_IN);
        $promise = $executor->query($query);

        $answer = null;
        $exception = null;
        $promise->then(function ($message) use (&$answer) {
            $answer = $message;
        }, function($reason) use (&$exception) {
            $exception = $reason;
        });

        Loop::run();

        $this->assertNull($exception);
        $this->assertNotNull($answer);
        $this->assertEquals(Message::RCODE_OK, $answer->rcode);
    }
}
