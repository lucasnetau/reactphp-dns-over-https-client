<?php declare(strict_types=1);

namespace EdgeTelemetrics\React\Dns\Tests;

use EdgeTelemetrics\React\Dns\DohExecutor;
use PHPUnit\Framework\TestCase;
use React\Dns\Model\Message;
use React\Dns\Query\Query;
use React\EventLoop\Loop;

/**
 * Functional Tests
 */
class FunctionalTest extends TestCase
{
    public function testResolveCloudflareViaPostResolves()
    {
        $executor = new DohExecutor('https://1.1.1.1/dns-query', DohExecutor::METHOD_POST);
        $query = new Query('one.one.one.one', Message::TYPE_A, Message::CLASS_IN);
        $promise = $executor->query($query);

        $answer = null;
        $promise->then(function ($message) use (&$answer) {
            $answer = $message;
        });

        Loop::run();

        $this->assertNotNull($answer);
        $this->assertEquals(Message::RCODE_OK, $answer->rcode);
    }

    public function testResolveCloudflareViaGetResolves()
    {
        $executor = new DohExecutor('https://1.1.1.1/dns-query',DohExecutor::METHOD_GET);
        $query = new Query('one.one.one.one', Message::TYPE_A, Message::CLASS_IN);
        $promise = $executor->query($query);

        $answer = null;
        $promise->then(function ($message) use (&$answer) {
            $answer = $message;
        });

        Loop::run();

        $this->assertNotNull($answer);
        $this->assertEquals(Message::RCODE_OK, $answer->rcode);
    }

    public function testResolveCloudflareHostnameViaGetResolves()
    {
        $executor = new DohExecutor('https://one.one.one.one/dns-query',DohExecutor::METHOD_GET);
        $query = new Query('one.one.one.one', Message::TYPE_A, Message::CLASS_IN);
        $promise = $executor->query($query);

        $answer = null;
        $promise->then(function ($message) use (&$answer) {
            $answer = $message;
        });

        Loop::run();

        $this->assertNotNull($answer);
        $this->assertEquals(Message::RCODE_OK, $answer->rcode);
    }

    public function testResolveSecondQueryReusesConnection()
    {
        $executor = new DohExecutor('https://one.one.one.one/dns-query');
        $query = new Query('one.one.one.one', Message::TYPE_A, Message::CLASS_IN);
        $promise1 = $executor->query($query);
        $promise2 = $executor->query($query);

        $answer = null;
        $promise1->then(function ($message) use (&$answer) {
            $answer = $message;
        });

        $promise2->then(function ($message) use (&$answer) {
            $answer = $message;
        });

        Loop::run();

        $this->assertNotNull($answer);
        $this->assertEquals(Message::RCODE_OK, $answer->rcode);
    }

    public function testResolveInvalidRejects()
    {
        $executor = new DohExecutor('https://1.1.1.1/dns-query');
        $query = new Query('example.invalid', Message::TYPE_A, Message::CLASS_IN);
        $promise = $executor->query($query);

        $answer = null;
        $promise->then(function ($message) use (&$answer) {
            $answer = $message;
        });

        Loop::run();

        $this->assertNotNull($answer);
        $this->assertEquals(Message::RCODE_NAME_ERROR, $answer->rcode);
    }

    public function testResolveToInvalidServerRejects()
    {
        $executor = new DohExecutor('https://127.0.0.1:0/dns-query');
        $query = new Query('google.com', Message::TYPE_A, Message::CLASS_IN);
        $promise = $executor->query($query);

        $exception = null;
        $promise->then(null, function ($reason) use (&$exception) {
            $exception = $reason;
        });

        Loop::run();

        $this->assertNotNull($exception);
        $this->assertInstanceOf(\RuntimeException::class, $exception);
        $this->assertStringStartsWith('DNS query for ' . $query->name . ' (A) failed: ', $exception->getMessage());
    }

    public function testQueryRejectsIfMessageExceedsMaximumMessageSize()
    {
        $executor = new DohExecutor('https://127.0.0.1:0/dns-query');

        $query = new Query('google.' . str_repeat('.com', 60000), Message::TYPE_A, Message::CLASS_IN);
        $promise = $executor->query($query);

        $exception = null;
        $promise->then(null, function ($reason) use (&$exception) {
            $exception = $reason;
        });

        Loop::run();

        /** @var \RuntimeException $exception */
        $this->assertInstanceOf('RuntimeException', $exception);
        $this->assertStringStartsWith('DNS query for '. $query->name . ' (A) failed: Query too large for HTTPS transport', $exception->getMessage());
    }

    public function testResolveViaInvalidHttpMethodThrows()
    {
        $this->expectException(\InvalidArgumentException::class);

        new DohExecutor('https://1.1.1.1/dns-query', 'put');
    }

    public function testInvalidNameserverThrows()
    {
        $this->expectException(\InvalidArgumentException::class);

        new DohExecutor('http://1.1.1.1/dns-query');
    }
}
