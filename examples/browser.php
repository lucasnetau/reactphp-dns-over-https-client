<?php declare(strict_types=1);

use EdgeTelemetrics\React\Dns\DohExecutor;
use React\Cache\ArrayCache;
use React\Dns\Query\CachingExecutor;
use React\Dns\Query\TimeoutExecutor;
use React\Dns\Resolver\Resolver;

include __DIR__ . '/../vendor/autoload.php';

$cache = new ArrayCache(256);

$executor = new TimeoutExecutor(
    new DohExecutor('1.1.1.1'),
    5.0,
);
$executor = new CachingExecutor($executor, $cache);

$resolver = new Resolver($executor);

$endpoint = 'https://raw.githubusercontent.com/lucasnetau/reactphp-dns-over-https-client/main/README.md';

$client = (new React\Http\Browser(new React\Socket\Connector([
    'tcp' => ['tcp_nodelay' => true,],
    'dns' => $resolver,
    'timeout' => 5.0,
])))->withTimeout(10.0);

$client->get($endpoint)->then(function (Psr\Http\Message\ResponseInterface $response) {
    $body = (string)$response->getBody();
    echo $body;
}, 'printf');