<?php declare(strict_types=1);

use EdgeTelemetrics\React\Dns\DohExecutor;
use React\Dns\Query\TimeoutExecutor;
use React\Dns\Resolver\Resolver;

include __DIR__ . '/../vendor/autoload.php';

$executor = new TimeoutExecutor(
    new DohExecutor('doh.opendns.com'),
    5.0,
);

$resolver = new Resolver($executor);

$resolver->resolve('myip.opendns.com')->then(function($ip) {
    echo 'Your IP is ' . $ip . PHP_EOL;
}, 'printf');


