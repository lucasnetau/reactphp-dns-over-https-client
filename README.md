# DNS over HTTPS client for ReactPHP

Resolve DNS queries over HTTPS, provides secure DNS resolution over untrusted or shared networks (eg Serverless deployments) utilising standard HTTPS queries.

## Requirements

The package is compatible with PHP 8.0+ and requires the [react/http](https://github.com/reactphp/http) library.

## Installation

You can add the library as project dependency using [Composer](https://getcomposer.org/):

```sh
composer require edgetelemetrics/reactphp-dns-over-https-client
```

## Examples
See [/examples](/examples) directory
 * [Use DoH with ReactHTTP Client](/examples/browser.php)
 * [Use DoH to find your public IP](/examples/whats-my-ip.php)

## License

MIT, see [LICENSE file](LICENSE).

### Contributing

Bug reports (and small patches) can be submitted via the [issue tracker](https://github.com/lucasnetau/reactphp-dns-over-https-client/issues). Forking the repository and submitting a Pull Request is preferred for substantial patches.