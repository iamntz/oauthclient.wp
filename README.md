## What is this?

A class that will help you to connect with the WP REST Api over oAuth 1.0a authentification. It requires [OAuth1](https://oauth1.wp-api.org/) plugin to be installed.

## Installing

```
composer require iamntz/oauthclient.wp
```

## Using


```
$client = new \iamntz\oauthClient\OauthClientWP([
  'url' => $restEndpoint,
  'secret' => 'my-wp-secret',
  'key' => 'my-wp-key',
]);

$client->setNamespace('my_namespace');
$client->setCallbackUrl(add_query_arg('my_namespace_oauth_callback', 1, home_url('/')));
$client->setCallbackHashValidator('hashValidator');
```

#### A word about `hashValidator`
todo

#### A word about `POST`ing data
The current implementation of the OAuth plugin doesn't respect the oauth standard, so all `$_POST` data is counted when signing requests. At this moment there is [PR opened](https://github.com/WP-API/OAuth1/pull/206), so you will need to either use @tsmd's version or make the required changes all by yourself.


## Like it?

You can get [hosting](https://m.do.co/c/c95a44d0e992), [donate](https://www.paypal.me/iamntz) or buy me a [gift](http://iamntz.com/wishlist).

## License

MIT.
