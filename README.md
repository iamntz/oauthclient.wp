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

After you init the class, you can make the auth process:

```
$client->getToken()
```
Will give you an array with either `ok` on the `status` key and a permanent token, or a `request` on the `status` key with a `redirect` value to start the auth process.

Once you're auth-ed, you can start making calls, e.g.:

```
 $client->api('wp/v2/users/me');
```

#### A word about `hashValidator`
If you're using a simple set-up like one server+one client, this shouldn't worry you too much, because you can set a certain „blessed” domain and that's that. But how do you deal with a multi-client set-up? I took a look at a different systems, and I decided that the best way is to use a common secret passphrase that will be used on all servers; one you could define on either `wp-config.php` (via a constant), or via an option field.

Here is how you can do it via `wp-config.php` (added on both server **AND** client!):

```
define('OAUTH_SECRET_KEY', 'KH1tgux%14CJ9tUi*TN5faZrj@!5l1N1h$U*G^4+Vfs(BJVKSO');
```

Then you can write a small function that will also be used on both server AND client:

```
function hashValidator($str) {
  $string = implode('|', [OAUTH_SECRET_KEY, $message]);
  return hash_hmac('sha1', $string, OAUTH_SECRET_KEY);
}
```

Having this in place, is time to whitelist signed domains. To do so, we will use several methods:

```
function getDomainSignature()
{
  return isset($_REQUEST['my_namespace_hash']) ? sanitize_text_field(wp_unslash($_REQUEST['my_namespace_hash'])) : '';
}

function maybeWhitelistDomain($valid)
{
  if (OAUTH_SECRET_KEY === getDomainSignature()) {
    return true;
  }

  return $valid;
}

function whietlistField($consumer)
{
  printf('<input type="hidden" name="my_namespace_hash" value="%s">', esc_attr(getDomainSignature()));
}

add_filter('rest_oauth.check_callback', 'maybeWhitelistDomain');
add_action('oauth1_authorize_form', 'whietlistField');
```

Yes, the `my_namespace` part should be the same as in the previous section!


#### A word about `POST`ing data
The current implementation of the OAuth plugin doesn't respect the oauth standard, so all `$_POST` data is counted when signing requests. At this moment there is [PR opened](https://github.com/WP-API/OAuth1/pull/206), so you will need to either use @tsmd's version or make the required changes all by yourself.


## Like it?

You can get [hosting](https://m.do.co/c/c95a44d0e992), [donate](https://www.paypal.me/iamntz) or buy me a [gift](http://iamntz.com/wishlist).

## License

MIT.
