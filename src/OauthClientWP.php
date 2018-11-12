<?php

namespace iamntz\oauthClient;

class OauthClientWP
{
	/**
	 * Namespace under which the caching and all storage is kept
	 *
	 * @var string
	 */
	private $namespace;

	/**
	 * Optional callback URL to redirect after last step of auth
	 *
	 * @var string
	 */
	private $callbackUrl;

	public function __construct(array $options)
	{
		if (empty($options['url']) || empty($options['key']) || empty($options['secret'])) {
			throw new \Exception('Url Endpoint, Cabllback, Auth Key or Auth Secret is missing!', 1);
		}

		/**
		 * Hash all options in order to cache everything in an unique way.
		 *
		 * @var string
		 */
		$this->hashed = substr(sha1(serialize($options)), 0, 10);

		$this->url = $options['url'];
		$this->key = $options['key'];
		$this->secret = $options['secret'];
		$this->userID = $options['userID'] ?? get_current_user_id();
	}

	/**
	 * Set Namespaces
	 *
	 * @method setNamespace
	 *
	 * @param  string       $namespace
	 */
	public function setNamespace($namespace)
	{
		$this->namespace = $namespace;
	}

	/**
	 * Set Callback URL
	 *
	 * @method setCallbackUrl
	 *
	 * @param  string         $url
	 */
	public function setCallbackUrl($url)
	{
		$this->callbackUrl = $url;
	}

	/**
	 * Set the hash method for the callback url. This should be implemented exactly the same on the
	 * both server AND client
	 *
	 * @method setCallbackHashValidator
	 *
	 * @param  function                   $callback
	 */
	public function setCallbackHashValidator($callback)
	{
		$this->callbackHashValidator = $callback;
	}

	/**
	 * Gets the oAuth endpoints
	 *
	 * @method authEndpoints
	 *
	 * @param  string        $endpoint request|authorize|access
	 *
	 * @return string
	 */
	public function authEndpoints($endpoint)
	{
		$discovered = get_transient("{$this->namespace}_oauth_{$this->hashed}");

		if (!$discovered) {
			$request = wp_remote_get($this->url);
			$body = json_decode(wp_remote_retrieve_body($request));
			if (isset($body->authentication->oauth1)) {
				$discovered = $body->authentication->oauth1;
				set_transient("{$this->namespace}_oauth_{$this->hashed}", $discovered, DAY_IN_SECONDS);
			}
		}

		if (!is_null($endpoint) && isset($discovered->{$endpoint})) {
			return $discovered->{$endpoint};
		}

		throw new \Exception("Invalid endpoint . {$endpoint}", 1);
	}

	/**
	 * Gets the callback url
	 *
	 * @method getCallbackUrl
	 *
	 * @return string
	 */
	private function getCallbackUrl()
	{
		return $this->callbackUrl;
	}

	/**
	 * Transient utility to store various token steps
	 *
	 * @method transient
	 *
	 * @param  string    $action get|set|delete
	 * @param  string    $key    the transient key
	 * @param  mixed     $value
	 *
	 * @return boolean
	 */
	private function transient($action, $key, $value = null)
	{
		$key = "{$this->namespace}_oauth_token_{$this->userID}" . $key;

		switch ($action) {
			case 'get':
				return get_transient($key);
				break;

			case 'set':
				return set_transient($key, $value, 600);
				break;

			case 'delete':
				return delete_transient($key);
				break;

			default:
				throw new \Exception("Invalid transient action", 1);
				break;
		}
	}

	/**
	 * User Meta utility to store permanent token
	 *
	 * @method tokenStorage
	 *
	 * @param  string    $action get|set
	 * @param  mixed     $value
	 *
	 * @return boolean
	 */
	private function tokenStorage($action = 'get', $value = null)
	{
		$key = "{$this->namespace}_oauth_token";

		switch ($action) {
			case 'get':
				return get_user_meta($this->userID, $key, true);
				break;

			case 'set':
				return update_user_meta($this->userID, $key, $value);
				break;

			case 'clear':
				return delete_user_meta($this->userID, $key);
				break;

			default:
				throw new \Exception("Invalid action", 1);
				break;
		}
	}

	/**
	 * Add oAuth callback & sign to an URL
	 *
	 * @method addOauthArgsToUrl
	 *
	 * @param  string            $url
	 */
	private function addOauthArgsToUrl($url)
	{
		if (!is_callable($this->callbackHashValidator)) {
			return;
		}

		return add_query_arg(
			[
				'oauth_callback' => urlencode($this->getCallbackUrl()),
				"{$this->namespace}_hash" => call_user_func($this->callbackHashValidator, $this->getCallbackUrl()),
			], $url);
	}

	/**
	 * Signing the auth headers
	 *
	 * @method sign
	 *
	 * @param  string $url
	 * @param  array $params
	 * @param  array $token the token received during/after the auth process
	 * @param  string $method
	 *
	 * @return string
	 */
	private function sign($url, $params, $token = null, $method = 'POST')
	{
		$url = parse_url($url);

		$endpoint = "{$url['scheme']}://{$url['host']}{$url['path']}";

		$signKey = rawurlencode($this->secret) . '&';

		if (is_null($token)) {
			$token = $this->transient('get', 'request_token');
			$this->transient('delete', 'request_token');
		}

		if (!empty($token['oauth_token_secret'])) {
			$signKey .= $token['oauth_token_secret'];
		}

		$data = $this->parseSignedData($url, $params);

		$string = $method . '&' . rawurlencode($endpoint) . '&' . rawurlencode(implode('&', $data));

		return base64_encode(hash_hmac('sha1', $string, $signKey, true));
	}

	/**
	 * Parse signature parameters so we move them out from the URL
	 *
	 * @method parseSignedData
	 *
	 * @param  array          $url
	 * @param  array          $params
	 *
	 * @return array
	 */
	private function parseSignedData($url, $params)
	{
		$data = [];

		if (!empty($url['query'])) {
			parse_str($url['query'], $getParams);
			$params = array_merge($getParams, $params);
		}

		foreach ($params as $key => $value) {
			$data[rawurlencode($key)] = rawurlencode($value);
		}

		ksort($data);
		array_walk($data, function (&$value, $key) {
			$value = $key . '=' . $value;
		});

		return $data;
	}

	/**
	 * Gets the authentification headers
	 *
	 * @method getAuthHeaders
	 *
	 * @param  string         $endpoint
	 * @param  array          $extraParams Additional parameters if needed
	 * @param  array          $token       the token received _after_ the auth process
	 * @param  string         $method
	 *
	 * @return string
	 */
	private function getAuthHeaders($endpoint, $extraParams = [], $token = null, $method = 'POST')
	{
		// The order of these parameters is important!
		$parameters = array_merge([
			'oauth_consumer_key' => $this->key,
			'oauth_nonce' => md5(mt_rand()),
			'oauth_signature_method' => 'HMAC-SHA1',
			'oauth_timestamp' => time(),
		], $extraParams);

		$parameters['oauth_version'] = '1.0';

		$parameters['oauth_signature'] = $this->sign($endpoint, $parameters, $token, $method);

		$parameters = http_build_query($parameters, '', ', ', PHP_QUERY_RFC3986);

		return "OAuth $parameters";
	}

	/**
	 * Generates the request-token url (step 1&2 of the oAuth process)
	 *
	 * @method getRequestToken
	 *
	 * @return string
	 */
	private function getRequestToken()
	{
		$this->transient('delete', 'request_token');

		$requestToken = wp_remote_post($this->authEndpoints('request'), [
			'headers' => [
				'Authorization' => $this->getAuthHeaders($this->authEndpoints('request')),
			],
		]);

		$response = wp_remote_retrieve_body($requestToken);

		if ($response) {
			parse_str($response, $parsed);
			$this->transient('set', 'request_token', $parsed);
			//  TODO: deal with non-mod_rewrite urls?
			$response = $this->authEndpoints('authorize') . '?' . $response;
			$response = $this->addOauthArgsToUrl($response);
		}

		return $response;
	}

	/**
	 * Fetch the permanent oAuth tokens (3rd step of the oAuth process)
	 *
	 * @method getAuthToken
	 *
	 * @param  string        $token
	 * @param  string        $verifier
	 *
	 * @return string
	 */
	private function getAuthToken($token, $verifier)
	{
		$requestToken = wp_remote_post($this->authEndpoints('access'), [
			'headers' => [
				'Authorization' => $this->getAuthHeaders($this->authEndpoints('access'), [
					'oauth_token' => $token,
					'oauth_verifier' => $verifier,
				]),
			],
		]);

		return wp_remote_retrieve_body($requestToken);
	}

	/**
	 * Save the long-term token
	 *
	 * @method refreshTokens
	 *
	 * @param  string        $token
	 * @param  string        $verifier
	 *
	 * @return array
	 */
	private function refreshTokens($token, $verifier)
	{
		$token = $this->getAuthToken($token, $verifier);
		parse_str($token, $parsed);

		if (!empty($parsed['oauth_token'])) {
			$parsed['last_check'] = time();
			$this->tokenStorage('set', $parsed);
			return [
				'status' => 'access',
				'redirect' => $this->getCallbackUrl(),
				'token' => $parsed,
			];
		}
	}

	/**
	 * Convert key/value array to a urlencoded string
	 *
	 * @method parsePayload
	 *
	 * @param  array       $payload
	 *
	 * @return string
	 */
	private function parsePayload(array $payload)
	{
		$parsed = [];
		foreach ($payload as $key => $value) {
			$parsed[] = "{$key}=" . rawurlencode($value);
		}

		return implode('&', $parsed);
	}

	/**
	 * Get an user token
	 *
	 * @method getToken
	 *
	 * @return array
	 */
	public function getToken()
	{
		$token = $this->tokenStorage();

		if ($token && isset($token['last_check'])) {
			if (time() - $token['last_check'] >= DAY_IN_SECONDS / 2) {
				$this->refreshTokens($token['oauth_token'], $token['oauth_token_secret']);
			}

			return [
				'status' => 'ok',
				'token' => $token,
			];
		}

		if (isset($_GET['oauth_token']) && isset($_GET['oauth_verifier'])) {
			return $this->refreshTokens($_GET['oauth_token'], $_GET['oauth_verifier']);
		}

		return [
			'status' => 'request',
			'redirect' => $this->getRequestToken(),
		];
	}

	/**
	 * Clear the user token
	 *
	 * @return     boolean
	 */
	public function clearToken(){
		return $this->tokenStorage('clear');
	}

	public function api($endpoint, $method = 'get', $params = [], $hasAuth = true)
	{
		$auth = $this->getToken();
		$method = strtoupper($method);

		if ($auth['status'] != 'ok' && !empty($auth['redirect'])) {
			return $auth;
		}

		$url = $this->url . $endpoint;

		$headers = [];
		$args = [
			'method' => $method,
		];

		if (!empty($params) && in_array($method, ['POST', 'PUT'])) {
			$headers['content-type'] = 'application/json; charset=utf-8';
			$args['body'] = json_encode($params);
		} else {
			$url .= '?' . $this->parsePayload($params);
		}

		if ($hasAuth) {
			$headers['Authorization'] = $this->getAuthHeaders($url, [
				'oauth_token' => $auth['token']['oauth_token'],
				'oauth_verifier' => $auth['token']['oauth_token_secret'],
			], $auth['token'], $method);
		}

		$args['headers'] = $headers;
		$args['timeout'] = 60000;

		$request = wp_remote_request($url, $args);

		return wp_remote_retrieve_body($request);
	}
}
