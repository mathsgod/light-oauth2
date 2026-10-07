<?php
// Separate process for the two-connection race test. Secrets stay on stdin.
require dirname(__DIR__) . '/vendor/autoload.php';
$input = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
$config = new \Light\OAuth2\Config(...$input['config']);
$store = new \Light\OAuth2\Storage\PdoStore(new PDO(getenv('OAUTH_TEST_DSN'), getenv('OAUTH_TEST_USER') ?: '', getenv('OAUTH_TEST_PASSWORD') ?: ''));
$permissions = new class implements \Light\OAuth2\Contract\PermissionProvider {
    public function scopes(): array { return ['client.list']; }
    public function can(string $userId, string $permission): bool { return $userId === '27' && $permission === 'client.list'; }
};
$flow = new class implements \Light\OAuth2\Contract\AuthorizationFlow {
    public function resolve(\Psr\Http\Message\ServerRequestInterface $request, \League\OAuth2\Server\RequestTypes\AuthorizationRequest $authorization): \Light\OAuth2\Contract\AuthorizationDecision|\Psr\Http\Message\ResponseInterface { throw new LogicException('Not used by refresh'); }
};
$provider = new \Light\OAuth2\OAuthProvider($config, $store, $permissions, $flow);
echo "ready\n";
flush();
$response = $provider->token((new \Laminas\Diactoros\ServerRequest())->withMethod('POST')->withParsedBody($input['params']));
echo json_encode(['status' => $response->getStatusCode(), 'body' => json_decode((string) $response->getBody(), true)], JSON_THROW_ON_ERROR);
