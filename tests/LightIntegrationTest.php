<?php
declare(strict_types=1);
namespace Light\OAuth2\Tests;
use PHPUnit\Framework\TestCase;
use Light\App;
use Light\OAuth2\Auth\{OAuthService, TokenContext};
use Light\OAuth2\Contract\PermissionProvider;
use Laminas\Diactoros\{ServerRequest, Response};
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\{ServerRequestInterface, ResponseInterface};
final class LightIntegrationTest extends TestCase
{
    public function testOAuthServiceUsesUserAndTokenScope(): void
    {
        $app = (new \ReflectionClass(App::class))->newInstanceWithoutConstructor();
        $user = (new \ReflectionClass(\Light\Model\User::class))->newInstanceWithoutConstructor();
        $permissions = new class implements PermissionProvider {
            public bool $allowed = true;
            public function scopes(): array { return ['client.list', 'client.edit']; }
            public function can(string $userId, string $permission): bool { return $this->allowed; }
        };
        $request = (new ServerRequest())->withAttribute(App::class, $app);
        $service = new OAuthService($request, new TokenContext('27', 'codex', 'id', ['client.list']), $permissions, fn() => $user);
        self::assertTrue($service->isLogged());
        self::assertSame($user, $service->getUser());
        self::assertTrue($service->isAllowed('client.list'));
        self::assertFalse($service->isAllowed('client.edit'));
        $permissions->allowed = false;
        self::assertFalse($service->isAllowed('client.list'));
        $invalid = new OAuthService($request, null, $permissions, fn() => $user);
        self::assertFalse($invalid->isLogged());
    }
    public function testLightRouterExtensionAndInvalidAuthFactory(): void
    {
        if (!method_exists(App::class, 'setAuthServiceFactory')) self::markTestSkipped('Set LIGHT_SOURCE_PATH to patched Light checkout');
        $app = (new \ReflectionClass(App::class))->newInstanceWithoutConstructor();
        $router = new \League\Route\Router();
        $server = $this->createStub(\Light\Server::class);
        $server->method('getRouter')->willReturn($router);
        (new \ReflectionProperty(App::class, 'server'))->setValue($app, $server);
        self::assertSame($router, $app->getRouter());
        $router->map('GET', '/oauth/authorize', fn() => new Response());
        self::assertSame(200, $router->dispatch((new ServerRequest())->withMethod('GET')->withUri(new \Laminas\Diactoros\Uri('https://example.com/oauth/authorize')))->getStatusCode());
        $app->setAuthServiceFactory(fn() => new \stdClass());
        $handler = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface { return new Response(); }
        };
        $this->expectException(\UnexpectedValueException::class);
        $app->process((new ServerRequest())->withParsedBody(['test' => true]), $handler);
    }
}
