<?php
declare(strict_types=1);
namespace Light\OAuth2\Tests;

use Light\App;
use Light\OAuth2\Auth\LightPermissionProvider;
use PHPUnit\Framework\TestCase;

final class LightPermissionProviderTest extends TestCase
{
    public function testScopesUseCurrentRegisteredPermissionsAndExcludeWildcards(): void
    {
        $permissions = ['user.list', '*', 'user.*', 'user.list', 'role.list', '', 'bad scope'];
        $app = $this->createStub(App::class);
        $app->method('getPermissions')->willReturnCallback(static function () use (&$permissions): array { return $permissions; });
        $provider = new LightPermissionProvider($app);
        self::assertSame(['role.list', 'user.list'], $provider->scopes());
        $permissions[] = 'invoice.list';
        self::assertSame(['invoice.list', 'role.list', 'user.list'], $provider->scopes());
    }
    public function testOptionalAllowlistCannotExposeUnregisteredPermissions(): void
    {
        $app = $this->createStub(App::class);
        $app->method('getPermissions')->willReturn(['user.list', 'role.list']);
        $provider = new LightPermissionProvider($app, ['user.list', 'missing.list', '*']);
        self::assertSame(['user.list'], $provider->scopes());
        self::assertFalse($provider->can('27', 'role.list'));
        self::assertFalse($provider->can('27', 'missing.list'));
    }
    public function testExplicitEmptyAllowlistExposesNothing(): void
    {
        $app = $this->createStub(App::class);
        $app->method('getPermissions')->willReturn(['user.list']);
        self::assertSame([], (new LightPermissionProvider($app, []))->scopes());
    }
}
