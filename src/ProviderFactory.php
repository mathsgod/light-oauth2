<?php
declare(strict_types=1);

namespace Light\OAuth2;

use Light\App;
use Light\Model\User;
use Light\OAuth2\Auth\LightPermissionProvider;
use Light\OAuth2\Contract\AuthorizationFlow;
use Light\OAuth2\Storage\PdoStore;
use PDO;

final class ProviderFactory
{
    public static function registerFromEnvironment(App $app, ?AuthorizationFlow $flow = null, ?TokenExchangePolicy $exchangePolicy = null): ?OAuthProvider
    {
        if (!filter_var($_ENV['OAUTH_ENABLED'] ?? false, FILTER_VALIDATE_BOOLEAN)) {
            return null;
        }

        $privateKey = self::keyPath('OAUTH_PRIVATE_KEY_PATH');
        $publicKey = self::keyPath('OAUTH_PUBLIC_KEY_PATH');
        $config = new Config(
            issuer: self::required('OAUTH_ISSUER'),
            resource: self::required('OAUTH_RESOURCE'),
            privateKey: 'file://' . $privateKey,
            publicKey: 'file://' . $publicKey,
            encryptionKey: self::required('OAUTH_ENCRYPTION_KEY'),
            apiResource: self::optional('OAUTH_API_RESOURCE'),
            cimdEnabled: filter_var($_ENV['OAUTH_CIMD_ENABLED'] ?? false, FILTER_VALIDATE_BOOLEAN),
            dcrEnabled: filter_var($_ENV['OAUTH_DCR_ENABLED'] ?? false, FILTER_VALIDATE_BOOLEAN),
            autoSelectScopes: filter_var($_ENV['OAUTH_AUTO_SELECT_SCOPES'] ?? false, FILTER_VALIDATE_BOOLEAN),
            authorizationUiUrl: self::optional('OAUTH_AUTHORIZATION_UI_URL'),
        );
        $exchangePolicy ??= TokenExchangePolicy::fromEnvironment($_ENV);
        $configuredScopes = self::optional('OAUTH_SCOPES');
        $scopes = $configuredScopes === null ? null : array_values(array_unique(array_filter(array_map('trim', explode(',', $configuredScopes)))));
        $app->addPermissions(['oauth_resource.list', 'oauth_resource.add', 'oauth_resource.update', 'oauth_resource.delete', 'oauth_client.list', 'oauth_client.add', 'oauth_client.update', 'oauth_client.delete']);
        $provider = new OAuthProvider(
            $config,
            new PdoStore(self::connection()),
            new LightPermissionProvider($app, $scopes),
            $flow ?? ($config->authorizationUiUrl !== null ? new FrontendAuthorizationFlow(new BrowserAuthorizationFlow($app), $config) : new BrowserAuthorizationFlow($app)),
            $exchangePolicy,
        );
        $provider->register($app, static function (string $id): ?User {
            if (!ctype_digit($id)) return null;
            $user = User::Get((int) $id);
            return $user && (int) $user->status === 0 ? $user : null;
        });
        return $provider;
    }

    /** Token exchanges must not share the ORM's persistent transaction connection. */
    public static function connection(): PDO
    {
        return new PDO(
            'mysql:host=' . self::required('DATABASE_HOSTNAME')
                . ';port=' . ($_ENV['DATABASE_PORT'] ?? '3306')
                . ';dbname=' . self::required('DATABASE_DATABASE')
                . ';charset=' . ($_ENV['DATABASE_CHARSET'] ?? 'utf8mb4'),
            self::required('DATABASE_USERNAME'),
            $_ENV['DATABASE_PASSWORD'] ?? '',
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_PERSISTENT => false],
        );
    }

    private static function required(string $name): string
    {
        $value = $_ENV[$name] ?? '';
        if (!is_string($value) || $value === '') throw new \RuntimeException("Missing {$name} configuration");
        return $value;
    }

    private static function optional(string $name): ?string
    {
        $value = $_ENV[$name] ?? null;
        if ($value === null || $value === '') return null;
        if (!is_string($value)) throw new \RuntimeException("Invalid {$name} configuration");
        return $value;
    }

    private static function keyPath(string $name): string
    {
        $path = realpath(self::required($name));
        if ($path === false || !is_readable($path)) throw new \RuntimeException("{$name} must point to a readable key file");
        return $path;
    }
}
