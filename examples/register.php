<?php
declare(strict_types=1);
use Light\App;
use Light\Model\User;
use Light\OAuth2\{Config, OAuthProvider};
use Light\OAuth2\Auth\LightPermissionProvider;
use Light\OAuth2\Storage\PdoStore;
use Light\OAuth2\Contract\AuthorizationFlow;

/**
 * Called from the application's entry point before $app->run().
 * $loginFlow must implement browser-session login, required 2FA and CSRF-protected consent.
 * Use a dedicated PDO connection for token-exchange transactions.
 */
function registerOAuth(App $app, PDO $pdo, AuthorizationFlow $loginFlow, array $settings): OAuthProvider
{
    $config = new Config(
        issuer: $settings['issuer'],
        resource: $settings['resource'],
        privateKey: $settings['private_key'],
        publicKey: $settings['public_key'],
        encryptionKey: $settings['encryption_key'],
    );
    $provider = new OAuthProvider($config, new PdoStore($pdo), new LightPermissionProvider($app, $settings['permissions']), $loginFlow);
    $provider->register($app, static function (string $id): ?User {
        if (!ctype_digit($id)) return null;
        $user = User::Get((int) $id);
        return $user && (int) $user->status === 0 ? $user : null;
    });
    return $provider;
}
