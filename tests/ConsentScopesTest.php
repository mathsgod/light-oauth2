<?php
declare(strict_types=1);
namespace Light\OAuth2\Tests;

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use Light\OAuth2\ConsentScopes;
use Light\OAuth2\Entity\Scope;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ConsentScopesTest extends TestCase
{
    public static function invalidSelections(): array
    {
        return [[null], ['client.list'], [[]], [['unknown']], [['client.list', 'unknown']], [[['client.list']]], [['scope' => 'client.list']]];
    }

    #[DataProvider('invalidSelections')]
    public function testRejectsMissingMalformedEmptyAndUnofferedSelections(mixed $selection): void
    {
        $request = new AuthorizationRequest();
        $request->setScopes([new Scope('client.list')]);
        $this->expectException(OAuthServerException::class);
        ConsentScopes::apply($request, $selection);
    }

    public function testRetainsOfferedOrderingAndRemovesDuplicates(): void
    {
        $request = new AuthorizationRequest();
        $request->setScopes([new Scope('client.list'), new Scope('quotation.list'), new Scope('invoice.list')]);
        ConsentScopes::apply($request, ['invoice.list', 'client.list', 'invoice.list']);
        self::assertSame(['client.list', 'invoice.list'], array_map(fn($scope) => $scope->getIdentifier(), $request->getScopes()));
    }
}
