<?php
declare(strict_types=1);
namespace Light\OAuth2\Type;
use TheCodingMachine\GraphQLite\Annotations\{Type, Field};

#[Type]
final class OAuthClientSaved
{
    public function __construct(
        #[Field] public OAuthClient $client,
        #[Field] public ?string $secret,
    ) {}
}
