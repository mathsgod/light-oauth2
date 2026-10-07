<?php
declare(strict_types=1);
namespace Light\OAuth2\Input;
use TheCodingMachine\GraphQLite\Annotations\{Input, Field};

#[Input]
final class OAuthClientInput
{
    #[Field]
    public string $id;
    #[Field]
    public string $name;
    /** @var string[] */
    #[Field]
    public array $redirectUris;
    /** @var string[] */
    #[Field]
    public array $scopes;
    #[Field]
    public bool $confidential;
    #[Field]
    public bool $enabled;
}
