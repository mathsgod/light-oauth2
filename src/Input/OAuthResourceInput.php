<?php
declare(strict_types=1);
namespace Light\OAuth2\Input;
use TheCodingMachine\GraphQLite\Annotations\{Input, Field};
#[Input]
final class OAuthResourceInput
{
    #[Field]
    public string $id;
    #[Field]
    public string $name;
    /** @var string[] */
    #[Field]
    public array $scopes;
    #[Field]
    public bool $enabled;
}
