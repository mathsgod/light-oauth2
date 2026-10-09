<?php
declare(strict_types=1);
namespace Light\OAuth2\Type;
use TheCodingMachine\GraphQLite\Annotations\{Type, Field};
#[Type]
final class OAuthClientResourcePolicy
{
    #[Field]
    public string $defaultResource;
    /** @var OAuthResource[] */
    #[Field]
    public array $resources;
    public function __construct(string $defaultResource, array $resources)
    {
        $this->defaultResource = $defaultResource;
        $this->resources = array_map(fn(array $record) => new OAuthResource($record), $resources);
    }
}
