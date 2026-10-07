<?php
declare(strict_types=1);
namespace Light\OAuth2\Type;
use TheCodingMachine\GraphQLite\Annotations\{Type, Field};

#[Type]
final class OAuthClient
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

    public function __construct(array $record)
    {
        $this->id = $record['id'];
        $this->name = $record['name'];
        $this->redirectUris = $record['redirect_uris'];
        $this->scopes = $record['scopes'];
        $this->confidential = $record['confidential'];
        $this->enabled = $record['enabled'];
    }
}
