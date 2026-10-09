<?php
declare(strict_types=1);
namespace Light\OAuth2\Controller;
use Light\OAuth2\Management\ResourceManager;
use Light\OAuth2\Input\OAuthResourceInput;
use Light\OAuth2\Type\OAuthResource;
use TheCodingMachine\GraphQLite\Annotations\{Query, Mutation, Logged, Right};
final class OAuthResourceController implements \Light\GraphQL\ExplicitController
{
    public function __construct(private ResourceManager $manager) {}
    /** @return OAuthResource[] */
    #[Query, Logged, Right('oauth_resource.list')]
    public function oauthResources(): array { return $this->manager->resources(); }
    /** @return string[] */
    #[Query, Logged, Right('oauth_resource.list')]
    public function oauthResourceScopes(): array { return $this->manager->scopes(); }
    #[Mutation, Logged, Right('oauth_resource.add')]
    public function createOAuthResource(OAuthResourceInput $input): OAuthResource { return $this->manager->save($input, true); }
    #[Mutation, Logged, Right('oauth_resource.update')]
    public function updateOAuthResource(OAuthResourceInput $input): OAuthResource { return $this->manager->save($input, false); }
    #[Mutation, Logged, Right('oauth_resource.delete')]
    public function deleteOAuthResource(string $id): bool { return $this->manager->delete($id); }
}
