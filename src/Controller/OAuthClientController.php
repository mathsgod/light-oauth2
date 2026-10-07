<?php
declare(strict_types=1);
namespace Light\OAuth2\Controller;
use Light\OAuth2\Management\ClientManager;
use Light\OAuth2\Input\OAuthClientInput;
use Light\OAuth2\Type\{OAuthClient, OAuthClientSaved};
use TheCodingMachine\GraphQLite\Annotations\{Query, Mutation, Logged, Right};

final class OAuthClientController implements \Light\GraphQL\ExplicitController
{
    public function __construct(private ClientManager $manager) {}

    /** @return OAuthClient[] */
    #[Query, Logged, Right('oauth_client.list')]
    public function oauthClients(): array { return $this->manager->clients(); }

    /** @return string[] */
    #[Query, Logged, Right('oauth_client.list')]
    public function oauthClientScopes(): array { return $this->manager->scopes(); }

    #[Mutation, Logged, Right('oauth_client.add')]
    public function createOAuthClient(OAuthClientInput $input): OAuthClientSaved { return $this->manager->save($input, true); }

    #[Mutation, Logged, Right('oauth_client.update')]
    public function updateOAuthClient(OAuthClientInput $input): OAuthClientSaved { return $this->manager->save($input, false); }

    #[Mutation, Logged, Right('oauth_client.update')]
    public function resetOAuthClientSecret(string $id): string { return $this->manager->resetSecret($id); }

    #[Mutation, Logged, Right('oauth_client.delete')]
    public function deleteOAuthClient(string $id): bool { return $this->manager->delete($id); }
}
