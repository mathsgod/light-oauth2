<?php
declare(strict_types=1);
namespace Light\OAuth2\Contract;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
interface AuthorizationFlow
{
    /**
     * Render login/2FA/consent or return an authenticated decision.
     * The application must bind the pending request to the browser session,
     * validate consent POST CSRF, and only approve after required 2FA.
     * When AutomaticScopes is present as a request attribute, call select()
     * with the authenticated user before displaying consent and on approval.
     * Bind the displayed scope identifiers to the pending consent; if they
     * change, render consent again instead of approving unseen permissions.
     */
    public function resolve(ServerRequestInterface $request, AuthorizationRequest $authorization): AuthorizationDecision|ResponseInterface;
}
