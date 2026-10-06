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
     */
    public function resolve(ServerRequestInterface $request, AuthorizationRequest $authorization): AuthorizationDecision|ResponseInterface;
}
