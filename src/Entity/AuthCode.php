<?php
declare(strict_types=1);
namespace Light\OAuth2\Entity;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\Traits\{EntityTrait, TokenEntityTrait, AuthCodeTrait};
final class AuthCode implements AuthCodeEntityInterface { use EntityTrait, TokenEntityTrait, AuthCodeTrait; }
