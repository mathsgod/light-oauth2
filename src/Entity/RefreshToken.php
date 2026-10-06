<?php
declare(strict_types=1);
namespace Light\OAuth2\Entity;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\{EntityTrait, RefreshTokenTrait};
final class RefreshToken implements RefreshTokenEntityInterface { use EntityTrait, RefreshTokenTrait; }
