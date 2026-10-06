<?php
declare(strict_types=1);
namespace Light\OAuth2\Entity;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
final class User implements UserEntityInterface
{
    use EntityTrait;
    public function __construct(string $id) { $this->setIdentifier($id); }
}
