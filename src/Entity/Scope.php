<?php
declare(strict_types=1);
namespace Light\OAuth2\Entity;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\{EntityTrait, ScopeTrait};
final class Scope implements ScopeEntityInterface
{
    use EntityTrait, ScopeTrait;
    public function __construct(string $id) { $this->setIdentifier($id); }
}
