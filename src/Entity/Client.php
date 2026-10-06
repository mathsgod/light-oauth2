<?php
declare(strict_types=1);
namespace Light\OAuth2\Entity;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\Traits\{EntityTrait, ClientTrait};
final class Client implements ClientEntityInterface
{
    use EntityTrait, ClientTrait;
    public function __construct(public readonly array $record)
    {
        $this->setIdentifier($record['id']);
        $this->name = $record['name'];
        $this->redirectUri = $record['redirect_uris'];
        $this->isConfidential = $record['confidential'];
    }
}
