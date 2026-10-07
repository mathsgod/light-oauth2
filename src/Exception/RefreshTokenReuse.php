<?php
declare(strict_types=1);
namespace Light\OAuth2\Exception;

/** Signals that security revocation must commit even though the exchange fails. */
final class RefreshTokenReuse extends \RuntimeException {}
