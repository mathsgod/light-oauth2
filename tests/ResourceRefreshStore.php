<?php
declare(strict_types=1);
namespace Light\OAuth2\Tests;
/** Shared contract for fault-injection stores that omit optional client management. */
interface ResourceRefreshStore extends \Light\OAuth2\Contract\RefreshTokenStore, \Light\OAuth2\Contract\ResourceStore {}
