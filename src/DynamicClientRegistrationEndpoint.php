<?php
declare(strict_types=1);
namespace Light\OAuth2;

use Laminas\Diactoros\Response\JsonResponse;
use Light\OAuth2\Contract\{ClientStore, PermissionProvider};
use Light\OAuth2\Storage\ClientRegistration;
use Psr\Http\Message\{ServerRequestInterface, ResponseInterface};

/** RFC 7591 open registration profile for public authorization-code clients. */
final class DynamicClientRegistrationEndpoint
{
    private const MAX_BYTES = 16384;
    public function __construct(private ClientStore $store, private PermissionProvider $permissions, private ?ResourceRegistry $registry = null) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        if ($request->getMethod() !== 'POST') {
            return $this->error('invalid_client_metadata', 'Registration requires POST.', 405)->withHeader('Allow', 'POST');
        }
        $type = strtolower(trim(explode(';', $request->getHeaderLine('Content-Type'))[0]));
        if ($type !== 'application/json') return $this->error('invalid_client_metadata', 'Content-Type must be application/json.', 415);
        $stream = $request->getBody();
        if ($stream->isSeekable()) $stream->rewind();
        $json = '';
        while (!$stream->eof() && strlen($json) <= self::MAX_BYTES) {
            $chunk = $stream->read(self::MAX_BYTES + 1 - strlen($json));
            if ($chunk === '') break;
            $json .= $chunk;
        }
        if (strlen($json) > self::MAX_BYTES) return $this->error('invalid_client_metadata', 'Registration document is too large.', 413);
        try {
            $object = json_decode($json, false, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return $this->error('invalid_client_metadata', 'Registration document must be a JSON object.');
        }
        if (!$object instanceof \stdClass) return $this->error('invalid_client_metadata', 'Registration document must be a JSON object.');
        $input = (array) $object;
        if (array_key_exists('software_statement', $input)) return $this->error('unapproved_software_statement', 'Software statements are not supported.');
        // RFC 7591 defaults omitted authentication to client_secret_basic.
        if (($input['token_endpoint_auth_method'] ?? 'client_secret_basic') !== 'none') {
            return $this->error('invalid_client_metadata', 'Only public clients with token_endpoint_auth_method none are supported.');
        }
        $grants = array_key_exists('grant_types', $input) ? $input['grant_types'] : ['authorization_code'];
        $responses = array_key_exists('response_types', $input) ? $input['response_types'] : ['code'];
        if (!$this->allowedList($grants, ['authorization_code', 'refresh_token']) || !in_array('authorization_code', $grants, true)
            || !$this->allowedList($responses, ['code'])) {
            return $this->error('invalid_client_metadata', 'Only authorization_code, optional refresh_token and code responses are supported.');
        }
        $name = array_key_exists('client_name', $input) ? $input['client_name'] : 'OAuth application';
        if (!is_string($name) || $name === '' || strlen($name) > 200 || preg_match('/[\x00-\x1F\x7F]/', $name)) {
            return $this->error('invalid_client_metadata', 'Invalid client_name.');
        }
        $redirects = $input['redirect_uris'] ?? null;
        if (!is_array($redirects) || !array_is_list($redirects) || !$redirects || count($redirects) > 20) {
            return $this->error('invalid_redirect_uri', 'Provide between 1 and 20 redirect URIs.');
        }
        foreach ($redirects as $uri) {
            if (!is_string($uri) || strlen($uri) > 2048 || preg_match('/[^\x21-\x7E]/', $uri) || str_contains($uri, '\\') || str_contains($uri, '*') || !filter_var($uri, FILTER_VALIDATE_URL)) {
                return $this->error('invalid_redirect_uri', 'Redirect URIs must be absolute HTTPS or HTTP loopback IP URLs without wildcards.');
            }
        }
        $resources = null;
        $allowedScopes = $this->permissions->scopes();
        if ($this->registry?->enabled()) {
            try {
                if (array_key_exists('resources', $input) && $input['resources'] === null) throw new \InvalidArgumentException('Invalid resources');
                $resources = $this->registry->clientResources($input['resources'] ?? null);
                $allowedScopes = $this->registry->registrationScopes($resources, $allowedScopes);
            } catch (\InvalidArgumentException) { return $this->error('invalid_client_metadata', 'Resources must be enabled and registered by the administrator.'); }
        } elseif (array_key_exists('resources', $input)) {
            return $this->error('invalid_client_metadata', 'Enable the resource registry to register resources.');
        }
        $scopes = $allowedScopes;
        if (array_key_exists('scope', $input)) {
            if (!is_string($input['scope']) || !preg_match('/\A[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*\z/', $input['scope'])) {
                return $this->error('invalid_client_metadata', 'Invalid scope.');
            }
            $scopes = array_values(array_unique(explode(' ', $input['scope'])));
            if (array_diff($scopes, $allowedScopes)) return $this->error('invalid_client_metadata', 'Requested scope is not exposed by this server.');
        }
        $record = ['id' => 'dcr_' . bin2hex(random_bytes(24)), 'name' => $name,
            'redirect_uris' => array_values(array_unique($redirects)), 'scopes' => $scopes,
            'confidential' => false, 'enabled' => true, 'grant_types' => array_values(array_unique($grants)),
            'client_id_issued_at' => time(), 'registration_source' => 'dcr'];
        if ($resources !== null) $record['resources'] = $resources;
        try {
            ClientRegistration::validate($record);
        } catch (\InvalidArgumentException) {
            return $this->error('invalid_redirect_uri', 'Redirect URIs must use HTTPS or HTTP loopback IPs, without credentials or fragments.');
        }
        // Insert only. Never let submitted metadata select or overwrite a client ID.
        $this->store->createClient($record);
        return $this->response([
            'client_id' => $record['id'], 'client_id_issued_at' => $record['client_id_issued_at'],
            'client_name' => $record['name'], 'redirect_uris' => $record['redirect_uris'],
            'token_endpoint_auth_method' => 'none', 'grant_types' => $record['grant_types'],
            'response_types' => ['code'], 'scope' => implode(' ', $record['scopes']),
            ...($resources === null ? [] : ['resources' => $resources]),
        ], 201);
    }

    private function allowedList(mixed $values, array $allowed): bool
    {
        if (!is_array($values) || !array_is_list($values) || !$values) return false;
        foreach ($values as $value) if (!is_string($value) || !in_array($value, $allowed, true)) return false;
        return true;
    }
    private function error(string $error, string $description, int $status = 400): ResponseInterface
    {
        return $this->response(['error' => $error, 'error_description' => $description], $status);
    }
    private function response(array $body, int $status): ResponseInterface
    {
        return new JsonResponse($body, $status, ['Cache-Control' => 'no-store', 'Pragma' => 'no-cache']);
    }
}
