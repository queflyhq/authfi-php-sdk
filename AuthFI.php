<?php
/**
 * AuthFI PHP SDK
 *
 * Usage (Laravel):
 *   $auth = new AuthFI('acme', 'sk_live_...');
 *
 *   // Middleware
 *   Route::get('/api/users', function (Request $request) use ($auth) {
 *       $user = $auth->authenticate($request);
 *       $auth->requirePermissions($user, ['read:users']);
 *       return User::all();
 *   });
 *
 *   // On startup
 *   $auth->sync();
 */

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\SignatureInvalidException;

class AuthFI {
    private string $tenant;
    private string $apiKey;
    private string $apiUrl;
    private ?string $applicationId;
    private array $registeredPermissions = [];

    /** Seconds to cache the JWKS in-memory before refetching. */
    private int $jwksTtl;
    /** @var array<string, \Firebase\JWT\Key>|null kid => Key, parsed from the JWKS. */
    private ?array $jwksKeys = null;
    /** Unix timestamp of the last successful JWKS fetch. */
    private int $jwksFetchedAt = 0;
    /** Clock-skew tolerance (seconds) applied to exp/nbf/iat. */
    private int $leeway;

    public function __construct(
        string $tenant,
        string $apiKey,
        string $apiUrl = 'https://api.authfi.app',
        ?string $applicationId = null,
        int $jwksTtl = 300,
        int $leeway = 60
    ) {
        $this->tenant = $tenant;
        $this->apiKey = $apiKey;
        $this->apiUrl = $apiUrl;
        $this->applicationId = $applicationId;
        $this->jwksTtl = $jwksTtl;
        $this->leeway = $leeway;
    }

    /**
     * Expected `iss` claim for tokens minted for this tenant.
     * AuthFI issues tokens under the tenant subdomain.
     */
    private function issuer(): string {
        return "https://{$this->tenant}.authfi.app";
    }

    /** Tenant-scoped JWKS endpoint. */
    private function jwksUrl(): string {
        return "{$this->apiUrl}/v1/{$this->tenant}/.well-known/jwks.json";
    }

    /**
     * Authenticate request and return decoded claims.
     */
    public function authenticate($request = null): object {
        $token = $this->extractToken($request);
        if (!$token) {
            throw new AuthFIException('Missing authorization', 401);
        }
        return $this->verifyToken($token);
    }

    /**
     * Verify a JWT's RS256 signature against the tenant's JWKS, then validate
     * its standard claims (exp/nbf/iat via firebase/php-jwt, plus iss here).
     *
     * @return object decoded claims (stdClass), backward compatible.
     * @throws AuthFIException on any verification failure.
     */
    public function verifyToken(string $token): object {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new AuthFIException('Invalid token', 401);
        }

        // Read the header to learn which signing key (kid) and algorithm to use.
        $header = json_decode(base64_decode(strtr($parts[0], '-_', '+/')) ?: '');
        if (!is_object($header) || !isset($header->kid)) {
            throw new AuthFIException('Invalid token header', 401);
        }
        if (($header->alg ?? null) !== 'RS256') {
            // Block "alg" confusion / downgrade (e.g. none, HS256).
            throw new AuthFIException('Unsupported token algorithm', 401);
        }

        $keys = $this->getSigningKeys($header->kid);

        // firebase/php-jwt verifies the RS256 signature, picks the key by kid,
        // and enforces exp/nbf/iat (with $leeway). It throws on any failure.
        JWT::$leeway = $this->leeway;
        try {
            $payload = JWT::decode($token, $keys);
        } catch (ExpiredException $e) {
            throw new AuthFIException('Token expired', 401);
        } catch (BeforeValidException $e) {
            throw new AuthFIException('Token not yet valid', 401);
        } catch (SignatureInvalidException $e) {
            throw new AuthFIException('Invalid token signature', 401);
        } catch (\UnexpectedValueException $e) {
            // Malformed token, unknown kid, or unsupported alg from the keyset.
            throw new AuthFIException('Invalid token', 401);
        }

        // Validate issuer (firebase/php-jwt does not check `iss`).
        if (($payload->iss ?? null) !== $this->issuer()) {
            throw new AuthFIException('Invalid token issuer', 401);
        }

        return $payload;
    }

    /**
     * Return the parsed JWKS keyed by kid, refetching when the cache is stale
     * or the requested kid is absent (handles key rotation).
     *
     * @return array<string, Key>
     * @throws AuthFIException if the JWKS cannot be fetched/parsed, or the kid
     *                         is still unknown after a refetch.
     */
    private function getSigningKeys(string $kid): array {
        $fresh = $this->jwksKeys !== null
            && (time() - $this->jwksFetchedAt) < $this->jwksTtl;

        if (!$fresh || !isset($this->jwksKeys[$kid])) {
            $this->refreshJwks();
        }

        if (!isset($this->jwksKeys[$kid])) {
            throw new AuthFIException('Unknown signing key', 401);
        }

        return $this->jwksKeys;
    }

    /**
     * Fetch and parse the tenant's JWKS into a kid => Key map.
     *
     * @throws AuthFIException on network, HTTP, JSON, or parse failure.
     */
    private function refreshJwks(): void {
        $url = $this->jwksUrl();
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
        ]);
        $response = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);

        if ($response === false || $status >= 400) {
            $detail = $err !== '' ? $err : "HTTP $status";
            throw new AuthFIException("Failed to fetch JWKS: $detail", 401);
        }

        $jwks = json_decode($response, true);
        if (!is_array($jwks) || empty($jwks['keys'])) {
            throw new AuthFIException('Invalid JWKS response', 401);
        }

        try {
            // Default alg to RS256 for keys whose JWK omits "alg".
            $keys = JWK::parseKeySet($jwks, 'RS256');
        } catch (\Exception $e) {
            throw new AuthFIException('Failed to parse JWKS', 401);
        }

        $this->jwksKeys = $keys;
        $this->jwksFetchedAt = time();
    }

    /**
     * Check ALL permissions are present.
     */
    public function requirePermissions(object $claims, array $permissions): void {
        $userPerms = $claims->permissions ?? [];
        $missing = array_diff($permissions, $userPerms);

        foreach ($permissions as $p) {
            $this->registerPermission($p);
        }

        if (!empty($missing)) {
            throw new AuthFIException('Missing permissions: ' . implode(', ', $missing), 403);
        }
    }

    /**
     * Check ANY role matches.
     */
    public function requireRole(object $claims, array $roles): void {
        $userRoles = $claims->roles ?? [];
        foreach ($roles as $r) {
            if (in_array($r, $userRoles)) return;
        }
        throw new AuthFIException('Insufficient role', 403);
    }

    public function registerPermission(string $name, ?string $description = null): void {
        $this->registeredPermissions[$name] = $description;
    }

    /**
     * Sync registered permissions with AuthFI. Call on deployment/startup.
     */
    public function sync(): void {
        if (empty($this->registeredPermissions)) return;

        $perms = [];
        foreach ($this->registeredPermissions as $name => $desc) {
            $p = ['name' => $name];
            if ($desc) $p['description'] = $desc;
            $perms[] = $p;
        }

        $body = ['permissions' => $perms];
        if ($this->applicationId) $body['application_id'] = $this->applicationId;

        $url = "{$this->apiUrl}/manage/v1/{$this->tenant}/permissions/sync";
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => 'PUT',
            CURLOPT_POSTFIELDS => json_encode($body),
            CURLOPT_HTTPHEADER => [
                'X-API-Key: ' . $this->apiKey,
                'Content-Type: application/json',
            ],
            CURLOPT_RETURNTRANSFER => true,
        ]);

        $response = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($status < 400) {
            $data = json_decode($response);
            error_log("[authfi] Synced {$data->synced} permissions ({$data->total} total)");
        } else {
            error_log("[authfi] Sync failed: $response");
        }
    }

    private function extractToken($request): ?string {
        // Laravel Request
        if ($request && method_exists($request, 'bearerToken')) {
            return $request->bearerToken();
        }
        // Raw PHP
        $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (str_starts_with($auth, 'Bearer ')) {
            return substr($auth, 7);
        }
        return null;
    }
}

class AuthFIException extends \RuntimeException {
    public int $status;
    public function __construct(string $message, int $status = 401) {
        parent::__construct($message);
        $this->status = $status;
    }
}
