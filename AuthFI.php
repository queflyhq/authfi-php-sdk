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

class AuthFI {
    private string $tenant;
    private string $apiKey;
    private string $apiUrl;
    private ?string $applicationId;
    private array $registeredPermissions = [];

    public function __construct(
        string $tenant,
        string $apiKey,
        string $apiUrl = 'https://api.authfi.app',
        ?string $applicationId = null
    ) {
        $this->tenant = $tenant;
        $this->apiKey = $apiKey;
        $this->apiUrl = $apiUrl;
        $this->applicationId = $applicationId;
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
     * Verify JWT and return claims.
     */
    public function verifyToken(string $token): object {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new AuthFIException('Invalid token', 401);
        }

        $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')));
        if (!$payload) {
            throw new AuthFIException('Invalid token payload', 401);
        }

        if (isset($payload->exp) && $payload->exp < time()) {
            throw new AuthFIException('Token expired', 401);
        }

        // NOTE: For production, verify RS256 signature using firebase/php-jwt
        return $payload;
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
