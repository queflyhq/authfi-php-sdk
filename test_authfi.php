<?php
/**
 * AuthFI PHP SDK Tests
 * Run: php test_authfi.php
 *
 * Requires Composer deps (firebase/php-jwt). Install with:
 *   composer install
 *
 * Signature-verification tests generate an in-process RSA keypair and seed the
 * SDK's in-memory JWKS cache via reflection, so they run offline (no live JWKS
 * endpoint). The OpenSSL extension must be enabled.
 */

if (is_file(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
}
require_once __DIR__ . '/AuthFI.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$passed = 0;
$failed = 0;

function test($name, $fn) {
    global $passed, $failed;
    try {
        $fn();
        echo "  ✓ $name\n";
        $passed++;
    } catch (Throwable $e) {
        echo "  ✗ $name — {$e->getMessage()}\n";
        $failed++;
    }
}

function assert_eq($expected, $actual, $msg = '') {
    if ($expected !== $actual) {
        throw new RuntimeException("Expected " . var_export($expected, true) . ", got " . var_export($actual, true) . " $msg");
    }
}

function assert_throws($class, $fn) {
    try {
        $fn();
        throw new RuntimeException("Expected $class to be thrown");
    } catch (\Throwable $e) {
        if (!($e instanceof $class)) {
            throw new RuntimeException("Expected $class, got " . get_class($e) . ": " . $e->getMessage());
        }
        return $e;
    }
}

const TEST_KID = 'test-key-1';

/** Generate a fresh RSA-2048 keypair for the test run. */
function rsa_keypair(): array {
    $res = openssl_pkey_new([
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ]);
    if ($res === false) {
        throw new RuntimeException('openssl_pkey_new failed — is the OpenSSL extension enabled?');
    }
    openssl_pkey_export($res, $privatePem);
    $details = openssl_pkey_get_details($res);
    return [$privatePem, $details]; // [PEM private key, public key details incl. rsa n/e]
}

function b64url(string $bin): string {
    return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
}

/** Build a JWKS array (one RSA key) from openssl public-key details. */
function jwks_from(array $details, string $kid = TEST_KID): array {
    return ['keys' => [[
        'kty' => 'RSA',
        'alg' => 'RS256',
        'use' => 'sig',
        'kid' => $kid,
        'n'   => b64url($details['rsa']['n']),
        'e'   => b64url($details['rsa']['e']),
    ]]];
}

/**
 * Seed the SDK's private in-memory JWKS cache so verifyToken() never hits the
 * network. Uses reflection to avoid exposing a test-only public API on the
 * shipping class.
 */
function seed_jwks(AuthFI $auth, array $jwks): void {
    $keys = \Firebase\JWT\JWK::parseKeySet($jwks, 'RS256');
    $ref = new ReflectionObject($auth);
    $p = $ref->getProperty('jwksKeys');     $p->setAccessible(true); $p->setValue($auth, $keys);
    $t = $ref->getProperty('jwksFetchedAt'); $t->setAccessible(true); $t->setValue($auth, time());
}

/** Sign a real RS256 JWT with the given private key. */
function sign_token(string $privatePem, array $payload, string $kid = TEST_KID): string {
    return JWT::encode($payload, $privatePem, 'RS256', $kid);
}

// --- Tests ---

echo "\nAuthFI PHP SDK Tests\n";
echo str_repeat('=', 40) . "\n\n";

echo "Initialization:\n";
test('creates instance', function() {
    $auth = new AuthFI('acme', 'sk_test');
    assert_eq(true, $auth instanceof AuthFI);
});

echo "\nToken verification (RS256 + JWKS):\n";
test('rejects invalid format', function() {
    $auth = new AuthFI('acme', 'sk_test');
    $e = assert_throws(AuthFIException::class, fn() => $auth->verifyToken('not-a-jwt'));
    assert_eq(401, $e->status);
});

test('accepts a validly-signed token', function() {
    [$priv, $details] = rsa_keypair();
    $auth = new AuthFI('acme', 'sk_test');
    seed_jwks($auth, jwks_from($details));

    $token = sign_token($priv, [
        'sub' => 'usr_123',
        'email' => 'jane@acme.com',
        'roles' => ['admin', 'editor'],
        'permissions' => ['read:users', 'write:users'],
        'org_slug' => 'acme-corp',
        'iss' => 'https://acme.authfi.app',
        'iat' => time() - 10,
        'exp' => time() + 3600,
    ]);

    $claims = $auth->verifyToken($token);
    assert_eq('usr_123', $claims->sub);
    assert_eq('jane@acme.com', $claims->email);
    assert_eq(['admin', 'editor'], $claims->roles);
    assert_eq(['read:users', 'write:users'], $claims->permissions);
    assert_eq('acme-corp', $claims->org_slug);
});

test('rejects a tampered payload (signature no longer matches)', function() {
    [$priv, $details] = rsa_keypair();
    $auth = new AuthFI('acme', 'sk_test');
    seed_jwks($auth, jwks_from($details));

    $token = sign_token($priv, [
        'sub' => 'usr_123',
        'permissions' => ['read:users'],
        'iss' => 'https://acme.authfi.app',
        'exp' => time() + 3600,
    ]);

    // Tamper: swap the payload for one granting admin perms, keep the old signature.
    [$h, , $s] = explode('.', $token);
    $forgedPayload = rtrim(strtr(base64_encode(json_encode([
        'sub' => 'usr_123',
        'permissions' => ['read:users', 'write:users', 'delete:users'],
        'iss' => 'https://acme.authfi.app',
        'exp' => time() + 3600,
    ])), '+/', '-_'), '=');
    $tampered = "$h.$forgedPayload.$s";

    $e = assert_throws(AuthFIException::class, fn() => $auth->verifyToken($tampered));
    assert_eq(401, $e->status);
    assert_eq(true, str_contains($e->getMessage(), 'signature'));
});

test('rejects a forged token signed with the wrong key', function() {
    [, $details] = rsa_keypair();      // public key the SDK trusts (in JWKS)
    [$attackerPriv, ] = rsa_keypair(); // attacker's key — NOT in the JWKS
    $auth = new AuthFI('acme', 'sk_test');
    seed_jwks($auth, jwks_from($details));

    // Forged token uses the trusted kid but is signed by the attacker's key.
    $token = sign_token($attackerPriv, [
        'sub' => 'attacker',
        'permissions' => ['delete:users'],
        'iss' => 'https://acme.authfi.app',
        'exp' => time() + 3600,
    ]);

    $e = assert_throws(AuthFIException::class, fn() => $auth->verifyToken($token));
    assert_eq(401, $e->status);
});

test('rejects an "alg: none" downgrade attempt', function() {
    [, $details] = rsa_keypair();
    $auth = new AuthFI('acme', 'sk_test');
    seed_jwks($auth, jwks_from($details));

    $h = b64url(json_encode(['alg' => 'none', 'typ' => 'JWT', 'kid' => TEST_KID]));
    $p = b64url(json_encode(['sub' => 'usr_123', 'iss' => 'https://acme.authfi.app', 'exp' => time() + 3600]));
    $token = "$h.$p.";

    $e = assert_throws(AuthFIException::class, fn() => $auth->verifyToken($token));
    assert_eq(401, $e->status);
});

test('rejects an expired token', function() {
    [$priv, $details] = rsa_keypair();
    $auth = new AuthFI('acme', 'sk_test');
    seed_jwks($auth, jwks_from($details));

    $token = sign_token($priv, [
        'sub' => 'usr_123',
        'iss' => 'https://acme.authfi.app',
        'iat' => time() - 7200,
        'exp' => time() - 3600,
    ]);

    $e = assert_throws(AuthFIException::class, fn() => $auth->verifyToken($token));
    assert_eq(401, $e->status);
    assert_eq(true, str_contains($e->getMessage(), 'expired'));
});

test('rejects a token with the wrong issuer', function() {
    [$priv, $details] = rsa_keypair();
    $auth = new AuthFI('acme', 'sk_test');
    seed_jwks($auth, jwks_from($details));

    $token = sign_token($priv, [
        'sub' => 'usr_123',
        'iss' => 'https://evil.authfi.app',
        'exp' => time() + 3600,
    ]);

    $e = assert_throws(AuthFIException::class, fn() => $auth->verifyToken($token));
    assert_eq(401, $e->status);
    assert_eq(true, str_contains($e->getMessage(), 'issuer'));
});

test('rejects an unknown kid (refetch attempted, then rejected)', function() {
    [$priv, $details] = rsa_keypair();
    // Point at an unroutable host so the rotation refetch fails fast instead of
    // calling production. A token bearing an untrusted kid must never verify.
    $auth = new AuthFI('acme', 'sk_test', 'https://127.0.0.1:1');
    seed_jwks($auth, jwks_from($details, 'rotated-out-key'));

    // Cache is fresh but lacks TEST_KID, so the SDK refetches (handles rotation);
    // the refetch fails (unroutable) and the token is rejected either way.
    $token = sign_token($priv, [
        'sub' => 'usr_123',
        'iss' => 'https://acme.authfi.app',
        'exp' => time() + 3600,
    ], TEST_KID);

    $e = assert_throws(AuthFIException::class, fn() => $auth->verifyToken($token));
    assert_eq(401, $e->status);
});

echo "\nPermission checks:\n";
test('passes with matching permissions', function() {
    $auth = new AuthFI('acme', 'sk_test');
    $claims = (object)['permissions' => ['read:users', 'write:users']];
    $auth->requirePermissions($claims, ['read:users']); // should not throw
});

test('raises on missing permission', function() {
    $auth = new AuthFI('acme', 'sk_test');
    $claims = (object)['permissions' => ['read:users']];
    $e = assert_throws(AuthFIException::class, fn() => $auth->requirePermissions($claims, ['delete:users']));
    assert_eq(403, $e->status);
});

test('handles empty permissions', function() {
    $auth = new AuthFI('acme', 'sk_test');
    $claims = (object)[];
    assert_throws(AuthFIException::class, fn() => $auth->requirePermissions($claims, ['read:users']));
});

echo "\nRole checks:\n";
test('passes with matching role', function() {
    $auth = new AuthFI('acme', 'sk_test');
    $claims = (object)['roles' => ['editor']];
    $auth->requireRole($claims, ['admin', 'editor']); // should not throw
});

test('raises on missing role', function() {
    $auth = new AuthFI('acme', 'sk_test');
    $claims = (object)['roles' => ['viewer']];
    $e = assert_throws(AuthFIException::class, fn() => $auth->requireRole($claims, ['admin']));
    assert_eq(403, $e->status);
});

test('handles empty roles', function() {
    $auth = new AuthFI('acme', 'sk_test');
    $claims = (object)[];
    assert_throws(AuthFIException::class, fn() => $auth->requireRole($claims, ['admin']));
});

echo "\nPermission registration:\n";
test('registers permissions', function() {
    $auth = new AuthFI('acme', 'sk_test');
    $auth->registerPermission('read:users', 'Read user data');
    $auth->registerPermission('write:users');
    // Should not throw
});

echo "\nSync:\n";
test('sync empty is noop', function() {
    $auth = new AuthFI('acme', 'sk_test');
    $auth->sync(); // should not throw
});

echo "\nAuthentication:\n";
test('rejects missing auth header', function() {
    $auth = new AuthFI('acme', 'sk_test');
    // Simulate no auth header
    unset($_SERVER['HTTP_AUTHORIZATION']);
    $e = assert_throws(AuthFIException::class, fn() => $auth->authenticate());
    assert_eq(401, $e->status);
});

echo "\nException:\n";
test('default status is 401', function() {
    $e = new AuthFIException('test');
    assert_eq(401, $e->status);
});

test('custom status', function() {
    $e = new AuthFIException('forbidden', 403);
    assert_eq(403, $e->status);
});

// --- Summary ---
echo "\n" . str_repeat('=', 40) . "\n";
echo "Results: $passed passed, $failed failed\n";
exit($failed > 0 ? 1 : 0);
