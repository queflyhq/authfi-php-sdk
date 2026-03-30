<?php
/**
 * AuthFI PHP SDK Tests
 * Run: php test_authfi.php
 */

require_once __DIR__ . '/AuthFI.php';

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

function make_token(array $payload, array $header = ['alg' => 'RS256', 'typ' => 'JWT', 'kid' => 'test-key-1']): string {
    $h = rtrim(base64_encode(json_encode($header)), '=');
    $h = strtr($h, '+/', '-_');
    $p = rtrim(base64_encode(json_encode($payload)), '=');
    $p = strtr($p, '+/', '-_');
    $s = rtrim(base64_encode('fakesig'), '=');
    $s = strtr($s, '+/', '-_');
    return "$h.$p.$s";
}

// --- Tests ---

echo "\nAuthFI PHP SDK Tests\n";
echo str_repeat('=', 40) . "\n\n";

echo "Initialization:\n";
test('creates instance', function() {
    $auth = new AuthFI('acme', 'sk_test');
    assert_eq(true, $auth instanceof AuthFI);
});

echo "\nToken verification:\n";
test('rejects invalid format', function() {
    $auth = new AuthFI('acme', 'sk_test');
    $e = assert_throws(AuthFIException::class, fn() => $auth->verifyToken('not-a-jwt'));
    assert_eq(401, $e->status);
});

test('rejects expired token', function() {
    $auth = new AuthFI('acme', 'sk_test');
    $token = make_token(['sub' => 'usr_123', 'exp' => time() - 3600]);
    $e = assert_throws(AuthFIException::class, fn() => $auth->verifyToken($token));
    assert_eq(401, $e->status);
    assert_eq(true, str_contains($e->getMessage(), 'expired'));
});

test('decodes valid payload', function() {
    $auth = new AuthFI('acme', 'sk_test');
    $token = make_token([
        'sub' => 'usr_123',
        'email' => 'jane@acme.com',
        'roles' => ['admin', 'editor'],
        'permissions' => ['read:users', 'write:users'],
        'org_slug' => 'acme-corp',
        'exp' => time() + 3600,
    ]);
    $claims = $auth->verifyToken($token);
    assert_eq('usr_123', $claims->sub);
    assert_eq('jane@acme.com', $claims->email);
    assert_eq(['admin', 'editor'], $claims->roles);
    assert_eq(['read:users', 'write:users'], $claims->permissions);
    assert_eq('acme-corp', $claims->org_slug);
});

test('accepts token without exp', function() {
    $auth = new AuthFI('acme', 'sk_test');
    $token = make_token(['sub' => 'usr_123']);
    $claims = $auth->verifyToken($token);
    assert_eq('usr_123', $claims->sub);
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
