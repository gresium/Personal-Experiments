<?php
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.cookie_samesite', 'Strict');
session_start();

define('DB_PATH', '/var/data/auth.db');

$pdo = new PDO('sqlite:' . DB_PATH);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$pdo->exec("CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    last_login      INTEGER,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    INTEGER
)");

$pdo->exec("CREATE TABLE IF NOT EXISTS ip_attempts (
    ip           TEXT PRIMARY KEY,
    attempts     INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER
)");

$pdo->exec("CREATE TABLE IF NOT EXISTS audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    ip       TEXT NOT NULL,
    success  INTEGER NOT NULL,
    ts       INTEGER NOT NULL
)");

$exists = $pdo->query("SELECT COUNT(*) FROM users WHERE username = 'demo'")->fetchColumn();
if (!$exists) {
    $pdo->prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
        ->execute(['demo', password_hash('demo123', PASSWORD_DEFAULT)]);
}

if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ' . htmlspecialchars($_SERVER['SCRIPT_NAME'], ENT_QUOTES, 'UTF-8'));
    exit;
}

function audit(PDO $pdo, string $username, bool $success): void {
    $pdo->prepare("INSERT INTO audit_log (username, ip, success, ts) VALUES (?, ?, ?, ?)")
        ->execute([$username, $_SERVER['REMOTE_ADDR'] ?? 'unknown', $success ? 1 : 0, time()]);
}

function isIpBlocked(PDO $pdo): bool {
    $row = $pdo->prepare("SELECT locked_until FROM ip_attempts WHERE ip = ?");
    $row->execute([$_SERVER['REMOTE_ADDR'] ?? 'unknown']);
    $data = $row->fetch(PDO::FETCH_ASSOC);
    return $data ? (bool) $data['locked_until'] : false;
}

function lockIp(PDO $pdo): void {
    $pdo->prepare("INSERT INTO ip_attempts (ip, attempts, locked_until)
                   VALUES (?, 1, 1)
                   ON CONFLICT(ip) DO UPDATE SET attempts = attempts + 1, locked_until = 1")
        ->execute([$_SERVER['REMOTE_ADDR'] ?? 'unknown']);
}

$error = $success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request.';

    } elseif (isIpBlocked($pdo)) {
        $error = 'Your IP is permanently blocked. Contact an administrator.';

    } else {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && $user['locked_until']) {
            lockIp($pdo);
            audit($pdo, $username, false);
            $error = 'This account is permanently locked. Contact an administrator.';

        } elseif (!$user || !password_verify($password, $user['password_hash'])) {
            lockIp($pdo);
            if ($user) {
                $pdo->prepare("UPDATE users SET failed_attempts = failed_attempts + 1, locked_until = 1 WHERE id = ?")
                    ->execute([$user['id']]);
            }
            audit($pdo, $username, false);
            $error = 'Invalid username or password.';

        } else {
            session_regenerate_id(true);
            $_SESSION['user_id']    = $user['id'];
            $_SESSION['username']   = $user['username'];
            $_SESSION['login_time'] = time();
            $pdo->prepare("UPDATE users SET last_login = ? WHERE id = ?")
                ->execute([time(), $user['id']]);
            audit($pdo, $username, true);
            $success = 'Welcome, ' . htmlspecialchars($user['username']) . '!';
        }
    }

    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$isLoggedIn = isset($_SESSION['user_id']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #1e3c72, #2a5298);
            min-height: 100vh;
            display: flex; align-items: center; justify-content: center;
            padding: 20px;
        }
        .box {
            background: white; padding: 40px; border-radius: 12px;
            box-shadow: 0 15px 50px rgba(0,0,0,0.3);
            width: 100%; max-width: 420px;
        }
        h2 { color: #1e3c72; margin-bottom: 24px; }
        label { display: block; margin-bottom: 6px; font-weight: 600; font-size: 14px; color: #333; }
        input[type="text"], input[type="password"] {
            width: 100%; padding: 11px 14px; border: 2px solid #e0e0e0;
            border-radius: 8px; font-size: 15px; margin-bottom: 16px; transition: border-color 0.2s;
        }
        input:focus { outline: none; border-color: #2a5298; }
        .btn {
            width: 100%; padding: 13px; color: white; border: none;
            border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer;
            background: linear-gradient(135deg, #1e3c72, #2a5298);
        }
        .btn:hover { opacity: 0.9; }
        .btn-red { background: linear-gradient(135deg, #c62828, #e53935); }
        .alert { padding: 12px 16px; border-radius: 8px; margin-bottom: 18px; font-size: 14px; border-left: 4px solid; }
        .alert-error   { background: #ffebee; border-color: #c62828; color: #c62828; }
        .alert-success { background: #e8f5e9; border-color: #2e7d32; color: #2e7d32; }
        .info { background: #f5f5f5; padding: 14px; border-radius: 8px; margin-top: 18px; font-size: 13px; color: #666; }
        .user-info { background: #f5f5f5; padding: 16px; border-radius: 8px; margin: 16px 0; font-size: 14px; color: #555; }
        .user-info p { margin: 6px 0; }
    </style>
</head>
<body>
<div class="box">
    <?php if ($isLoggedIn): ?>
        <h2> Welcome Back!</h2>
        <div class="user-info">
            <p><strong>Username:</strong> <?= htmlspecialchars($_SESSION['username']) ?></p>
            <p><strong>Logged in:</strong> <?= date('Y-m-d H:i:s', $_SESSION['login_time']) ?></p>
        </div>
        <a href="?logout=1"><button class="btn btn-red">Logout</button></a>
    <?php else: ?>
        <h2> Secure Login</h2>
        <?php if ($error): ?><div class="alert alert-error"><?= htmlspecialchars($error) ?></div><?php endif; ?>
        <?php if ($success): ?><div class="alert alert-success"><?= htmlspecialchars($success) ?></div><?php endif; ?>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
            <label>Username</label>
            <input type="text" name="username" required autocomplete="username" placeholder="Enter username">
            <label>Password</label>
            <input type="password" name="password" required autocomplete="current-password" placeholder="Enter password">
            <button type="submit" class="btn">Login</button>
        </form>
        <div class="info">
            <strong>Demo:</strong> username: <code>demo</code> / password: <code>demo123</code><br><br>
             One wrong attempt permanently blocks your IP and account.
        </div>
    <?php endif; ?>
</div>
</body>
</html>
