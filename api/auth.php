<?php
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/response.php';
require_once __DIR__ . '/config.php';

function l2_hash(string $plain): string
{
    // base64_encode(sha1($plain, true))
    return base64_encode(sha1($plain, true));
}

function generate_session_token(): string
{
    return bin2hex(random_bytes(32)); // 64 chars
}

function create_session(string $accountLogin): string
{
    $pdo = get_pdo_launcher();

    $token = generate_session_token();
    $now   = date('Y-m-d H:i:s');
    $exp   = date('Y-m-d H:i:s', time() + SESSION_LIFETIME);

    $ip    = $_SERVER['REMOTE_ADDR'] ?? null;
    $agent = $_SERVER['HTTP_USER_AGENT'] ?? null;

    $stmt = $pdo->prepare("
        INSERT INTO launcher_session (session_token, account_login, created_at, expires_at, last_ip, last_agent)
        VALUES (:token, :login, :created_at, :expires_at, :ip, :agent)
    ");
    $stmt->execute([
        ':token'      => $token,
        ':login'      => $accountLogin,
        ':created_at' => $now,
        ':expires_at' => $exp,
        ':ip'         => $ip,
        ':agent'      => $agent,
    ]);

    return $token;
}

function get_token_from_request(): ?string
{
    // 헤더 우선
    $headerName = 'HTTP_' . str_replace('-', '_', strtoupper(AUTH_TOKEN_HEADER));
    if (!empty($_SERVER[$headerName])) {
        return trim($_SERVER[$headerName]);
    }

    // 그 다음 GET/POST 파라미터 token
    if (!empty($_GET['token'])) {
        return trim((string)$_GET['token']);
    }
    if (!empty($_POST['token'])) {
        return trim((string)$_POST['token']);
    }

    return null;
}

/**
 * 유효한 세션이면 account_login 반환, 아니면 에러로 종료
 */
function require_auth(): string
{
    $token = get_token_from_request();
    if ($token === null || $token === '') {
        json_error('인증 토큰이 없습니다.', 401);
    }

    $pdo = get_pdo_launcher();

    $stmt = $pdo->prepare("
        SELECT account_login, expires_at
        FROM launcher_session
        WHERE session_token = :token
        LIMIT 1
    ");
    $stmt->execute([':token' => $token]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row) {
        json_error('유효하지 않은 세션입니다.', 401);
    }

    if (strtotime($row['expires_at']) < time()) {
        json_error('세션이 만료되었습니다.', 401);
    }

    return $row['account_login'];
}

/**
 * accounts.accessLevel 기준으로 운영자 여부 판별
 *  - accessLevel > 0 이면 운영자로 간주
 */
function is_admin_account(string $accountLogin): bool
{
    // 게임 DB에서 accessLevel 조회
    $pdoGame = get_pdo_game();

    $stmt = $pdoGame->prepare("
        SELECT accessLevel
        FROM accounts
        WHERE login = :login
        LIMIT 1
    ");
    $stmt->execute([':login' => $accountLogin]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row) {
        return false;
    }

    return ((int)$row['accessLevel'] >= 100);
}

function require_admin(array $session): void
{
    if (empty($session['is_admin'])) {
        json_error('권한이 없습니다. (운영자 전용 기능입니다.)', 403);
    }
}

function load_board(PDO $pdo, int $boardId): array
{
    if ($boardId <= 0) {
        json_error('잘못된 게시판입니다.', 400);
    }

    $stmt = $pdo->prepare('SELECT * FROM launcher_board WHERE id = :id');
    $stmt->execute([':id' => $boardId]);
    $board = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$board) {
        json_error('존재하지 않는 게시판입니다.', 404);
    }

    return $board;
}

/**
 * 공지/업데이트/이벤트 게시판인지 여부
 *  - 이 게시판들은 admin 만 글작성 가능
 */
function is_admin_only_board(string $code): bool
{
    return in_array($code, ['notice', 'update', 'event'], true);
}
