<?php
require_once __DIR__ . '/auth.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_error('POST 메서드만 허용됩니다.', 405);
}

$input = json_decode(file_get_contents('php://input'), true);
if (!is_array($input)) {
    $input = $_POST; // 폼 전송 대비
}

$login    = isset($input['login']) ? trim((string)$input['login']) : '';
$password = isset($input['password']) ? (string)$input['password'] : '';

if ($login === '' || $password === '') {
    json_error('아이디와 비밀번호를 입력해 주세요.', 400);
}

$pwdHash = l2_hash($password);

$pdoGame = get_pdo_game();

// accounts 확인
$stmt = $pdoGame->prepare("
    SELECT password, accessLevel
    FROM accounts
    WHERE login = :login
    LIMIT 1
");
$stmt->execute([':login' => $login]);
$acc = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$acc) {
    json_error('존재하지 않는 계정입니다.', 400);
}

if (!hash_equals($acc['password'], $pwdHash)) {
    json_error('비밀번호가 올바르지 않습니다.', 400);
}

// 세션 생성
$token = create_session($login);

// admin 여부: accounts.accessLevel >= 100 이면 true
$isAdmin = ((int)$acc['accessLevel'] >= 100);

// 캐릭터 목록
$stmt = $pdoGame->prepare("
    SELECT
        c.charId,
        c.char_name,
        c.level,
        c.race,
        c.classid,
        c.clanid,
        c.createDate,
        c.visual_classid,
        cd.clan_name
    FROM characters c
    LEFT JOIN clan_data cd ON cd.clan_id = c.clanid
    WHERE c.account_name = :login
    ORDER BY c.level DESC
");
$stmt->execute([':login' => $login]);
$chars = [];
while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    $chars[] = [
        'charId'        => (int)$row['charId'],
        'name'          => $row['char_name'],
        'level'         => (int)$row['level'],
        'race'          => isset($row['race']) ? (int)$row['race'] : 0,
        'classId'       => isset($row['classid']) ? (int)$row['classid'] : 0,
        'clanId'        => $row['clanid'] !== null ? (int)$row['clanid'] : null,
        'clanName'      => $row['clan_name'] ?? null,
        'birthday'      => $row['createDate'] ?? null,
        'visualClassId' => isset($row['visual_classid']) ? (int)$row['visual_classid'] : -2,
    ];
}

header('Content-Type: application/json; charset=utf-8');
echo json_encode([
    'success'    => true,
    'token'      => $token,
    'account'    => $login,
    'characters' => $chars,
	'isAdmin'    => $isAdmin,
], JSON_UNESCAPED_UNICODE);
exit;
