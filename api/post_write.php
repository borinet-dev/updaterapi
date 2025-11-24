<?php
require_once __DIR__ . '/auth.php';

// auth.php / response.php 어디에도 json_response() 가 없어서 직접 정의
if (!function_exists('json_response')) {
    function json_response(array $payload, int $statusCode = 200): void
    {
        http_response_code($statusCode);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($payload, JSON_UNESCAPED_UNICODE);
        exit;
    }
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_error('POST 메서드만 허용됩니다.', 405);
}

$accountLogin = require_auth();

// 원본 바디를 먼저 읽어서 로그로 남김
$rawBody = file_get_contents('php://input');

$input = json_decode($rawBody, true);
if (!is_array($input)) {
    $input = $_POST;
}

$boardCode   = isset($input['board']) ? trim((string)$input['board']) : '';
$subject     = isset($input['subject']) ? trim((string)$input['subject']) : '';
$contentHtml = isset($input['contentHtml']) ? (string)$input['contentHtml'] : '';
$category    = isset($input['category']) ? trim((string)$input['category']) : '';
// 공지 여부 (런처에서 isNotice 또는 IsNotice 로 true/false 또는 0/1 전달)
//    기본값: 0 (일반 글), 관리자인 경우에만 1로 승격
$isNoticeRaw = $input['isNotice'] ?? ($input['IsNotice'] ?? null);
$isNotice    = 0;

$isSecretRaw = $input['isSecret'] ?? ($input['IsSecret'] ?? null);
$isSecret    = 0;

// 런처에서 넘겨주는 선택 캐릭터 닉네임
$authorName  = isset($input['authorName']) ? trim((string)$input['authorName']) : '';

if ($authorName === '') {
    // 혹시 안 넘어오면 계정명으로 대체
    $authorName = $accountLogin;
}

if ($boardCode === '' || $subject === '' || $contentHtml === '') {
    json_error('게시판, 제목, 내용은 필수입니다.', 400);
}

$pdo = get_pdo_launcher();

// 게시판 정보
$stmt = $pdo->prepare("
    SELECT id, code, name, isAminBoard, category
    FROM launcher_board
    WHERE code = :code
    LIMIT 1
");
$stmt->execute([':code' => $boardCode]);
$board = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$board) {
    json_error('존재하지 않는 게시판입니다.', 404);
}

$boardId      = (int)$board['id'];
$boardCode    = (string)$board['code'];
$isAdminBoard = (bool)$board['isAminBoard'];
$boardCategoryConfig = isset($board['category']) ? trim((string)$board['category']) : '';

// 카테고리 설정이 있는 게시판인데 category 가 비어 있으면 작성 불가
if ($boardCategoryConfig !== '' && $category === '' && !is_admin_account($accountLogin)) {
    json_error('카테고리를 선택해 주세요.', 400);
}

// isAminBoard = 1 이면 운영자만 글 작성 가능
if ($isAdminBoard && !is_admin_account($accountLogin)) {
    json_error('운영자만 글을 작성할 수 있는 게시판입니다.', 403);
}

$now = date('Y-m-d H:i:s');

// 공지글 처리: 운영자 계정일 때만 is_notice 설정 허용
if (is_admin_account($accountLogin)) {
    // 값이 "0" / 0 / false / null 이 아니고, 뭔가 들어와 있으면 전부 1로 처리
    if (!empty($isNoticeRaw) && $isNoticeRaw !== '0' && $isNoticeRaw !== 0) {
        $isNotice = 1;
    }
}

if (!empty($isSecretRaw) && $isSecretRaw !== '0' && $isSecretRaw !== 0) {
	$isSecret = 1;
}

// author_name은 일단 accountLogin으로 넣고,
// 나중에 원하시면 l2jserver.characters에서 대표 캐릭터명을 가져와도 됨.
$stmt = $pdo->prepare("
    INSERT INTO launcher_post (
        board_id, is_notice, is_secret, category,
        subject, content_html,
        author_login, author_name,
        created_at, updated_at
    )
    VALUES (
        :board_id, :is_notice, :is_secret, :category,
        :subject, :content_html,
        :author_login, :author_name,
        :created_at, :updated_at
    )
");
$stmt->execute([
    ':board_id'     => $boardId,
	':is_notice'    => $isNotice,
	':is_secret'    => $isSecret,
    ':category'     => ($category !== '' ? $category : null),
    ':subject'      => $subject,
    ':content_html' => $contentHtml,
    ':author_login' => $accountLogin,
    ':author_name'  => $authorName,
    ':created_at'   => $now,
    ':updated_at'   => $now,
]);

$postId = (int)$pdo->lastInsertId();

json_response([
    'success' => true,
    'postId'  => $postId,
]);