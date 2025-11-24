<?php
require_once __DIR__ . '/auth.php';

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
$isAdminUser  = is_admin_account($accountLogin);

$input = json_decode(file_get_contents('php://input'), true);
if (!is_array($input)) {
    $input = $_POST;
}

$postId      = isset($input['postId']) ? (int)$input['postId'] : 0;
$subject     = isset($input['subject']) ? trim((string)$input['subject']) : '';
$contentHtml = isset($input['contentHtml']) ? (string)$input['contentHtml'] : '';
$category    = isset($input['category']) ? trim((string)$input['category']) : '';

if ($postId <= 0 || $subject === '' || $contentHtml === '') {
    json_error('postId, 제목, 내용은 필수입니다.', 400);
}

$pdo = get_pdo_launcher();

// 게시글 조회
$stmt = $pdo->prepare("
    SELECT p.id, p.board_id, p.author_login, p.is_notice
    FROM launcher_post p
    WHERE p.id = :id
    LIMIT 1
");
$stmt->execute([':id' => $postId]);
$post = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$post) {
    json_error('존재하지 않거나 삭제된 게시글입니다.', 404);
}

// 게시판 정보 로드
$board     = load_board($pdo, (int)$post['board_id']);
$boardCode = (string)$board['code'];
// 카테고리 설정 문자열 (예: "건의 | 버그제보")
$boardCategoryConfig = isset($board['category']) ? trim((string)$board['category']) : '';

$isAdminBoard  = is_admin_only_board($boardCode);
// 작성자 여부(대소문자 무시)
$isAuthorUser  = (strcasecmp($post['author_login'], $accountLogin) === 0);

// 권한 체크
if ($isAdminBoard) {
    // 공지/업데이트/이벤트 게시판: 운영자만 수정 가능
    if (!$isAdminUser) {
        json_error('운영자만 이 게시글을 수정할 수 있습니다.', 403);
    }
} else {
    // 일반 게시판: 작성자 본인만 수정 가능

	if (!$isAuthorUser && !$isAdminUser) {
        json_error('자신의 게시글만 수정할 수 있습니다.', 403);
    }
}

// 댓글 개수 확인 (삭제되지 않은 것만)
$stmt = $pdo->prepare("
    SELECT COUNT(*) AS cnt
    FROM launcher_comment
    WHERE post_id = :post_id
");
$stmt->execute([':post_id' => $postId]);
$commentCount = (int)$stmt->fetchColumn();

// 일반 계정만 댓글이 있는 글 수정 제한, 운영자는 예외
if ($commentCount > 0 && !$isAdminUser) {
    json_error('댓글이 있는 게시글은 수정할 수 없습니다.', 400);
}

// 이 게시판에 카테고리 설정이 있는데, 수정 요청에서 category 가 비어 있으면 막기
if ($boardCategoryConfig !== '' && $category === '') {
    json_error('카테고리를 선택해 주세요.', 400);
}

$now = date('Y-m-d H:i:s');

// 공지 여부 처리 (운영자만 변경 가능)
$isNoticeRaw = $input['isNotice'] ?? null;
$isNotice    = (int)$post['is_notice'];

$isSecretRaw = $input['isSecret'] ?? null;
$isSecret    = (int)$post['is_secret'];

if ($isAdminUser && $isNoticeRaw !== null)
{
    if ($isNoticeRaw === '1' || $isNoticeRaw === 1 || $isNoticeRaw === true)
    {
        $isNotice = 1;
    }
    else
    {
        $isNotice = 0;
    }
}

if ($isSecretRaw !== null)
{
    if ($isSecretRaw === '1' || $isSecretRaw === 1 || $isSecretRaw === true)
    {
        $isSecret = 1;
    }
    else
    {
        $isSecret = 0;
    }
}

$stmt = $pdo->prepare("
    UPDATE launcher_post
    SET subject = :subject,
        content_html = :content_html,
        category = :category,
		is_notice = :is_notice,
		is_secret = :is_secret,
        updated_at = :updated_at
    WHERE id = :id
");
$stmt->execute([
    ':subject'      => $subject,
    ':content_html' => $contentHtml,
    ':category'     => ($category !== '' ? $category : null),
	':is_notice'    => $isNotice,
	':is_secret'    => $isSecret,
    ':updated_at'   => $now,
    ':id'           => $postId,
]);

json_response([
    'success' => true,
]);
