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

$commentId   = isset($input['commentId']) ? (int)$input['commentId'] : 0;
$contentHtml = isset($input['contentHtml']) ? (string)$input['contentHtml'] : '';

if ($commentId <= 0 || $contentHtml === '') {
    json_error('commentId와 내용은 필수입니다.', 400);
}

$pdo = get_pdo_launcher();

// 댓글 조회
$stmt = $pdo->prepare("
    SELECT id, author_login, is_deleted
    FROM launcher_comment
    WHERE id = :id
    LIMIT 1
");
$stmt->execute([':id' => $commentId]);
$comment = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$comment || (int)$comment['is_deleted'] === 1) {
    json_error('존재하지 않거나 삭제된 댓글입니다.', 404);
}

// 본인 댓글인지 확인
$isAuthorUser = (strcasecmp($comment['author_login'], $accountLogin) === 0);

if (!$isAuthorUser && !$isAdminUser) {
    json_error('자신의 댓글만 수정할 수 있습니다.', 403);
}

$now = date('Y-m-d H:i:s');

$stmt = $pdo->prepare("
    UPDATE launcher_comment
    SET content_html = :content_html,
        updated_at   = :updated_at
    WHERE id = :id
");
$stmt->execute([
    ':content_html' => $contentHtml,
    ':updated_at'   => $now,
    ':id'           => $commentId,
]);

json_response([
    'success' => true,
]);
