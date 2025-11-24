<?php
require_once __DIR__ . '/auth.php';

// post_write.php 와 동일하게 json_response 보급
if (!function_exists('json_response')) {
    function json_response(array $payload, int $statusCode = 200): void
    {
        http_response_code($statusCode);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($payload, JSON_UNESCAPED_UNICODE);
        exit;
    }
}

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    json_error('GET 메서드만 허용됩니다.', 405);
}

$postId = isset($_GET['postId']) ? (int)$_GET['postId'] : 0;

if ($postId <= 0) {
    json_error('postId가 필요합니다.', 400);
}

$pdo = get_pdo_launcher();

// 게시글 존재 여부 확인 (삭제 여부 포함)
$stmt = $pdo->prepare("
    SELECT id
    FROM launcher_post
    WHERE id = :id
    LIMIT 1
");
$stmt->execute([':id' => $postId]);
$post = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$post) {
    json_error('존재하지 않거나 삭제된 게시글입니다.', 404);
}

// 댓글 목록 조회 (삭제되지 않은 것만, 작성일 오름차순)
$stmt = $pdo->prepare("
    SELECT id,
           post_id,
           parent_comment_id,
           content_html,
           author_login,
           author_name,
           created_at
    FROM launcher_comment
    WHERE post_id = :post_id
    ORDER BY created_at ASC, id ASC
");
$stmt->execute([':post_id' => $postId]);

$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

$comments = [];
foreach ($rows as $row) {
    $comments[] = [
        'id'              => (int)$row['id'],
        'postId'          => (int)$row['post_id'],
        'parentCommentId' => $row['parent_comment_id'] !== null ? (int)$row['parent_comment_id'] : null,
        'author'        => $row['author_name'] ?? '',
	    'authorLogin'   => $row['author_login'] ?? '',
        'contentHtml'     => (string)$row['content_html'],
        'createdAtText'   => $row['created_at'] !== null ? substr($row['created_at'], 0, 16) : '',
    ];
}

json_response($comments);