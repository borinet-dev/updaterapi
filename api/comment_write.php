<?php
require_once __DIR__ . '/auth.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_error('POST 메서드만 허용됩니다.', 405);
}

$accountLogin = require_auth();

$input = json_decode(file_get_contents('php://input'), true);
if (!is_array($input)) {
    $input = $_POST;
}

$postId         = isset($input['postId']) ? (int)$input['postId'] : 0;
$contentHtml    = isset($input['contentHtml']) ? (string)$input['contentHtml'] : '';
$parentCommentId= isset($input['parentCommentId']) ? (int)$input['parentCommentId'] : 0;

// 런처에서 넘겨주는 선택 캐릭터 닉네임
$authorName     = isset($input['authorName']) ? trim((string)$input['authorName']) : '';

if ($authorName === '') {
    // 혹시 안 넘어오면 계정명으로 대체
    $authorName = $accountLogin;
}

if ($postId <= 0 || $contentHtml === '') {
    json_error('postId와 내용은 필수입니다.', 400);
}

$pdo = get_pdo_launcher();

// 게시글 + 게시판 확인
$stmt = $pdo->prepare("
    SELECT p.id, p.board_id,
           b.code AS board_code,
           b.isAminBoard
    FROM launcher_post p
    JOIN launcher_board b
      ON p.board_id = b.id
    WHERE p.id = :id
    LIMIT 1
");
$stmt->execute([':id' => $postId]);
$post = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$post) {
    json_error('존재하지 않거나 삭제된 게시글입니다.', 404);
}

$boardCode    = (string)$post['board_code'];
$parentId = $parentCommentId > 0 ? $parentCommentId : null;

$now = date('Y-m-d H:i:s');

$stmt = $pdo->prepare("
    INSERT INTO launcher_comment (
        post_id, parent_comment_id,
        content_html, author_login, author_name,
        created_at, updated_at
    )
    VALUES (
        :post_id, :parent_id,
        :content_html, :author_login, :author_name,
        :created_at, :updated_at
    )
");
$stmt->execute([
    ':post_id'      => $postId,
    ':parent_id'    => $parentId,
    ':content_html' => $contentHtml,
    ':author_login' => $accountLogin,
    ':author_name'  => $authorName,
    ':created_at'   => $now,
    ':updated_at'   => $now,
]);

$commentId = (int)$pdo->lastInsertId();

json_response([
    'success'   => true,
    'commentId' => $commentId,
]);
