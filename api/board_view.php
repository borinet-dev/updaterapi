<?php
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/response.php';

$postId = isset($_GET['postId']) ? (int)$_GET['postId'] : 0;
if ($postId <= 0) {
    json_error('postId가 필요합니다.', 400);
}

$pdo = get_pdo_launcher();

// 게시글 + 게시판 정보
$stmt = $pdo->prepare("
    SELECT p.id, p.board_id, p.is_notice, p.category,
           p.subject, p.content_html,
           p.author_login, p.author_name,
           p.created_at, p.updated_at,
           b.code AS board_code, b.name AS board_name,
           b.show_author, b.show_date, b.allow_reply
    FROM launcher_post p
    JOIN launcher_board b
      ON p.board_id = b.id
    WHERE p.id = :id
      AND p.is_deleted = 0
    LIMIT 1
");
$stmt->execute([':id' => $postId]);
$post = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$post) {
    json_error('게시글을 찾을 수 없습니다.', 404);
}

$boardCode   = $post['board_code'];
$boardName   = $post['board_name'];
$isNotice    = (bool)$post['is_notice'];
$showAuthor  = (bool)$post['show_author'];
$showDate    = (bool)$post['show_date'];
$allowReply  = (bool)$post['allow_reply'];

// 댓글
$comments = [];
if ($allowReply) {
    $stmt = $pdo->prepare("
        SELECT id, content_html, author_login, author_name, created_at, updated_at
        FROM launcher_comment
        WHERE post_id = :post_id
          AND is_deleted = 0
        ORDER BY created_at ASC
    ");
    $stmt->execute([':post_id' => $postId]);
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $comments[] = [
			'id'          => (int)$row['id'],
			'contentHtml' => $row['content_html'],
			'author'      => $row['author_name'],
			'authorLogin' => $row['author_login'], // ← 추가
			'createdAt'   => $row['created_at'],
		];
    }
}

json_response([
    'success' => true,
    'post' => [
        'id'         => (int)$post['id'],
        'boardCode'  => $boardCode,
        'boardName'  => $boardName,
        'isNotice'   => $isNotice,
        'category'   => $post['category'],
        'subject'    => $post['subject'],
        'contentHtml'=> $post['content_html'],
        'author'     => $post['author_name'],
        'authorLogin'=> $post['author_login'],
        'createdAt'  => $post['created_at'],
        'updatedAt'  => $post['updated_at'],
        'showAuthor' => $showAuthor,
        'showDate'   => $showDate,
        'allowReply' => $allowReply,
    ],
    'comments' => $comments,
]);
