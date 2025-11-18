<?php
// /api/board_list.php

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/response.php';

try {
    $boardCode = isset($_GET['board']) ? trim((string)$_GET['board']) : '';
    $page      = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    if ($page < 1) {
        $page = 1;
    }

    if ($boardCode === '') {
        json_error('board 파라미터가 없습니다.', 400);
    }

    $pdo = get_pdo_launcher();

    // ─ 게시판 정보 ─
    $stmt = $pdo->prepare("
        SELECT id, code, name, show_author, show_date, allow_write, allow_reply
        FROM launcher_board
        WHERE code = :code
        LIMIT 1
    ");
    $stmt->execute([':code' => $boardCode]);
    $board = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$board) {
        json_error('존재하지 않는 게시판입니다.', 404);
    }

    $boardId    = (int)$board['id'];
    $showAuthor = (bool)$board['show_author'];
    $showDate   = (bool)$board['show_date'];

    $pageSize = 10;

    // ─ 공지 제외 전체 글 수 ─
    //  is_deleted 가 NULL 인 기존 데이터도 살리기 위해 COALESCE 사용
    $stmt = $pdo->prepare("
        SELECT COUNT(*)
        FROM launcher_post
        WHERE board_id = :board_id
          AND COALESCE(is_deleted, 0) = 0
          AND is_notice = 0
    ");
    $stmt->execute([':board_id' => $boardId]);
    $totalCount = (int)$stmt->fetchColumn();

    $totalPages = $totalCount > 0 ? (int)ceil($totalCount / $pageSize) : 1;
    if ($page > $totalPages) {
        $page = $totalPages;
    }
    $offset = ($page - 1) * $pageSize;

    $posts = [];

    // ─ 1) 첫 페이지: 공지 글 먼저 ─
    if ($page === 1) {
        $stmt = $pdo->prepare("
            SELECT p.id, p.is_notice, p.category, p.subject,
                   p.author_login, p.author_name,
                   p.created_at, p.content_html,
                   (
                       SELECT COUNT(*)
                       FROM launcher_comment c
                       WHERE c.post_id = p.id
                         AND COALESCE(c.is_deleted, 0) = 0
                   ) AS comment_count
            FROM launcher_post p
            WHERE p.board_id = :board_id
              AND COALESCE(p.is_deleted, 0) = 0
              AND p.is_notice = 1
            ORDER BY p.created_at DESC
        ");
        $stmt->execute([':board_id' => $boardId]);

        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $authorLogin = isset($row['author_login']) ? (string)$row['author_login'] : '';
            $authorName  = isset($row['author_name'])  ? (string)$row['author_name']  : '';
            $author      = $authorName !== '' ? $authorName : $authorLogin;

			$posts[] = [
                'id'           => (int)$row['id'],
                'isNotice'     => true,
                'category'     => $row['category'],
                'subject'      => $row['subject'],
                'author'       => $author,
                'authorLogin'  => $authorLogin, // 🔹 추가
                'createdAt'    => $row['created_at'],
                'contentHtml'  => $row['content_html'],
                'commentCount' => isset($row['comment_count']) ? (int)$row['comment_count'] : 0,
            ];
        }
    }

    // ─ 2) 일반 글 ─
    $stmt = $pdo->prepare("
        SELECT p.id, p.is_notice, p.category, p.subject,
               p.author_login, p.author_name,
               p.created_at, p.content_html,
               (
                   SELECT COUNT(*)
                   FROM launcher_comment c
                   WHERE c.post_id = p.id
                     AND COALESCE(c.is_deleted, 0) = 0
               ) AS comment_count
        FROM launcher_post p
        WHERE p.board_id = :board_id
          AND COALESCE(p.is_deleted, 0) = 0
          AND p.is_notice = 0
        ORDER BY p.created_at DESC
        LIMIT :limit OFFSET :offset
    ");
    $stmt->bindValue(':board_id', $boardId, PDO::PARAM_INT);
    $stmt->bindValue(':limit',    $pageSize, PDO::PARAM_INT);
    $stmt->bindValue(':offset',   $offset,   PDO::PARAM_INT);
    $stmt->execute();

    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $authorLogin = isset($row['author_login']) ? (string)$row['author_login'] : '';
        $authorName  = isset($row['author_name'])  ? (string)$row['author_name']  : '';
        $author      = $authorName !== '' ? $authorName : $authorLogin;

        $posts[] = [
            'id'           => (int)$row['id'],
            'isNotice'     => (bool)$row['is_notice'],
            'category'     => $row['category'],
            'subject'      => $row['subject'],
            'author'       => $author,
			'authorLogin'  => $authorLogin,
            'createdAt'    => $row['created_at'],
            'contentHtml'  => $row['content_html'],
            'commentCount' => isset($row['comment_count']) ? (int)$row['comment_count'] : 0,
        ];
    }

    // C#에서 바로 읽게: success + 나머지 필드
    $response = [
        'success' => true,
        'board' => [
            'code'       => $board['code'],
            'name'       => $board['name'],
            'showAuthor' => $showAuthor,
            'showDate'   => $showDate,
        ],
        'page'       => $page,
        'totalPages' => $totalPages,
        'posts'      => $posts,
    ];

    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($response, JSON_UNESCAPED_UNICODE);
    exit;

} catch (Exception $e) {
    // PHP 에러가 HTML로 안 튀게 JSON으로 고정
    json_error('board_list error: '.$e->getMessage());
}
