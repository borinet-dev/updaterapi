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

    // ─ 게시판 정보 ─
    $stmt = $pdo->prepare("
        SELECT id, code, name, category, isAminBoard, show_author, show_date, allow_file, isSecretBoard, is_reward
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
	$isAdminBoard = (bool)$board['isAminBoard'];
	$allowFile  = (bool)$board['allow_file'];
	$isSecretBoard   = (bool)$board['isSecretBoard'];
	$isReward   = (bool)$board['is_reward'];

    $pageSize = 10;

    // ─ 공지 / 일반 글 수 ─
    $stmt = $pdo->prepare("
        SELECT COUNT(*)
        FROM launcher_post
        WHERE board_id = :board_id
          AND is_notice = 1
    ");
    $stmt->execute([':board_id' => $boardId]);
    $noticeCountAll = (int)$stmt->fetchColumn();

    $stmt = $pdo->prepare("
        SELECT COUNT(*)
        FROM launcher_post
        WHERE board_id = :board_id
          AND is_notice = 0
    ");
    $stmt->execute([':board_id' => $boardId]);
    $normalCount = (int)$stmt->fetchColumn();

    // 첫 페이지에서 실제로 노출할 공지 개수 (최대 10개)
    $noticeCountFirst = min($noticeCountAll, $pageSize);
    // 첫 페이지에서 일반 글이 차지할 수 있는 슬롯 수

	$slotsFirstPage   = max($pageSize - $noticeCountFirst, 0);

    if ($normalCount <= 0) {
        // 일반 글이 없어도 최소 1페이지 (공지 전용)
        $totalPages = 1;
    } else {
        if ($slotsFirstPage >= $normalCount) {
            // 첫 페이지 안에서 일반 글이 모두 들어가는 경우
            $totalPages = 1;
        } else {
            // 나머지 일반 글은 이후 페이지에서 pageSize 단위로 분배
            $remainingNormals = $normalCount - $slotsFirstPage;
            $totalPages = 1 + (int)ceil($remainingNormals / $pageSize);
        }
    }

    if ($page > $totalPages) {
        $page = $totalPages;
    }

    // 현재 페이지의 일반 글 offset / limit 계산
    if ($page === 1) {
        $normalOffset = 0;
        $normalLimit  = $slotsFirstPage;
    } else {
        $normalOffset = $slotsFirstPage + ($page - 2) * $pageSize;
        $normalLimit  = $pageSize;
    }

    $posts = [];

    // ─ 1) 첫 페이지: 공지 글 먼저 (최대 $pageSize 개 내에서 상단 고정) ─
    if ($page === 1 && $noticeCountFirst > 0) {
        $stmt = $pdo->prepare("
            SELECT p.id, p.is_notice, p.is_secret, p.category, p.subject,
                   p.author_login, p.author_name,
                   p.created_at, p.content_html,
                   (
                       SELECT COUNT(*)
                       FROM launcher_comment c
                       WHERE c.post_id = p.id
                   ) AS comment_count
            FROM launcher_post p
            WHERE p.board_id = :board_id
              AND p.is_notice = 1
            ORDER BY p.created_at DESC
            LIMIT :limit
        ");
        $stmt->bindValue(':board_id', $boardId, PDO::PARAM_INT);
        $stmt->bindValue(':limit', $noticeCountFirst, PDO::PARAM_INT);
        $stmt->execute();

        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $authorLogin = isset($row['author_login']) ? (string)$row['author_login'] : '';
            $authorName  = isset($row['author_name'])  ? (string)$row['author_name']  : '';
            $author      = $authorName !== '' ? $authorName : $authorLogin;

			$posts[] = [
                'id'           => (int)$row['id'],
                'isNotice'     => true,
                'isSecret'     => (bool)$row['is_secret'],
                'category'     => $row['category'],
                'subject'      => $row['subject'],
                'author'       => $author,
                'authorLogin'  => $authorLogin,
                'createdAt'    => $row['created_at'],
                'contentHtml'  => $row['content_html'],
                'rawHtml'      => $row['content_html'],
                'commentCount' => isset($row['comment_count']) ? (int)$row['comment_count'] : 0,
            ];
        }
    }

    // ─ 2) 일반 글 ─
    if ($normalLimit > 0 && $normalCount > 0) {
        $stmt = $pdo->prepare("
            SELECT p.id, p.is_notice, p.is_secret, p.category, p.subject,
                   p.author_login, p.author_name,
                   p.created_at, p.content_html,
                   (
                       SELECT COUNT(*)
                       FROM launcher_comment c
                       WHERE c.post_id = p.id
                   ) AS comment_count
            FROM launcher_post p
            WHERE p.board_id = :board_id
              AND p.is_notice = 0
            ORDER BY p.created_at DESC
            LIMIT :limit OFFSET :offset
        ");
        $stmt->bindValue(':board_id', $boardId, PDO::PARAM_INT);
        $stmt->bindValue(':limit',    $normalLimit, PDO::PARAM_INT);
        $stmt->bindValue(':offset',   $normalOffset, PDO::PARAM_INT);
        $stmt->execute();

        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
			$authorLogin = isset($row['author_login']) ? (string)$row['author_login'] : '';
			$authorName  = isset($row['author_name'])  ? (string)$row['author_name']  : '';
			$author      = $authorName !== '' ? $authorName : $authorLogin;

			$posts[] = [
				'id'           => (int)$row['id'],
				'isNotice'     => (bool)$row['is_notice'],
				'isSecret'     => (bool)$row['is_secret'],
				'category'     => $row['category'],
				'subject'      => $row['subject'],
				'author'       => $author,
				'authorLogin'  => $authorLogin,
				'createdAt'    => $row['created_at'],
				'contentHtml'  => $row['content_html'],
                'rawHtml'      => $row['content_html'],
				'commentCount' => isset($row['comment_count']) ? (int)$row['comment_count'] : 0,
			];
		}
    }

	// ─ 게시판 카테고리 옵션 배열 생성 ─
    // launcher_board.category 컬럼: "건의 | 버그제보" 형태라고 가정
	
$categoryOptions = [];
    if (!empty($board['category'])) {
        foreach (explode('|', $board['category']) as $part) {
            $name = trim($part);
            if ($name !== '') {
                $categoryOptions[] = $name;
            }
        }
    }

    // C#에서 바로 읽게: success + 나머지 필드
    $response = [
        'success'      => true,
        'isAdminBoard' => $isAdminBoard ? 1 : 0,
        'showAuthor' => $showAuthor ? 1 : 0,
        'showDate' => $showDate ? 1 : 0,
		'allowFile'    => $allowFile ? 1 : 0,
		'isSecretBoard' => $isSecretBoard ? 1 : 0,
		'is_reward'     => $isReward ? 1 : 0,
		// 런처에서 글쓰기/수정 시 카테고리 드롭다운 표시에 사용
        'categoryOptions' => $categoryOptions,
        'board'        => [
            'code'         => $board['code'],
            'name'         => $board['name'],
            'category'     => $board['category'],
            'isAdminBoard' => $isAdminBoard,
            'showAuthor'   => $showAuthor,
            'showDate'     => $showDate,
			'allowFile'    => $allowFile,
			'isSecretBoard' => $isSecretBoard,
			'is_reward'    => $isReward,
        ],
        'page'        => $page,
        'totalPages'  => $totalPages,
        'posts'       => $posts,
    ];

    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($response, JSON_UNESCAPED_UNICODE);
    exit;

} catch (Exception $e) {
    // PHP 에러가 HTML로 안 튀게 JSON으로 고정
    json_error('board_list error: '.$e->getMessage());
}
