<?php
require_once __DIR__ . "/db.php";
require_once __DIR__ . "/response.php";

try {
    $pdo = get_pdo_launcher(); // launcher DB 연결

    // 홈 화면에 표시할 게시판 코드 목록 (순서 포함)
    $boardCodes = ['notice', 'update'];

    // code -> name 매핑 (launcher_board.name 기준)
    $boardNameMap = [];
    if (!empty($boardCodes)) {
        $in = implode(',', array_fill(0, count($boardCodes), '?'));
        $stmtBoard = $pdo->prepare("SELECT code, name FROM launcher_board WHERE code IN ($in)");
        $stmtBoard->execute($boardCodes);
        while ($row = $stmtBoard->fetch(PDO::FETCH_ASSOC)) {
            $boardNameMap[$row['code']] = $row['name'];
        }
    }

    // 공지 5개, 패치노트 5개 따로 뽑아서 하나의 리스트로 합치기
    $list = [];

    foreach ($boardCodes as $code) {
        $stmt = $pdo->prepare("
            SELECT p.id,
                   p.subject,
                   p.content_html,
                   p.created_at,
                   b.code,
                   b.name,
                   (
                       SELECT COUNT(*)
                       FROM launcher_comment c
                       WHERE c.post_id = p.id
                   ) AS comment_count
            FROM launcher_post p
            JOIN launcher_board b ON p.board_id = b.id
            WHERE b.code = :code
            ORDER BY p.created_at DESC
            LIMIT 5
        ");
        $stmt->execute([':code' => $code]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($rows as $r) {
            $created = $r["created_at"];
            $ts = strtotime($created);

            $boardCode = $r['code'];
            $boardName = $boardNameMap[$boardCode] ?? ($r['name'] ?? $boardCode);

            $list[] = [
                // C# BoardPostDto.Id
                "Id"        => isset($r["id"]) ? (int)$r["id"] : 0,
                // C# BoardPostDto.BoardCode (런처에서 게시판 구분용)
                "BoardCode" => $boardCode,
                // C# BoardPostDto.Type (표시용 게시판 이름)
                "Type"      => $boardName,
                // C# BoardPostDto.Subject / RawHtml
                "Subject"   => $r["subject"],
                "RawHtml"   => $r["content_html"],
                // 홈 화면에서는 사용하지 않지만 DTO 호환용 필드들
                "Category"  => null,
                "IsNotice"  => false,
                "Author"    => null,
                "AuthorLogin" => null,
                // 댓글 수
                "CommentCount" => isset($r["comment_count"]) ? (int)$r["comment_count"] : 0,
                // C# DateTime 파싱 가능하도록 ISO8601로
                "Date"     => $ts ? date("c", $ts) : null,
                "DateText" => $ts ? date("Y-m-d", $ts) : null,
            ];
        }
    }

    echo json_encode($list, JSON_UNESCAPED_UNICODE);
    exit;

} catch (Exception $e) {
    json_error("DB 오류: " . $e->getMessage());
}
