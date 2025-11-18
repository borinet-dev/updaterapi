<?php
require_once __DIR__ . "/db.php";
require_once __DIR__ . "/response.php";

try {
    $pdo = get_pdo_launcher(); // launcher DB 연결

    // launcher_post + launcher_board 조인해서 notice / update 5개
    $stmt = $pdo->prepare("
        SELECT p.subject, p.content_html, p.created_at, b.code
        FROM launcher_post p
        JOIN launcher_board b ON p.board_id = b.id
        WHERE b.code IN ('notice', 'update')
        ORDER BY p.created_at DESC
        LIMIT 5
    ");
    $stmt->execute();

    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // C# DTO(BoardPostDto)에 맞게 변환
    $list = [];
    foreach ($rows as $r) {
        $code = $r["code"];
        if ($code === "notice") {
            $type = "공지사항";
        } elseif ($code === "update") {
            $type = "패치노트";
        } else {
            $type = $code;
        }

        $created = $r["created_at"];
        $ts = strtotime($created);

        $list[] = [
            "Type" => $type,
            "Subject" => $r["subject"],
            "RawHtml" => $r["content_html"],
            "Category" => null,
            "IsNotice" => false,
            "Author" => null,
            // C# DateTime 파싱 가능하도록 ISO8601로
            "Date" => $ts ? date("c", $ts) : null,
            "DateText" => $ts ? date("Y-m-d", $ts) : null
        ];
    }

    echo json_encode($list, JSON_UNESCAPED_UNICODE);
    exit;

} catch (Exception $e) {
    json_error("DB 오류: " . $e->getMessage());
}
