<?php
// /api/launcher_board.php
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/response.php';

try {
    $pdo = get_pdo_launcher();

    // launcher_board 테이블에서 code, name 만 조회
    $sql = "SELECT code, name
              FROM launcher_board";
    $stmt = $pdo->query($sql);

    $boards = [];

    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $code = isset($row['code']) ? trim((string)$row['code']) : '';
        if ($code === '') {
            continue; // code 없는 행은 무시
        }

        $name = isset($row['name']) ? trim((string)$row['name']) : '';
        if ($name === '') {
            $name = $code; // name 없으면 code 그대로 사용
        }

        $boards[] = [
            'code' => $code,
            'name' => $name,
        ];
    }

    // online_count.php 와 동일하게 json_success 사용
    // 결과 JSON 예:
    // { "success": true, "message": "ok", "data": { "boards": [ { "code": "...", "name": "..." }, ... ] } }
    json_success('ok', ['boards' => $boards]);
} catch (Throwable $e) {
    // 필요 시 로그
    // error_log($e->getMessage());
    json_error('게시판 목록을 가져오는 중 오류가 발생했습니다.');
}