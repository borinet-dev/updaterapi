<?php
// /api/online_count.php
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/response.php';

try {
    // 게임 DB에서 현재 접속자 조회
    $pdo = get_pdo_game();
    $stmt = $pdo->query("SELECT COUNT(*) AS cnt FROM characters WHERE online = 1");
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $online = (int)($row['cnt'] ?? 0);

    // response.php 형식에 맞춰 성공 응답
    // 예: { "success": true, "message": "ok", "data": { "online": 123 } }
    json_success('ok', ['online' => $online]);
} catch (Throwable $e) {
    // 필요하면 로그 남기기
    // error_log($e->getMessage());
    json_error('현재 접속자 수를 가져오는 중 오류가 발생했습니다.');
}
