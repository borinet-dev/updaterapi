<?php
require_once __DIR__ . '/auth.php';

$token = get_token_from_request();
if ($token === null || $token === '') {
    json_error('토큰이 없습니다.', 400);
}

$pdo = get_pdo_launcher();
$stmt = $pdo->prepare("DELETE FROM launcher_session WHERE session_token = :token");
$stmt->execute([':token' => $token]);

json_response([
    'success' => true,
]);
