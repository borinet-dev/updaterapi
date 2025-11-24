<?php
// DB 접속 정보
define('DB_HOST', '127.0.0.1');
define('DB_USER', 'root');
define('DB_PASS', 'wlsxo4451');

// 런처 전용 테이블이 들어 있는 DB
define('DB_NAME_LAUNCHER', 'launcher');  // ← 런처 전용 DB

// 게임 DB (accounts, characters)
define('DB_NAME_GAME', 'l2jserver');

// 세션 설정
define('SESSION_LIFETIME', 86400 * 7);   // 7일
define('AUTH_TOKEN_HEADER', 'X-Auth-Token');

// CORS / 공통 헤더
// API에서는 JSON 헤더를 보내고,
// acm.php처럼 라이브러리 용도로 include 할 때는
// 상단에서 LAUNCHER_CONFIG_AS_LIBRARY 상수를 정의해
// 헤더 전송을 생략합니다.
if (!defined('LAUNCHER_CONFIG_AS_LIBRARY'))
{
    header('Content-Type: application/json; charset=utf-8');
}