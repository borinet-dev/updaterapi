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

// CORS 필요하면 여기에서 설정해도 됨
header('Content-Type: application/json; charset=utf-8');
