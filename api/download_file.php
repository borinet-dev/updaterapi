<?php
// /api/download_file.php
// 업로드된 첨부 파일을 "원래 파일명"으로 다운로드시키기 위한 엔드포인트
//
// 파라미터:
//   f = Launcher_Attach/2025/11/files/20251124_103525_xxxx.ext (upload_file.php 가 내려준 relativePath)
//   n = 원래 파일명 (예: DSETUP.dll)

$relativePath = isset($_GET['f']) ? $_GET['f'] : '';
$originalName = isset($_GET['n']) ? $_GET['n'] : '';

if ($relativePath === '') {
    http_response_code(400);
    echo '잘못된 요청입니다. (f 없음)';
    exit;
}

// 간단한 필터링 (널문자 제거, 앞쪽 슬래시 제거)
$relativePath = str_replace("\0", '', $relativePath);
$relativePath = ltrim($relativePath, '/');

// 반드시 Launcher_Attach/ 로 시작하는지만 허용 (디렉토리 탈출 방지)
if (strpos($relativePath, 'Launcher_Attach/') !== 0) {
    http_response_code(400);
    echo '잘못된 경로입니다.';
    exit;
}

// upload_file.php 와 동일한 방식으로 루트 결정
if (!empty($_SERVER['DOCUMENT_ROOT'])) {
    $rootDir = rtrim($_SERVER['DOCUMENT_ROOT'], '/');
} else {
    $rootDir = dirname(__DIR__);
}

$filePath = $rootDir . '/' . $relativePath;

if (!is_file($filePath) || !is_readable($filePath)) {
    http_response_code(404);
    echo '파일을 찾을 수 없습니다.';
    exit;
}

// n 이 비어 있으면, 저장된 파일명이라도 사용
if ($originalName === '') {
    $originalName = basename($filePath);
}

// 헤더에 넣기 전에 위험한 문자 제거
$originalName = str_replace(["\r", "\n", "\"", "\\"], '', $originalName);
if ($originalName === '') {
    $originalName = basename($filePath);
}

// RFC 5987 형식으로 UTF-8 파일명 처리
$encodedName = rawurlencode($originalName);

header('Content-Description: File Transfer');
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . $originalName . '"; filename*=UTF-8\'\'' . $encodedName);
header('Content-Length: ' . filesize($filePath));
header('Cache-Control: private');

readfile($filePath);
exit;
