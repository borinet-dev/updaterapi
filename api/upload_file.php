<?php
// /api/upload_file.php
// 이미지 + 일반 파일 공용 업로드 엔드포인트
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/response.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_error('POST 메서드만 허용됩니다.');
}

// 로그인 체크 (업로더 계정ID 확보용)
$accountLogin = require_auth();

// 호스트 설정: config.ini 의 AttachHost 사용, 없으면 기본값
$configPath = __DIR__ . '/config.ini';
$host = 'l2jliberty.org'; // 기본값

if (is_file($configPath)) {
    $config = parse_ini_file($configPath);
    if (!empty($config['AttachHost'])) {
        $host = $config['AttachHost'];
    }
}

// 파일 존재 확인 (필드명: file 또는 image)
$file = null;
if (!empty($_FILES['file']) && is_array($_FILES['file'])) {
    $file = $_FILES['file'];
} elseif (!empty($_FILES['image']) && is_array($_FILES['image'])) {
    $file = $_FILES['image'];
}

if ($file === null) {
    json_error('업로드할 파일이 없습니다.');
}

// 업로드 에러 체크
switch ($file['error']) {
    case UPLOAD_ERR_OK:
        break;
    case UPLOAD_ERR_INI_SIZE:
    case UPLOAD_ERR_FORM_SIZE:
        json_error('업로드 가능한 최대 용량을 초과했습니다.');
    case UPLOAD_ERR_PARTIAL:
        json_error('파일이 온전하게 전송되지 않았습니다.');
    case UPLOAD_ERR_NO_FILE:
        json_error('전송된 파일이 없습니다.');
    default:
        json_error('파일 업로드 중 오류가 발생했습니다. (code: ' . $file['error'] . ')');
}

// 용량 제한 (기본 20MB)
if ($file['size'] <= 0) {
    json_error('비어 있는 파일입니다.');
}
if ($file['size'] > 20 * 1024 * 1024) {
    json_error('최대 20MB까지 업로드할 수 있습니다.');
}

// 파일명 / 확장자
$originalName = $file['name'] ?? 'file';
$ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));

// 이미지 여부 판별
$imageExt = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
$isImage = in_array($ext, $imageExt, true);

// 업로드 루트 디렉토리 설정
// 가능하면 웹서버 DOCUMENT_ROOT 를 기준으로 사용, 없으면 /api 상위 폴더 사용
if (!empty($_SERVER['DOCUMENT_ROOT'])) {
    $rootDir = rtrim($_SERVER['DOCUMENT_ROOT'], '/');
} else {
    // fallback: /api 상위 = 웹루트 가정
    $rootDir = dirname(__DIR__);
}

// Launcher_Attach/년/월/images|files 구조로 저장
$uploadRoot = $rootDir . '/Launcher_Attach';

$year  = date('Y');
$month = date('m');
$datePath = $year . '/' . $month;
$typeDir  = $isImage ? 'images' : 'files';

$targetDir = $uploadRoot . '/' . $datePath . '/' . $typeDir;

// 디렉토리 생성
if (!is_dir($targetDir)) {
    if (!mkdir($targetDir, 0775, true) && !is_dir($targetDir)) {
        json_error('업로드 디렉토리를 생성할 수 없습니다.');
    }
}

// 파일명: 20251118_223045_abcd1234.ext
$timestamp   = date('Ymd_His');
$randomToken = bin2hex(random_bytes(4)); // 8자리
$baseName    = $timestamp . '_' . $randomToken;

$tmpPath = $file['tmp_name'];

// 1) 먼저 원본을 최종 위치에 저장
$originalPath = $targetDir . '/' . $baseName . '.' . $ext;
if (!move_uploaded_file($tmpPath, $originalPath)) {
    json_error('파일 저장에 실패했습니다.');
}

// 최종 노출할 파일 경로 (기본은 원본)
$finalPath = $originalPath;

// 2) 이미지인 경우 webp 변환 시도 (gif/webp 제외)
if ($isImage && !in_array($ext, ['gif', 'webp'], true)) {
    if (function_exists('imagewebp')) {
        $image = false;
        switch ($ext) {
            case 'jpg':
            case 'jpeg':
                $image = @imagecreatefromjpeg($originalPath);
                break;
            case 'png':
                $image = @imagecreatefrompng($originalPath);
                break;
        }

        if ($image !== false) {
            $webpPath = $targetDir . '/' . $baseName . '.webp';
            if (@imagewebp($image, $webpPath, 85)) {
                $finalPath = $webpPath;
            }
            imagedestroy($image);
        }
    }
}

// 퍼블릭 URL 생성 (최종 경로 기준)
$relativePath = 'Launcher_Attach/' . $datePath . '/' . $typeDir . '/' . basename($finalPath);

// 접속 프로토콜에 따라 자동 선택 (http / https)
$scheme    = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
$publicUrl = $scheme . '://' . $host . '/' . $relativePath;

// 이미지/파일별로 url 의미 분리
// - 이미지 : url = 실제 파일 경로 + ?n=원래파일명 (수정 화면에서 이름 복원용)
// - 일반파일 : url = download_file.php (다운로드 시 원래 파일명 유지)
if ($isImage) {
    $url = $publicUrl . '?n=' . rawurlencode($originalName);
} else {
    $url = $scheme . '://' . $host . '/api/download_file.php'
        . '?f=' . rawurlencode($relativePath)
        . '&n=' . rawurlencode($originalName);
}

// 참고용 실제 저장 경로(필요 없으면 무시해도 됨)
$fileUrl = $publicUrl;

// 최종 응답
header('Content-Type: application/json; charset=utf-8');
json_success([
    'url'           => $url,      // 런처/게시판에서 사용하는 href
    'file_url'      => $fileUrl,  // 실제 저장 경로 (관리용)
    'original_name' => $originalName,
    'is_image'      => $isImage ? 1 : 0,
]);
