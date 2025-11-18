<?php
// /api/upload_image.php
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/response.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_error('POST 메서드만 허용됩니다.');
}

// 로그인 체크 (업로더 계정ID 확보용, 지금은 권한 체크만)
$accountLogin = require_auth();
$host   = 'borinet.org';

// 파일 존재 확인
if (empty($_FILES['image']) || !is_array($_FILES['image'])) {
    json_error('이미지 파일이 없습니다.');
}

$file = $_FILES['image'];

// 업로드 에러 체크
switch ($file['error']) {
    case UPLOAD_ERR_OK:
        break;
    case UPLOAD_ERR_INI_SIZE:
    case UPLOAD_ERR_FORM_SIZE:
        json_error('업로드 용량 제한을 초과했습니다.');
    case UPLOAD_ERR_NO_FILE:
        json_error('전송된 파일이 없습니다.');
    default:
        json_error('파일 업로드 중 오류가 발생했습니다. (code: ' . $file['error'] . ')');
}

// 용량 제한: 최대 10MB
if ($file['size'] <= 0) {
    json_error('비어 있는 파일입니다.');
}
if ($file['size'] > 10 * 1024 * 1024) { // 10MB
    json_error('이미지 최대 용량은 10MB 입니다.');
}

// 확장자 체크
$originalName = $file['name'] ?? 'image';
$ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));

$allowedExt = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
if (!in_array($ext, $allowedExt, true)) {
    json_error('허용되지 않은 이미지 형식입니다. (jpg, jpeg, png, gif, webp 만 가능)');
}

// 업로드 루트 디렉토리 설정
$rootDir     = dirname(__DIR__); // /api 상위 = 웹루트
$uploadRoot  = $rootDir . '/launcher_images';

$year  = date('Y');
$month = date('m');
$subDir = $year . '/' . $month;

$targetDir = $uploadRoot . '/' . $subDir;

// 디렉토리 생성
if (!is_dir($targetDir)) {
    if (!mkdir($targetDir, 0775, true) && !is_dir($targetDir)) {
        json_error('업로드 디렉토리를 생성할 수 없습니다.');
    }
}

// 파일명: 20251118_223045_abcd1234.webp
$timestamp   = date('Ymd_His');
$randomToken = bin2hex(random_bytes(4)); // 8자리
$baseName    = $timestamp . '_' . $randomToken;

// GIF는 그대로 저장, 나머지는 가급적 webp로 변환
$tmpPath = $file['tmp_name'];
$publicExt = '';
$targetPath = '';

if ($ext === 'gif') {
    // 움직이는 GIF 고려해서 그대로 저장
    $publicExt = 'gif';
    $targetPath = $targetDir . '/' . $baseName . '.gif';

    if (!move_uploaded_file($tmpPath, $targetPath)) {
        json_error('이미지 저장에 실패했습니다. (gif)');
    }
} else {
    // jpg / jpeg / png / webp → webp 변환 시도
    $publicExt = 'webp';
    $targetPath = $targetDir . '/' . $baseName . '.webp';

    // GD 확장 필수
    if (!function_exists('imagewebp')) {
        // webp 변환 불가 시, 원본 확장자로 저장 (fallback)
        $publicExt = $ext;
        $targetPath = $targetDir . '/' . $baseName . '.' . $ext;

        if (!move_uploaded_file($tmpPath, $targetPath)) {
            json_error('이미지 저장에 실패했습니다. (원본)');
        }
    } else {
        // 원본을 GD로 읽어서 webp로 저장
        switch ($ext) {
            case 'jpg':
            case 'jpeg':
                $image = @imagecreatefromjpeg($tmpPath);
                break;
            case 'png':
                $image = @imagecreatefrompng($tmpPath);
                // PNG 투명도 보존
                if ($image !== false) {
                    imagealphablending($image, true);
                    imagesavealpha($image, true);
                }
                break;
            case 'webp':
                $image = @imagecreatefromwebp($tmpPath);
                break;
            default:
                $image = false;
        }

        if ($image === false) {
            json_error('이미지 파일을 읽을 수 없습니다.');
        }

        // 필요시 리사이즈 로직 추가 가능 (현재는 원본 크기로 저장)
        $quality = 80;
        if (!imagewebp($image, $targetPath, $quality)) {
            imagedestroy($image);
            json_error('webp 변환에 실패했습니다.');
        }

        imagedestroy($image);
    }
}

// 퍼블릭 URL 생성
$relativePath = 'launcher_images/' . $subDir . '/' . basename($targetPath);

$scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
$url    = $scheme . '://' . $host . '/' . $relativePath;

// 최종 응답
json_success([
    'url' => $url,
]);
