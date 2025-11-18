<?php
// includes/send_email.php

// ----- 출력/헤더: 오직 JSON만 -----
while (ob_get_level() > 0) { @ob_end_clean(); }
if (!headers_sent()) {
    header('Content-Type: application/json; charset=UTF-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
}

// ----- 입력값 -----
$email = isset($_POST['email']) ? trim($_POST['email']) : '';
$code  = isset($_POST['code'])  ? trim($_POST['code'])  : '';

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(['success'=>false, 'message'=>'올바른 이메일을 입력해주세요.'], JSON_UNESCAPED_UNICODE);
    exit;
}
if ($code === '') {
    echo json_encode(['success'=>false, 'message'=>'인증번호가 없습니다.'], JSON_UNESCAPED_UNICODE);
    exit;
}

// ----- 설정파일 읽기: includes/email_config.txt -----
// 포맷 예시 (Key=Value 라인/INI 둘다 허용):
// FROM_NAME=My Server
// FROM_EMAIL=no-reply@example.com
// SUBJECT=[인증] 인증번호 안내
// BODY=인증번호는 {CODE} 입니다. 유효시간 내에 입력하세요.
$configPath = __DIR__ . '/email_config.txt';
$cfg = [
    'FROM_NAME'  => 'Admin',
    'FROM_EMAIL' => 'no-reply@example.com',
    'SUBJECT'    => '[인증] 인증번호 안내',
    'BODY'       => "인증번호는 {CODE} 입니다.\n유효시간 내에 입력하세요.",
];

if (is_file($configPath)) {
    $raw = @file_get_contents($configPath);
    if ($raw !== false) {
        $raw = trim($raw);

        // 1) INI로 파싱 시도
        $ini = @parse_ini_string($raw, false, INI_SCANNER_RAW);
        if (is_array($ini) && !empty($ini)) {
            foreach ($ini as $k=>$v) {
                $k = strtoupper(trim($k));
                if ($k !== '') $cfg[$k] = $v;
            }
        } else {
            // 2) Key=Value 라인 파싱
            $lines = preg_split('/\r\n|\r|\n/', $raw);
            foreach ($lines as $line) {
                if (trim($line) === '' || strpos($line, '=') === false) continue;
                list($k, $v) = explode('=', $line, 2);
                $k = strtoupper(trim($k));
                $v = trim($v);
                if ($k !== '') $cfg[$k] = $v;
            }
        }
    }
}

// ----- 메일 본문/제목/헤더 구성 -----
$subject = str_replace('{CODE}', $code, $cfg['SUBJECT']);
$body    = str_replace('{CODE}', $code, $cfg['BODY']);

// 기본 mail() 사용 (SMTP 필요하면 PHPMailer 등으로 교체)
$fromName  = $cfg['FROM_NAME'];
$fromEmail = $cfg['FROM_EMAIL'];

// 헤더 만들기
$encodedFromName = '=?UTF-8?B?'.base64_encode($fromName).'?=';
$headers  = "MIME-Version: 1.0\r\n";
$headers .= "Content-Type: text/plain; charset=UTF-8\r\n";
$headers .= "From: {$encodedFromName} <{$fromEmail}>\r\n";
$headers .= "Reply-To: {$fromEmail}\r\n";
$headers .= "X-Mailer: PHP/".phpversion();

// ----- 발송 -----
try {
    $ok = @mail($email, '=?UTF-8?B?'.base64_encode($subject).'?=', $body, $headers);
    if ($ok) {
        echo json_encode(['success'=>true, 'message'=>'OK'], JSON_UNESCAPED_UNICODE);
    } else {
        echo json_encode(['success'=>false, 'message'=>'메일 발송 실패(mail 함수)'], JSON_UNESCAPED_UNICODE);
    }
} catch (Throwable $e) {
    // 필요하면 로그: file_put_contents(__DIR__.'/email_error.log', date('c').' '.$e->getMessage()."\n", FILE_APPEND);
    echo json_encode(['success'=>false, 'message'=>'메일 발송 실패: '.$e->getMessage()], JSON_UNESCAPED_UNICODE);
}
exit;
