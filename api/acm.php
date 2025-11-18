<?php
ob_start();
error_reporting(0);
include __DIR__ . '/includes/config.php';
session_start();

$error = "";

// ===== IPv6 → IPv4 선호 헬퍼 =====
function prefer_ipv4($ip) {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return $ip;
    }
    // IPv4-mapped IPv6 ::ffff:x.x.x.x
    if (preg_match('/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i', $ip, $m)) {
        return $m[1];
    }
    // 6to4 2002:VVVV:WWWW::/16  → (VVVV|WWWW) 32비트를 IPv4로
    if (preg_match('/^2002:([0-9a-f]{4}):([0-9a-f]{4})/i', $ip, $m)) {
        $a = hexdec($m[1]); $b = hexdec($m[2]);
        return sprintf('%d.%d.%d.%d', ($a >> 8) & 255, $a & 255, ($b >> 8) & 255, $b & 255);
    }
    return null; // 순수 IPv6
}
function get_client_ip_v4_or_fallback() {
    // Cloudflare 사용 시 원본 IP 우선
    $raw = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? ($_SERVER['REMOTE_ADDR'] ?? '');
    $v4  = prefer_ipv4($raw);
    return $v4 ?: '0.0.0.0';
}

// PHPMailer 로더: Composer 오토로드 → 수동 로드(여러 경로)까지 시도
if (!class_exists('\\PHPMailer\\PHPMailer\\PHPMailer')) {
    $loaded = false;
    $tried  = [];
    // 1) Composer autoload 여러 위치 탐색
    $candidates = [
        __DIR__ . '/vendor/autoload.php',
        dirname(__DIR__) . '/vendor/autoload.php',
        dirname(__DIR__, 2) . '/vendor/autoload.php',
    ];
    foreach ($candidates as $auto) {
        $tried[] = $auto;
        if (is_file($auto)) {
            require_once $auto;
            if (class_exists('\\PHPMailer\\PHPMailer\\PHPMailer')) { $loaded = true; break; }
        }
    }
    // 2) 수동 로드: lib/PHPMailer/src (요청 경로)
    if (!$loaded) {
        $manualBases = [
            __DIR__ . '/lib/PHPMailer/src',
            __DIR__ . '/includes/phpmailer/src',
        ];
        foreach ($manualBases as $base) {
            $tried[] = $base . ' (manual src)';
            $files = [
                $base . '/Exception.php',
                $base . '/PHPMailer.php',
                $base . '/SMTP.php',
            ];
            $ok = true;
            foreach ($files as $f) { if (!is_file($f)) { $ok = false; break; } }
            if ($ok) {
                require_once $files[0];
                require_once $files[1];
                require_once $files[2];
                if (class_exists('\\PHPMailer\\PHPMailer\\PHPMailer')) { $loaded = true; break; }
            }
        }
    }
}

/** 공용: 해시 함수 (게임/웹 동일) */
function l2_hash($plain) { return base64_encode(sha1($plain, true)); }

/** 공용: DB 연결 (게임/웹) */
function db_game() {
    global $server_host, $db_user_name, $db_user_password, $db_database;
    $m = @new mysqli($server_host, $db_user_name, $db_user_password, $db_database);
    if ($m && !$m->connect_errno) { @$m->set_charset('utf8mb4'); }
    return $m;
}

/**
 * accounts INSERT (환경별 컬럼 차이를 자동 흡수)
 * - 존재하는 컬럼만 사용
 * - NOT NULL·기본값 없는 일부 L2J 컬럼은 안전 기본값 주입
 * - 성공 시 true, 실패 시 에러메시지 문자열 반환
 */
function insert_account_flex(mysqli $conn, $account, $password, $ip, $regEmail) {
    // 1) 메타 읽기
    $cols = [];
    $meta = [];
    if ($rs = $conn->query("SHOW COLUMNS FROM accounts")) {
        while ($r = $rs->fetch_assoc()) {
            $name = $r['Field'];
            $meta[$name] = $r; // Null, Default, Type
        }
        $rs->close();
    } else {
        return 'accounts 메타 조회 실패';
    }

    // 2) 필수·선택 컬럼 구성
    $insCols = [];
    $types   = '';
    $params  = [];
    $add = function($c, $v, $t) use (&$insCols,&$types,&$params) {
        $insCols[] = $c; $types .= $t; $params[] = $v;
    };

    // 필수
    if (!isset($meta['login']) || !isset($meta['password'])) {
        return 'accounts에 login/password 컬럼이 없습니다';
    }
    $add('login',    $account, 's');
    $add('password', $password,'s');

    // lastIp / lastIP (IPv4만 저장)
    if (isset($meta['lastIp'])) { $add('lastIp', $ip, 's'); }
    elseif (isset($meta['lastIP'])) { $add('lastIP', $ip, 's'); }

    // email / e_mail
    if ($regEmail !== '' && isset($meta['e_mail'])) { $add('e_mail', $regEmail, 's'); }
    elseif ($regEmail !== '' && isset($meta['email'])) { $add('email', $regEmail, 's'); }

    // 3) NOT NULL & 기본값 없는 컬럼들에 안전값 주입(환경별 상이 → 존재할 때만)
    $now = date('Y-m-d H:i:s');
    $safeInt = function($name) use ($meta) {
        return isset($meta[$name]) && stripos($meta[$name]['Type'],'int') !== false;
    };
    // accessLevel
    if (isset($meta['accessLevel']) && $meta['Null']==='NO' && $meta['Default']===null) {
        $add('accessLevel', 0, $safeInt('accessLevel') ? 'i' : 's');
    }
    // lastactive / lastActive
    if (isset($meta['lastactive']) && $meta['Null']==='NO' && $meta['Default']===null) {
        $add('lastactive', $now, 's');
    } elseif (isset($meta['lastActive']) && $meta['Null']==='NO' && $meta['Default']===null) {
        $add('lastActive', $now, 's');
    }
    // lastServer
    if (isset($meta['lastServer']) && $meta['Null']==='NO' && $meta['Default']===null) {
        $add('lastServer', 1, $safeInt('lastServer') ? 'i' : 's');
    }
    // pcIp / allowed_ip (있으면 비워두기보다 현재 IP 기록)
    if (isset($meta['pcIp']) && $meta['Null']==='NO' && $meta['Default']===null) {
        $add('pcIp', $ip, 's');
    }
    if (isset($meta['allowed_ip']) && $meta['Null']==='NO' && $meta['Default']===null) {
        $add('allowed_ip', '', 's');
    }

    // 4) 실행
    $place = implode(',', array_fill(0, count($insCols), '?'));
    $sql   = 'INSERT INTO accounts ('.implode(',', $insCols).') VALUES ('.$place.')';
    $stmt  = $conn->prepare($sql);
    if (!$stmt) return 'PREPARE 실패: '.$conn->error;

    // PHP 7+ 스프레드가 안전하지만 하위호환 위해 refs 사용
    $bind = array_merge([$types], array_map(function($v){ return $v; }, $params));
    $refs = [];
    foreach ($bind as $k => $v) { $refs[$k] = &$bind[$k]; }
    if (!call_user_func_array([$stmt,'bind_param'], $refs)) {
        $e = $stmt->error ?: $conn->error;
        $stmt->close();
        return 'BIND 실패: '.$e;
    }
    $ok = $stmt->execute();
    $err= $stmt->error;
    $stmt->close();
    return $ok ? true : ('EXEC 실패: '.$err);
}

/** 내부 메일 발송: includes/email_config.txt 를 읽어 mail()로 전송 */
function send_verification_email_inline($email, $code, &$errMsg = '') {
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errMsg = '올바른 이메일을 입력해주세요.';
        return false;
    }
    if ($code === '' || $code === null) {
        $errMsg = '인증번호가 없습니다.';
        return false;
    }
	// 만료 표기 (KST, 발송 시각 +10분)
	$tz = new DateTimeZone('Asia/Seoul');
	$expiresAt = (new DateTime('now', $tz))->add(new DateInterval('PT10M'))->format('G시 i분 s초까지');

    // 기본값
    $cfg = [
        'FROM_NAME'  => 'Liberty',
        'FROM_EMAIL' => 'no-reply@L2jliberty.org',
        'SUBJECT'    => '[인증] 인증번호 안내',
        'BODY'       => "
            <div style='font-family:Segoe UI,Arial,sans-serif;font-size:14px'>
                <p>안녕하세요, Liberty 입니다.</p>
                <p>아래 인증번호를 입력하여 이메일 인증을 완료해 주세요.</p>
                <p style='font-size:20px;font-weight:bold;letter-spacing:2px'>인증번호: <span>{CODE}</span></p>
                <p>유효시간: <strong>{EXPIRES_AT}</strong></p>
                <p style='color:#d32f2f;font-weight:bold;letter-spacing:2px;margin:0'>참고: 캐릭터 생성을 하지 않으면 계정이 삭제됩니다.</p>
            </div>
        ",
    ];

    // includes/email_config.txt 반영
    $configPath = __DIR__ . '/includes/email_config.txt';
    if (is_file($configPath)) {
        $raw = @file_get_contents($configPath);
        if ($raw !== false) {
            $raw = trim($raw);
            $ini = @parse_ini_string($raw, false, INI_SCANNER_RAW);
            if (is_array($ini) && !empty($ini)) {
                foreach ($ini as $k=>$v) { $k=strtoupper(trim($k)); if($k!=='') $cfg[$k]=$v; }
            } else {
                foreach (preg_split('/\r\n|\r|\n/', $raw) as $line) {
                    if (trim($line)==='' || strpos($line, '=')===false) continue;
                    list($k,$v)=explode('=', $line, 2);
                    $k=strtoupper(trim($k)); $v=trim($v);
                    if ($k!=='') $cfg[$k] = $v;
                }
            }
        }
    }

    // 본문/제목/발신자 구성
    $fromEmail = isset($cfg['FROM']) && trim($cfg['FROM']) !== '' ? trim($cfg['FROM']) : trim($cfg['FROM_EMAIL']);
    $fromName  = trim($cfg['FROM_NAME']);
    $repl = [
        '{CODE}'       => $code,
        '{EXPIRES_AT}' => $expiresAt,
    ];
    $subject  = strtr($cfg['SUBJECT'], $repl);
    $htmlBody = strtr($cfg['BODY'], [
        '{CODE}'       => htmlspecialchars($code, ENT_QUOTES, 'UTF-8'),
        '{EXPIRES_AT}' => htmlspecialchars($expiresAt, ENT_QUOTES, 'UTF-8'),
    ]);
    $textBody = strtr(trim(preg_replace('/\s+/', ' ', strip_tags($cfg['BODY']))), $repl);
    if ($textBody === '') $textBody = "인증번호: {$code}";

    // SMTP 사용 여부 판단
    $hasPHPMailer = class_exists('\\PHPMailer\\PHPMailer\\PHPMailer');
    $useSmtp = !empty($cfg['SMTP']);

    if ($useSmtp) {
        if (!$hasPHPMailer) {
            $errMsg = 'SMTP가 설정되어 있으나 PHPMailer가 로드되지 않았습니다.';
            return false;
        }
        // --- PHPMailer + Resend ---
        try {
            $mail = new \PHPMailer\PHPMailer\PHPMailer(true);
            $mail->CharSet     = 'UTF-8';
            $mail->isSMTP();
            $mail->Host        = 'smtp.resend.com';
            $mail->Port        = (int)($cfg['PORT'] ?? 587);
            $mail->SMTPAuth    = true;
            $mail->SMTPSecure  = \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
            $mail->SMTPAutoTLS = true;

            // Resend: username='resend', password=API Key
            $mail->Username    = 'resend';
            $mail->Password    = trim($cfg['APP_PASSWORD'] ?? '');

            // From 은 Verified 도메인
            $mail->setFrom($fromEmail, $fromName);

            $mail->addAddress($email);
            $mail->Subject = $subject;
            $mail->isHTML(true);
            $mail->Body    = $htmlBody;
            $mail->AltBody = $textBody;
            if (!empty($cfg['REPLY_TO'])) $mail->addReplyTo($cfg['REPLY_TO'], $fromName);

            $mail->send();
            return true;
        } catch (\Throwable $e) {
            $errMsg = 'SMTP 발송 실패: ' . $e->getMessage();
            return false;
        }
    } else {
        // --- mail() 폴백 ---
        $isHtml = $htmlBody !== strip_tags($htmlBody);
        $encodedFromName = '=?UTF-8?B?' . base64_encode($fromName) . '?=';
        $headers  = "MIME-Version: 1.0\r\n";
        $headers .= "Content-Type: " . ($isHtml ? "text/html" : "text/plain") . "; charset=UTF-8\r\n";
        $headers .= "From: {$encodedFromName} <{$fromEmail}>\r\n";
        $headers .= "Reply-To: {$fromEmail}\r\n";
        $headers .= "X-Mailer: PHP/".phpversion();
        $bodyToSend = $isHtml ? $htmlBody : $textBody;

        try {
            $ok = @mail(
                $email,
                '=?UTF-8?B?'.base64_encode($subject).'?=',
                $bodyToSend,
                $headers,
                "-f {$fromEmail}"
            );
            if (!$ok) { $errMsg = '메일 발송 실패(mail 함수)'; }
            return (bool)$ok;
        } catch (Throwable $e) {
            $errMsg = '메일 발송 실패: ' . $e->getMessage();
            return false;
        }
    }
}


/** AJAX JSON 응답 */
function jsonResponse($success, $message='') {
    // 상단에서 시작한 버퍼만 깨끗이 비우고 다시 시작(응답을 순수 JSON 마커만 내보내기 위함)
    while (ob_get_level() > 0) { @ob_end_clean(); }
    ob_start();

    if (!headers_sent()) {
        header('Content-Type: application/json; charset=UTF-8');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('X-JSON-Envelope: 1');
    }

    $payload = json_encode(['success'=>$success,'message'=>$message], JSON_UNESCAPED_UNICODE);
    $out = "/*JSONSTART*/".$payload."/*JSONEND*/";
    if (!headers_sent()) { header('Content-Length: '.strlen($out)); }
    echo $out;
    exit;
}

/* ========================
   ID 중복 확인 (AJAX)
   ======================== */
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['check_id'])) {
    $conn = db_game();
    if (!$conn || $conn->connect_errno) jsonResponse(false, 'DB 연결 실패');

    $id = trim($_POST['id'] ?? '');
    if (!preg_match('/^[A-Za-z][A-Za-z0-9]{5,19}$/', $id)) {
        jsonResponse(false, '계정은 영문으로 시작, 영문+숫자 조합만 가능합니다. (6~20자)');
    }

    $stmt = $conn->prepare("SELECT 1 FROM accounts WHERE login = ? LIMIT 1");
    $stmt->bind_param("s", $id);
    $stmt->execute();
    $exists = $stmt->get_result()->num_rows > 0;
    $stmt->close();
    $conn->close();

    if ($exists) jsonResponse(false, '이미 사용 중인 ID입니다.');
    jsonResponse(true, '사용 가능한 ID입니다.');
}

/* ========================
   인증메일 발송 (AJAX)
   ======================== */
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['send_code'])) {
    $conn = db_game();
    if (!$conn || $conn->connect_errno) jsonResponse(false, 'DB 연결 실패');

    $email = trim($_POST['email'] ?? '');
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) jsonResponse(false, '올바른 이메일을 입력해주세요.');
	// [FORGOT-FLOW] 계정과 이메일 일치 확인: username이 함께 오면 반드시 매칭되어야 함
    $accountForForgot = trim($_POST['username'] ?? '');
    if ($accountForForgot !== '') {
        $emailCol = null;
        $c1 = $conn->query("SHOW COLUMNS FROM accounts LIKE 'e_mail'");
        $c2 = $conn->query("SHOW COLUMNS FROM accounts LIKE 'email'");
        if ($c1 && $c1->num_rows > 0)       $emailCol = 'e_mail';
        else if ($c2 && $c2->num_rows > 0)  $emailCol = 'email';
        if (!$emailCol) jsonResponse(false, '저장된 메일이 없어 본인 확인을 할 수 없습니다.');
        $stmt = $conn->prepare("SELECT 1 FROM accounts WHERE login = ? AND {$emailCol} = ? LIMIT 1");
        $stmt->bind_param("ss", $accountForForgot, $email);
        $stmt->execute();
        $ok = $stmt->get_result()->num_rows > 0;
        $stmt->close();
        if (!$ok) jsonResponse(false, '계정에 등록된 Email과 일치하지 않습니다.');
    }

    // 0) 세션 기반 60초 쿨타임
    if (!isset($_SESSION['last_code_send'])) $_SESSION['last_code_send'] = [];
    $lastTs = (int)($_SESSION['last_code_send'][$email] ?? 0);
    if (time() - $lastTs < 60) {
        $wait = 60 - (time() - $lastTs);
        jsonResponse(false, "재전송은 {$wait}초 후 가능합니다.");
    }

    // 1) 유효(10분)한 미검증 코드가 있으면 새로 만들지 않음 → 재전송/안내
    $chk = $conn->prepare(
        "SELECT id, code, created_at
           FROM verification_codes
          WHERE email=? AND status IN ('PENDING','SENT')
            AND created_at >= NOW() - INTERVAL 10 MINUTE
       ORDER BY id DESC
          LIMIT 1"
    );
    $chk->bind_param("s", $email);
    $chk->execute();
    $res = $chk->get_result();
    if ($row = $res->fetch_assoc()) {
        $code = $row['code'];
        $expiresTs = strtotime($row['created_at'].' +10 minutes');
        $expiresAt = (new DateTime('@'.$expiresTs))
            ->setTimezone(new DateTimeZone('Asia/Seoul'))
            ->format('G시 i분 s초까지');

        $errMsg = '';
        if (!send_verification_email_inline($email, $code, $errMsg)) {
            jsonResponse(false, $errMsg ?: '메일 발송 실패');
        }
        $_SESSION['last_code_send'][$email] = time();
        jsonResponse(true, "인증메일을 재전송했습니다. (유효시간: {$expiresAt})");
    }
    $chk->close();

    // 2) 유효한 코드가 없을 때만 새 코드 생성
    $verification_code = (string)rand(100000, 999999);
    $stmt = $conn->prepare("INSERT INTO verification_codes (email, code, status) VALUES (?, ?, 'PENDING')");
    $stmt->bind_param("ss", $email, $verification_code);
    if (!$stmt->execute()) jsonResponse(false, '데이터베이스 오류');
    $stmt->close();

    $errMsg = '';
    if (!send_verification_email_inline($email, $verification_code, $errMsg)) {
        jsonResponse(false, $errMsg ?: '메일 발송 실패');
    }
    $upd = $conn->prepare("UPDATE verification_codes SET status='SENT' WHERE email=? AND code=? ORDER BY id DESC LIMIT 1");
    if ($upd) {
        $upd->bind_param("ss", $email, $verification_code);
        $upd->execute();
        $upd->close();
    }
    $_SESSION['last_code_send'][$email] = time();

    $expiresAt = (new DateTime('now', new DateTimeZone('Asia/Seoul')))
        ->add(new DateInterval('PT10M'))
        ->format('G시 i분 s초까지');
    jsonResponse(true, "인증메일이 발송되었습니다. (유효: {$expiresAt})");
}

/* ========================
   인증번호 확인 (AJAX)
   ======================== */
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['verify_code'])) {
    $conn = db_game();
    if (!$conn || $conn->connect_errno) jsonResponse(false, 'DB 연결 실패');

    $email = trim($_POST['email'] ?? '');
    $code  = trim($_POST['verification_code'] ?? '');

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) jsonResponse(false, '올바른 이메일을 입력해주세요.');
    if ($code === '') jsonResponse(false, '인증번호를 입력해주세요.');

    $stmt = $conn->prepare("SELECT id FROM verification_codes WHERE email=? AND code=? AND status IN ('SENT','PENDING') AND created_at >= NOW() - INTERVAL 10 MINUTE ORDER BY id DESC LIMIT 1");
    $stmt->bind_param("ss", $email, $code);
    $stmt->execute();
    $res = $stmt->get_result();
    if ($row = $res->fetch_assoc()) {
        $upd = $conn->prepare("UPDATE verification_codes SET status='VERIFIED' WHERE id=?");
        $upd->bind_param("i", $row['id']);
        $upd->execute();
        $_SESSION['verified'] = true;
        $_SESSION['verified_email'] = $email;
        jsonResponse(true, '인증번호가 일치합니다.');
    } else {
        jsonResponse(false, '인증번호가 일치하지 않습니다.');
    }
}

/* ========================
   Register (AJAX 전용)
   ======================== */
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['register_ajax'])) {
    $conn = db_game();
    if (!$conn || mysqli_connect_errno()) {
        jsonResponse(false, "Can't Connect to MySQL: " . mysqli_connect_error());
    } else {
        $ip       = get_client_ip_v4_or_fallback();
        $account  = trim($_POST['username'] ?? '');
        $regEmail = trim($_POST['email'] ?? '');
        $passRaw  = $_POST['password'] ?? '';
        $passVer  = $_POST['passwordVerify'] ?? '';
        $vcode    = trim($_POST['verification_code'] ?? '');
        $password = l2_hash($passRaw);

        if (!filter_var($regEmail, FILTER_VALIDATE_EMAIL))        { jsonResponse(false, '올바른 이메일을 입력해주세요.'); }
        if ($passRaw !== $passVer)                                { jsonResponse(false, '비밀번호가 일치하지 않습니다.'); }
        if (mb_strlen($account) < 4 || mb_strlen($account) > 14)  { jsonResponse(false, '계정 길이는 4 ~ 14 자 여야합니다.'); }
        if (mb_strlen($passRaw) < 6 || mb_strlen($passRaw) > 16)  { jsonResponse(false, '비밀번호 길이는 6 ~ 16 자 여야합니다.'); }
        if ($vcode === '')                                        { jsonResponse(false, '인증번호를 입력해주세요.'); }

        $stmt = $conn->prepare("SELECT 1 FROM verification_codes WHERE email=? AND code=? AND status='VERIFIED' ORDER BY id DESC LIMIT 1");
        $stmt->bind_param("ss", $regEmail, $vcode);
        $stmt->execute();
        if ($stmt->get_result()->num_rows === 0) {
            $stmt->close();
            jsonResponse(false, '이메일 인증을 완료해주세요.');
        }
        $stmt->close();

        $stmt = $conn->prepare("SELECT 1 FROM accounts WHERE login = ?");
        $stmt->bind_param("s", $account);
        $stmt->execute();
        if ($stmt->get_result()->num_rows !== 0) { $stmt->close(); jsonResponse(false, '계정이 이미 존재합니다.'); }
        $stmt->close();

        $stmt = $conn->prepare("SELECT 1 FROM accounts WHERE accessLevel='-100' AND lastIp = ?");
        $stmt->bind_param("s", $ip);
        $stmt->execute();
        if ($stmt->get_result()->num_rows !== 0) { $stmt->close(); jsonResponse(false, '계정생성이 불가능한 IP입니다.'); }
        $stmt->close();

        $stmt = $conn->prepare("SELECT 1 FROM ban_ip WHERE access_level='-100' AND ip_adress = ?");
        $stmt->bind_param("s", $ip);
        $stmt->execute();
        if ($stmt->get_result()->num_rows !== 0) { $stmt->close(); jsonResponse(false, '계정생성이 불가능한 IP입니다.'); }
        $stmt->close();

        $emailCol = null;
        $c1 = $conn->query("SHOW COLUMNS FROM accounts LIKE 'e_mail'");
        $c2 = $conn->query("SHOW COLUMNS FROM accounts LIKE 'email'");
        if ($c1 && $c1->num_rows > 0)       $emailCol = 'e_mail';
        else if ($c2 && $c2->num_rows > 0)  $emailCol = 'email';

        // ✅ 유연 INSERT로 교체
        $ins = insert_account_flex($conn, $account, $password, $ip, $regEmail);
        if ($ins !== true) {
            jsonResponse(false, '계정 생성 실패: '.$ins);
        }

        $u = $conn->prepare("UPDATE verification_codes SET status='VERIFIED' WHERE email=? AND code=?");
        $u->bind_param("ss", $regEmail, $vcode);
        $u->execute();
        $u->close();

        $conn->close();
        jsonResponse(true, "{$account} 계정생성이 완료되었습니다!");
    }
}


/* ========================
   Register (계정 생성)
   ======================== */
if (isset($_POST['register'])) {
    $conn = db_game();
    if (!$conn || mysqli_connect_errno()) {
        $error = "Can't Connect to MySQL <h5>" . mysqli_connect_error() . "</h5>";
    } else {
        $ip       = get_client_ip_v4_or_fallback();
        $account  = trim($_POST['username'] ?? '');
        $regEmail = trim($_POST['email'] ?? '');
        $passRaw  = $_POST['password'] ?? '';
        $passVer  = $_POST['passwordVerify'] ?? '';
        $vcode    = trim($_POST['verification_code'] ?? '');
        $password = l2_hash($passRaw);

        if (!filter_var($regEmail, FILTER_VALIDATE_EMAIL))        { $error .= "<center>올바른 이메일을 입력해주세요.</center>"; }
        if ($passRaw !== $passVer)                                { $error .= "<center>비밀번호가 일치하지 않습니다.</center>"; }
        if (mb_strlen($account) < 4 || mb_strlen($account) > 14)  { $error .= "<center>계정 길이는 4 ~ 14 자 여야합니다.</center>"; }
        if (mb_strlen($passRaw) < 6 || mb_strlen($passRaw) > 16)  { $error .= "<center>비밀번호 길이는 6 ~ 16 자 여야합니다.</center>"; }
        if ($vcode === '')                                        { $error .= "<center>인증번호를 입력해주세요.</center>"; }

        if ($error === "") {
            $stmt = $conn->prepare("SELECT 1 FROM verification_codes WHERE email=? AND code=? AND status='VERIFIED' ORDER BY id DESC LIMIT 1");
            $stmt->bind_param("ss", $regEmail, $vcode);
            $stmt->execute();
            if ($stmt->get_result()->num_rows === 0) {
                $error .= "<center>이메일 인증을 완료해주세요.</center>";
            }
            $stmt->close();
        }

        if ($error === "") {
            $stmt = $conn->prepare("SELECT 1 FROM accounts WHERE login = ?");
            $stmt->bind_param("s", $account);
            $stmt->execute();
            if ($stmt->get_result()->num_rows !== 0) { $error .= "<center>계정이 이미 존재합니다.</center>"; }
            $stmt->close();
        }
        if ($error === "") {
            $stmt = $conn->prepare("SELECT 1 FROM accounts WHERE accessLevel='-100' AND lastIp = ?");
            $stmt->bind_param("s", $ip);
            $stmt->execute();
            if ($stmt->get_result()->num_rows !== 0) { $error .= "<center>계정생성이 불가능한 IP입니다.</center>"; }
            $stmt->close();
        }
        if ($error === "") {
            $stmt = $conn->prepare("SELECT 1 FROM ban_ip WHERE access_level='-100' AND ip_adress = ?");
            $stmt->bind_param("s", $ip);
            $stmt->execute();
            if ($stmt->get_result()->num_rows !== 0) { $error .= "<center>계정생성이 불가능한 IP입니다.</center>"; }
            $stmt->close();
        }

        if ($error === "") {
            $emailCol = null;
            $c1 = $conn->query("SHOW COLUMNS FROM accounts LIKE 'e_mail'");
            $c2 = $conn->query("SHOW COLUMNS FROM accounts LIKE 'email'");
            if ($c1 && $c1->num_rows > 0)       $emailCol = 'e_mail';
            else if ($c2 && $c2->num_rows > 0)  $emailCol = 'email';

            // ✅ 유연 INSERT로 교체
            $ins = insert_account_flex($conn, $account, $password, $ip, $regEmail);
            if ($ins === true) {
                $u = $conn->prepare("UPDATE verification_codes SET status='VERIFIED' WHERE email=? AND code=?");
                $u->bind_param("ss", $regEmail, $vcode);
                $u->execute();

                $error = "<center>{$account} 계정생성이 완료되었습니다!</center>";
            } else {
                $error = "<center>계정 생성 실패: ".htmlspecialchars(is_string($ins)?$ins:'unknown',ENT_QUOTES,'UTF-8')."</center>";
            }
            $stmt->close();
        }
        $conn->close();
    }
}

/* ---- Forgot/Change PW ---- */
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['forgot_ajax'])) {
    $conn = db_game();
    if (!$conn || mysqli_connect_errno()) {
        jsonResponse(false, "Can't Connect to MySQL: " . mysqli_connect_error());
    } else {
        $account  = trim($_POST['username'] ?? '');
        $email    = trim($_POST['email'] ?? '');
        $passRaw  = $_POST['password'] ?? '';
        $passVer  = $_POST['passwordVerify'] ?? '';
        $password = l2_hash($passRaw);
		$vcode    = trim($_POST['verification_code'] ?? '');

        if ($account === '') { jsonResponse(false, 'Enter account'); }
        if ($email   === '') { jsonResponse(false, 'Enter email'); }
        if ($passRaw === '') { jsonResponse(false, 'Enter password'); }
		if ($vcode   === '') { jsonResponse(false, '인증번호를 입력해주세요.'); }
        if ($passRaw !== $passVer) { jsonResponse(false, '비밀번호가 일치하지 않습니다.'); }
        if (mb_strlen($passRaw) < 6 || mb_strlen($passRaw) > 16) { jsonResponse(false, '비밀번호 길이는 6 ~ 16 자 여야합니다.'); }

        $emailCol = null;
        $chkCol1 = $conn->query("SHOW COLUMNS FROM accounts LIKE 'e_mail'");
        $chkCol2 = $conn->query("SHOW COLUMNS FROM accounts LIKE 'email'");
        if ($chkCol1 && $chkCol1->num_rows > 0) $emailCol = 'e_mail';
        elseif ($chkCol2 && $chkCol2->num_rows > 0) $emailCol = 'email';
        if (!$emailCol) jsonResponse(false, '서버에 이메일 컬럼이 없어 본인 확인을 할 수 없습니다.');

        $stmt = $conn->prepare("SELECT 1 FROM accounts WHERE login = ? AND {$emailCol} = ? LIMIT 1");
        $stmt->bind_param("ss", $account, $email);
        $stmt->execute();
        if ($stmt->get_result()->num_rows === 0) {
            jsonResponse(false, 'Email 또는 계정이 일치하지 않습니다.');
        }
        $stmt->close();

		// NEW: 이메일 인증 확인 (VERIFIED, 10분 창 내 발송/검증 가정)
        $stmt = $conn->prepare("SELECT 1 FROM verification_codes WHERE email=? AND code=? AND status='VERIFIED' ORDER BY id DESC LIMIT 1");
        $stmt->bind_param("ss", $email, $vcode);
        $stmt->execute();
        if ($stmt->get_result()->num_rows === 0) {
            $stmt->close();
            jsonResponse(false, '이메일 인증을 완료해주세요.');
        }
        $stmt->close();

        $stmt = $conn->prepare("UPDATE accounts SET password = ? WHERE login = ?");
        $stmt->bind_param("ss", $password, $account);
        $okGame = $stmt->execute();
        $stmt->close();

        if ($okGame) {
            $msg = "{$account} 계정의 비밀번호가 변경되었습니다!";
        } else {
            jsonResponse(false, '운영자에게 문의하세요.');
        }
    }
}

if (isset($_POST['forgot'])) {
    $conn = db_game();
    if (!$conn || mysqli_connect_errno()) {
        $error = "Can't Connect to MySQL <h5>" . mysqli_connect_error() . "</h5>";
    } else {
        $account  = trim($_POST['username'] ?? '');
        $email    = trim($_POST['email'] ?? '');
        $passRaw  = $_POST['password'] ?? '';
        $passVer  = $_POST['passwordVerify'] ?? '';
        $password = l2_hash($passRaw);
		$vcode    = trim($_POST['verification_code'] ?? '');

        if ($account === '') { $error = 'Enter account'; }
        if ($email   === '') { $error = 'Enter email'; }
        if ($passRaw === '') { $error = 'Enter password'; }
		if ($vcode   === '') { $error = '인증번호를 입력해주세요.'; }

        if ($error === "") {
            $emailCol = null;
            $chkCol1 = $conn->query("SHOW COLUMNS FROM accounts LIKE 'e_mail'");
            $chkCol2 = $conn->query("SHOW COLUMNS FROM accounts LIKE 'email'");
            if ($chkCol1 && $chkCol1->num_rows > 0) $emailCol = 'e_mail';
            elseif ($chkCol2 && $chkCol2->num_rows > 0) $emailCol = 'email';

            if (!$emailCol) {
                $error = "<center>서버에 이메일 컬럼이 없어 본인 확인을 할 수 없습니다.</center>";
            } else {
                $stmt = $conn->prepare("SELECT 1 FROM accounts WHERE login = ? AND {$emailCol} = ? LIMIT 1");
                $stmt->bind_param("ss", $account, $email);
                $stmt->execute();
                if ($stmt->get_result()->num_rows === 0) {
                    $error = "<center>Email 또는 계정이 일치하지 않습니다.</center>";
                }
                $stmt->close();
            }
        }

		if ($error === "") {
            // NEW: 이메일 인증 확인
            $stmt = $conn->prepare("SELECT 1 FROM verification_codes WHERE email=? AND code=? AND status='VERIFIED' ORDER BY id DESC LIMIT 1");
            $stmt->bind_param("ss", $email, $vcode);
            $stmt->execute();
            if ($stmt->get_result()->num_rows === 0) {
                $error = "<center>이메일 인증을 완료해주세요.</center>";
            }
            $stmt->close();
        }

        if ($error === "") {
            if ($passRaw !== $passVer)                               { $error .= "<center>비밀번호가 일치하지 않습니다.</center>"; }
            if (mb_strlen($passRaw) < 6 || mb_strlen($passRaw) > 16) { $error .= "<center>비밀번호 길이는 6 ~ 16 자 여야합니다.</center>"; }
        }

        if ($error === "") {
            $stmt = $conn->prepare("UPDATE accounts SET password = ? WHERE login = ?");
            $stmt->bind_param("ss", $password, $account);
            $okGame = $stmt->execute();
            $stmt->close();

            if ($okGame) {
                $error = "<center>{$account} 계정의 비밀번호가 변경되었습니다!</center>";
            } else {
                $error = "<center>운영자에게 문의하세요.</center>";
            }
        }
        $conn->close();
    }
}
?>

<meta content="width=device-width, initial-scale=1.0" name="viewport">
<link href="../theme/home_g5/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="../theme/home_g5/css/override.css?v=2025595">
<script defer src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>


<style>
  /* 이 페이지 배경 투명 + 가로 스크롤 제거 */
  html,
  body {
    background: transparent !important;
    margin: 0;
    padding: 0;
    overflow-x: hidden !important;  /* ← 가로 스크롤 막기 */
  }

  /* body 바로 아래 .row 에서 부트스트랩 -마진 때문에 생기는 가로 오버플로우 제거 */
  body > .row {
    margin-left: 0 !important;
    margin-right: 0 !important;
  }

  /* 크로미움(WebView2) 가로 스크롤바 자체 숨기기 */
  ::-webkit-scrollbar:horizontal {
    height: 0 !important;
    display: none !important;
  }

  /* 결과 팝업이 항상 최상단으로 오도록(필요 시) */
  #resultPopup { z-index: 1085; }

  #emailMsg:empty, #codeMsg:empty { display:none !important; }
  #emailMsg, #codeMsg { min-height:0 !important; margin-top:4px !important; }

  #emailForgotMsg:empty, #codeMsg:empty { display:none !important; }
  #emailForgotMsg, #codeMsg { min-height:0 !important; margin-top:4px !important; }

  .modal-backdrop.show {
    opacity: 0 !important;
  }


  /* 계정 생성 / 비번 변경 모달 전체 높이 제한 */
  #modalRegister .modal-dialog,
  #modalForgot .modal-dialog {
    max-height: 83vh; /* 화면 높이의 80%까지만 */
  }

  #modalRegister .modal-content,
  #modalForgot .modal-content {
    max-height: 83vh;
  }

  /* 안쪽 여백 줄이기 */
  #modalRegister .modal-body,
  #modalForgot .modal-body {
    padding: 0.75rem 1rem; /* 기본값보다 살짝 줄임 */
  }

  /* 입력 박스 간 간격 줄이기 */
  #modalRegister .mb-3,
  #modalForgot .mb-3 {
    margin-bottom: 0.5rem;
  }

  #modalRegister .mb-2,
  #modalForgot .mb-2 {
    margin-bottom: 0.4rem;
  }

  /* 마지막 버튼(계정 생성 / 비밀번호 변경) 높이 줄이기 */
  #modalRegister input.btn-primary,
  #modalForgot input.btn-primary {
    padding: 0.25rem 0.75rem;
    font-size: 0.875rem;
  }
</style>

<!-- 메시지 -->
<div class="messages" style="margin-bottom:16px; display:none;">
  <h4><span style="color:#FFFFFF;"><?php echo (!empty($error) ? "<label><strong>{$error}</strong></label>" : ""); ?></span></h4>
</div>
<br><br>
<!-- 트리거 버튼 -->
<div class="row gx-4 gy-2 mb-3 align-items-center"> <!-- 더 벌리려면 gx-5, 줄이려면 gx-3 -->
  <div class="col-12 col-md-6 d-flex justify-content-md-end justify-content-center">
    <button type="button"
            class="p-0 border-0 bg-transparent mx-md-2"
            style="width:40%; max-width:340px; cursor:pointer;"
            data-bs-toggle="modal" data-bs-target="#modalRegister">
      <img src="https://borinet-dev.github.io/css/img/h2_account.webp"
           alt="신규 계정 생성"
           class="img-fluid w-100"
           width="680" height="176"
           loading="lazy" decoding="async">
    </button>
  </div>

  <div class="col-12 col-md-6 d-flex justify-content-md-start justify-content-center">
    <button type="button"
            class="p-0 border-0 bg-transparent mx-md-2"
            style="width:40%; max-width:340px; cursor:pointer;"
            data-bs-toggle="modal" data-bs-target="#modalForgot">
      <img src="https://borinet-dev.github.io/css/img/h2_password.webp"
           alt="비밀번호 분실 및 변경"
           class="img-fluid w-100"
           width="680" height="176"
           loading="lazy" decoding="async">
    </button>
  </div>
</div>

<!-- 신규 계정 생성 Modal -->
<div class="modal fade" id="modalRegister" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered" style="width:auto; max-width:min(95vw, 600px);">
    <div class="modal-content" style="background:#575757;color:#fff;">
      <div class="modal-body">
        <form id="register" method="post" action="">
          <!-- 1. 계정 -->
          <div class="mb-3">
            <input class="form-control" id="username" name="username" placeholder="계정" required
                   value="<?php if(isset($_POST['username'])) echo htmlspecialchars($_POST['username']); ?>">
          </div>
          <div id="idMsg" class="small" style="display:none;"></div>
          <!-- 2. 비번 -->
          <div class="mb-3">
            <input class="form-control" id="password" name="password" placeholder="비밀번호" required type="password">
          </div>
          <!-- 3. 비번확인 -->
          <div class="mb-3">
            <input class="form-control" id="passwordVerify" name="passwordVerify" placeholder="비밀번호 확인" required type="password">
          </div>
          <div id="pwMsg" class="small" style="display:none;"></div>
          <!-- 4. 이메일 -->
          <div class="mb-1">
            <input class="form-control" id="email_reg" name="email" placeholder="E-mail" type="email" required>
          </div>
          <!-- 5. 인증메일 발송 -->
          <div class="mb-2">
            <div id="emailMsg" class="small" style="min-height:1.25rem;"></div>
            <button type="button" id="btnSendCode" class="btn btn-outline-light btn-sm">인증메일 발송</button>
          </div>
          <!-- 6. 인증번호 -->
          <div class="mb-1">
            <input class="form-control" id="verification_code" name="verification_code" placeholder="인증번호" type="text">
          </div>
          <!-- 7. 인증번호 확인 -->
          <div class="mb-2">
            <div id="codeMsg" class="small" style="min-height:1.25rem;"></div>
            <button type="button" id="btnVerifyCode" class="btn btn-outline-light btn-sm">인증번호 확인</button>
          </div>
          <!-- 8. 계정생성 -->
          <input class="btn btn-primary" name="register" type="submit" value="계정 생성하기">
        </form>
      </div>
    </div>
  </div>
</div>

<!-- ✅ 결과 팝업(부트스트랩 모달) -->
<div class="modal fade" id="resultPopup" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered" style="max-width:420px;">
    <div class="modal-content" style="background:#575757;color:#fff;">
      <div class="modal-header">
        <h5 class="modal-title text-warning">알림</h5>
        <button type="button" class="btn btn-primary" data-bs-dismiss="modal">확인</button>
      </div>
      <div class="modal-body">
        <div id="resultPopupMsg" class="small"></div>
      </div>
    </div>
  </div>
</div>

<!-- 비밀번호 변경 Modal -->
<div class="modal fade" id="modalForgot" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered" style="width:auto; max-width:min(95vw, 600px);">
    <div class="modal-content" style="background:#575757;color:#fff;">
      <div class="modal-body">
        <form id="login" method="post" action="">
          <div class="mb-3">
            <input class="form-control" id="username_f" name="username" placeholder="계정" required>
          </div>
          <div class="mb-1">
            <input class="form-control" id="email" name="email" placeholder="E-mail (게임내에서 설정했던 이메일 또는 계정생성 시 인증받은 이메일)" required type="email">
          </div>
		  <!-- NEW: 인증메일 발송 -->
			<div class="mb-2">
			  <div id="emailForgotMsg" class="small" style="min-height:1.25rem;"></div>
			  <button type="button" id="btnSendCode_f" class="btn btn-outline-light btn-sm">인증메일 발송</button>
			</div>
			<!-- NEW: 인증번호 입력 -->
			<div class="mb-1">
			  <input class="form-control" id="verification_code_f" name="verification_code" placeholder="인증번호" type="text">
			</div>
			<!-- NEW: 인증번호 확인 -->
			<div class="mb-2">
			  <div id="codeMsg_f" class="small" style="min-height:1.25rem;"></div>
			  <button type="button" id="btnVerifyCode_f" class="btn btn-outline-light btn-sm">인증번호 확인</button>
			</div>
          <div class="mb-3">
            <input class="form-control" id="password_f" name="password" placeholder="신규 비밀번호" required type="password">
          </div>
          <div class="mb-3">
            <input class="form-control" id="passwordVerify_f" name="passwordVerify" placeholder="비밀번호 확인" required type="password">
          </div>
          <input class="btn btn-primary" name="forgot" type="submit" value="비밀번호 변경">
        </form>
      </div>
    </div>
  </div>
</div>

<!-- (선택) ACM iframe 모달 -->
<div class="modal fade" id="modalAcm" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered" id="acmDialog" style="width:auto; max-width:min(95vw, 600px);">
    <div class="modal-content" style="background:#575757;color:#fff;">
      <div class="modal-header">
        <h5 class="modal-title text-warning">계정 생성</h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="닫기"></button>
      </div>
      <div class="modal-body p-0">
        <iframe id="acmFrame" src="" style="width:95%; height:60vh; border:0; display:block;"></iframe>
      </div>
    </div>
  </div>
</div>

<script>
(function(){
  document.addEventListener('DOMContentLoaded', function(){

    // ===== 공용 모달 제어 =====
    function hideModal(id){
      var el = document.getElementById(id); if (!el) return;
      if (window.bootstrap && bootstrap.Modal) { bootstrap.Modal.getOrCreateInstance(el).hide(); return; }
      if (window.jQuery && typeof jQuery(el).modal === 'function') { jQuery(el).modal('hide'); return; }
      el.classList.remove('show'); el.style.display='none'; el.setAttribute('aria-hidden','true');
      document.body.classList.remove('modal-open');
      var bd=document.getElementById('resultPopupBackdrop'); if (bd && bd.parentNode) bd.parentNode.removeChild(bd);
    }

	function hardResetModals(){
	  try{
		if (window.bootstrap && bootstrap.Modal) {
		  // 열려있는 모달을 전부 "정상적으로" 닫음
		  document.querySelectorAll('.modal.show').forEach(function(m){
			try { bootstrap.Modal.getOrCreateInstance(m).hide(); } catch(e){}
		  });
		  // 잠깐 뒤에, 다른 모달이 없으면 잔여 백드롭/스크롤락만 정리
		  setTimeout(function(){
			if (!document.querySelector('.modal.show')) {
			  document.querySelectorAll('.modal-backdrop').forEach(function(n){
				if (n && n.parentNode) n.parentNode.removeChild(n);
			  });
			  document.body.classList.remove('modal-open');
			  document.body.style.removeProperty('padding-right');
			  document.body.style.removeProperty('overflow');
			}
		  }, 30);
		} else {
		  // Bootstrap 미사용시 기존 강제 정리
		  document.querySelectorAll('.modal-backdrop').forEach(function(n){
			if (n && n.parentNode) n.parentNode.removeChild(n);
		  });
		  document.querySelectorAll('.modal.show').forEach(function(m){
			m.classList.remove('show');
			m.style.display = 'none';
			m.setAttribute('aria-hidden','true');
		  });
		  document.body.classList.remove('modal-open');
		  document.body.style.removeProperty('padding-right');
		  document.body.style.removeProperty('overflow');
		}
	  }catch(e){}
	}

	// 결과 팝업 (다른 모달이 열려있으면 그 모달을 정상적으로 닫은 뒤에만 띄움)
	function showPopup(message, opts){
	  opts = opts || {};
	  var preserve = !!opts.preserveModals;
	  var reloadOnClose = !!opts.reloadOnClose;   // ✅ 새로고침 옵션

	  var el = document.getElementById('resultPopup');
	  if (!el) return;

	  var msgBox = document.getElementById('resultPopupMsg');
	  if (msgBox) msgBox.textContent = message || '';

	  // ✅ 닫힐 때 새로고침(한 번만)
	  // 부트스트랩 사용 시
	  if (window.bootstrap && typeof bootstrap.Modal === 'function') {
		// 기존에 걸린 리스너 중복 방지 위해 먼저 제거용으로 once 리스너만 사용
		if (reloadOnClose) {
		  el.addEventListener('hidden.bs.modal', function onHiddenReload(){
			el.removeEventListener('hidden.bs.modal', onHiddenReload);
			try { location.reload(); } catch(e){}
		  }, { once:true });
		}
	  } else if (window.jQuery && typeof jQuery(el).on === 'function') {
		if (reloadOnClose) {
		  jQuery(el).one('hidden.bs.modal', function(){ try{ location.reload(); }catch(e){} });
		}
	  } else {
		// 폴백: 닫기 버튼 클릭 시 새로고침
		var closeBtn = el.querySelector('[data-bs-dismiss="modal"]');
		if (closeBtn) {
		  closeBtn.onclick = function(){
			try { if (reloadOnClose) location.reload(); else hideModal('resultPopup'); } catch(e){}
		  };
		}
	  }

	  // ===== 이하 기존 show 로직 그대로 =====
	  try {
		if (window.bootstrap && bootstrap.Modal) {
		  var exist = bootstrap.Modal.getInstance(el);
		  if (exist) exist.dispose();
		  var instance = new bootstrap.Modal(
			el,
			preserve ? { backdrop:false, keyboard:true, focus:true } : { backdrop:true, keyboard:true, focus:true }
		  );
		  if (!preserve) {
			var opened = document.querySelector('.modal.show:not(#resultPopup)');
			if (opened) {
			  var openedInst = bootstrap.Modal.getOrCreateInstance(opened);
			  opened.addEventListener('hidden.bs.modal', function onHidden(){
				opened.removeEventListener('hidden.bs.modal', onHidden);
				instance.show();
			  }, { once:true });
			  openedInst.hide();
			  return;
			}
		  }
		  instance.show();
		  return;
		}

		if (window.jQuery && typeof jQuery(el).modal === 'function') {
		  if (!preserve) {
			var $opened = jQuery('.modal.show').not('#resultPopup');
			if ($opened.length) {
			  $opened.one('hidden.bs.modal', function(){ jQuery(el).modal({ backdrop:true, show:true }); });
			  $opened.modal('hide');
			  return;
			}
		  }
		  jQuery(el).modal({ backdrop: preserve ? false : true, show:true });
		  return;
		}
	  } catch(e){}

	  // 폴백
	  el.classList.add('show');
	  el.style.display='block';
	  el.removeAttribute('aria-hidden');
	  if (!preserve) {
		document.body.classList.add('modal-open');
		var bd = document.createElement('div');
		bd.className='modal-backdrop fade show';
		bd.id='resultPopupBackdrop';
		document.body.appendChild(bd);
	  }
	  var closeBtn2 = el.querySelector('[data-bs-dismiss="modal"]');
	  if (closeBtn2 && !closeBtn2.onclick) {
		closeBtn2.onclick = function(){ hideModal('resultPopup'); };
	  }
	}

	// 지정 모달을 "정상적으로" 닫은 뒤 팝업을 띄움 (강제 리셋 없음)
	function queuePopupAfterHide(modalId, message, afterReset, opts){
	  opts = opts || {};
	  var el = document.getElementById(modalId);
	  var done = false;
	  function fireOnce(){
		if (done) return; done = true;
		try { if (typeof afterReset === 'function') afterReset(); } catch(e){}
		setTimeout(function(){ showPopup(message, { preserveModals:false, reloadOnClose: !!opts.reloadOnClose }); }, 10);
	  }
	  if (!el){ fireOnce(); return; }
	  if (window.bootstrap && bootstrap.Modal){
		try{
		  el.addEventListener('hidden.bs.modal', fireOnce, { once:true });
		  bootstrap.Modal.getOrCreateInstance(el).hide();
		  return;
		}catch(e){}
	  }
	  if (window.jQuery && typeof jQuery(el).modal === 'function'){
		try{
		  jQuery(el).one('hidden.bs.modal', fireOnce).modal('hide');
		  return;
		}catch(e){}
	  }
	  hideModal(modalId);
	  fireOnce();
	}

    // 0) 모달/초기화
    function resetRegisterUI(){
      try {
        var regForm  = document.getElementById('register');
        var emailMsg = document.getElementById('emailMsg');
        var codeMsg  = document.getElementById('codeMsg');
        var btnSend  = document.getElementById('btnSendCode');
        var btnVerify= document.getElementById('btnVerifyCode');
        var vcode    = document.getElementById('verification_code');
        if (regForm) regForm.reset();
        if (emailMsg) { emailMsg.textContent=''; emailMsg.style.color=''; emailMsg.style.display=''; }
	    if (codeMsg)  { codeMsg.textContent=''; codeMsg.style.color=''; codeMsg.style.display=''; }
        if (btnSend)  btnSend.style.display = '';
        if (btnVerify){ btnVerify.disabled = false; btnVerify.style.display = ''; }
        if (vcode) vcode.value = '';

        var rp = document.getElementById('resultPopupMsg'); if (rp){ rp.textContent=''; }
        ['idMsg','pwMsg'].forEach(function(id){
          var el = document.getElementById(id);
          if (el){ el.style.display='none'; el.textContent=''; }
        });

        userInteracted = false;
        idTouched = false;
      } catch(e){}
    }

    var modalRegister = document.getElementById('modalRegister');
    if (modalRegister) {
      modalRegister.addEventListener('show.bs.modal', resetRegisterUI);
      var openBtns = document.querySelectorAll('[data-bs-target="#modalRegister"], [data-target="#modalRegister"]');
      openBtns.forEach(function(b){ b.addEventListener('click', resetRegisterUI); });
    }

	var resultPopupEl = document.getElementById('resultPopup');
	if (resultPopupEl) {
	  resultPopupEl.addEventListener('hidden.bs.modal', function(){
		// 다른 모달이 없을 때만 잔여 백드롭/스크롤락 정리
		setTimeout(function(){
		  if (!document.querySelector('.modal.show')) {
			document.querySelectorAll('.modal-backdrop').forEach(function(n){
			  if (n && n.parentNode) n.parentNode.removeChild(n);
			});
			document.body.classList.remove('modal-open');
			document.body.style.removeProperty('padding-right');
			document.body.style.removeProperty('overflow');
		  }
		}, 30);
	  });
	}

	var modalForgotEl = document.getElementById('modalForgot');
	if (modalForgotEl) {
	  modalForgotEl.addEventListener('show.bs.modal', function(){
		try {
		  // NEW: 모달 열릴 때 포가ット 인증 UI 초기화
        sessionStorage.removeItem('verified_forgot');
        var msgEF = document.getElementById('emailForgotMsg');
        var msgCF = document.getElementById('codeMsg_f');
        var btnSF = document.getElementById('btnSendCode_f');
        var btnVF = document.getElementById('btnVerifyCode_f');
        if (msgEF) { msgEF.textContent=''; msgEF.style.display='none'; msgEF.style.color=''; }
        if (msgCF) { msgCF.textContent=''; msgCF.style.display='none'; msgCF.style.color=''; }
        if (btnSF) btnSF.style.display='';
        if (btnVF) { btnVF.disabled=false; btnVF.style.display=''; }
		} catch(e){}
	  });
	}

    // 공용 메시지
    function flash(el, msg, color, holdMs){
      if(!el) return;
      el.textContent   = msg || '';
      el.style.color   = color || '#bbb';
      el.style.display = 'block';
      clearTimeout(el.__t);
      el.__t = setTimeout(function(){
        el.style.display = 'none';
        el.textContent   = '';
      }, (typeof holdMs==='number' ? holdMs : 1000));
    }

    // JSON 파서
    function extractJson(raw) {
      if (!raw) return null;
      raw = String(raw).replace(/^\uFEFF/, '');
      var s='/*JSONSTART*/', e='/*JSONEND*/', i=raw.indexOf(s), k=raw.indexOf(e);
      if (i!==-1 && k!==-1 && k>i) { try { return JSON.parse(raw.slice(i+s.length,k).trim()); } catch(_){} }
      try { return JSON.parse(raw); } catch(_) {}
      var m = raw.match(/\{[\s\S]*?\}/g) || [];
      for (var t=0; t<m.length; t++) { try { var o=JSON.parse(m[t]); if (o && typeof o.success!=='undefined') return o; } catch(_) {} }
      return null;
    }

    // 회원가입 AJAX
    var regForm = document.getElementById('register');
    if (regForm) {
      regForm.addEventListener('submit', function(e){
        e.preventDefault();
        var acc  = document.getElementById('username').value.trim();
        var mail = document.getElementById('email_reg').value.trim();
        var p1   = document.getElementById('password').value;
        var p2   = document.getElementById('passwordVerify').value;
        var code = document.getElementById('verification_code').value.trim();
        if (!/^[A-Za-z][A-Za-z0-9]{5,19}$/.test(acc)) { flash(document.getElementById('idMsg'),'계정은 영문으로 시작, 영문+숫자 조합만 가능합니다. (6~20자)','red'); return; }
        if (!p2) { flash(document.getElementById('pwMsg'),'비밀번호를 한번더 입력해주세요.','red'); return; }
        if (p1 !== p2) { flash(document.getElementById('pwMsg'),'비밀번호가 일치하지 않습니다.','red'); return; }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(mail)) { flash(document.getElementById('emailMsg'),'올바른 이메일을 입력해주세요.','red'); return; }
        if (!sessionStorage.getItem('verified')) { flash(document.getElementById('codeMsg'),'이메일 인증을 완료해주세요.','red',1200); return; }

        var submitBtn = regForm.querySelector('input[type=submit]');
        if (submitBtn) submitBtn.disabled = true;
        fetch('', {
          method: 'POST',
          headers: {'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8'},
          credentials: 'same-origin',
          body: new URLSearchParams({ register_ajax:'1', username:acc, email:mail, password:p1, passwordVerify:p2, verification_code:code })
        })
        .then(r=>r.text())
        .then(function(raw){
          var j = extractJson(raw);
          if (!j) throw new Error('parse');
          var msg = j.message || (j.success ? '처리되었습니다.' : '실패했습니다.');
          if (j.success){
            queuePopupAfterHide('modalRegister', msg, resetRegisterUI, { reloadOnClose: true });
          } else {
            showPopup(msg);
          }
        })
        .catch(function(){ showPopup('요청 실패 또는 응답 파싱 실패'); })
        .finally(function(){ if (submitBtn) submitBtn.disabled = false; });
      });
    }

    // 요소 캐싱
    var $id    = document.getElementById('username');
    var $pw    = document.getElementById('password');
    var $pw2   = document.getElementById('passwordVerify');
    var $email = document.getElementById('email_reg');

    var $idMsg = document.getElementById('idMsg');
    var $pwMsg = document.getElementById('pwMsg');

    try {
      if ($id && $idMsg)   { $id.parentNode.appendChild($idMsg); }
      if ($pw2 && $pwMsg)  { $pw2.parentNode.appendChild($pwMsg); }
    } catch(e){}

    var userInteracted = false;
    var idTouched = false;
    ['pointerdown','keydown','touchstart'].forEach(function(evt){
      document.addEventListener(evt, function(){ userInteracted = true; }, {once:false, passive:true});
    });
    if ($id) {
      $id.addEventListener('keydown', function(){ idTouched = true; });
      $id.addEventListener('input', function(){ idTouched = true; });
    }

    if ($id) {
      $id.addEventListener('blur', checkIdNow);
      if ($pw) { $pw.addEventListener('focus', checkIdNow); }
    }

    function checkIdNow(){
      if (!$id || !$idMsg) return;
      var v = ($id.value || '').trim();
      if (!userInteracted) return;
      if (!idTouched && document.activeElement !== $pw) return;
      var ok = /^[A-Za-z][A-Za-z0-9]{5,19}$/.test(v);
      if (!ok) {
        flash($idMsg, '계정은 영문으로 시작, 영문+숫자 조합만 가능합니다. (6~20자)', 'red');
        return;
      }
      fetch('', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
        credentials: 'same-origin',
        body: new URLSearchParams({ check_id: '1', id: v })
      })
      .then(r=>r.text())
      .then(function(raw){
        var j = extractJson(raw);
        if (!j || typeof j.success==='undefined') {
          flash($idMsg, '요청 실패 또는 응답 파싱 실패', 'red');
          return;
        }
        if (j.success) flash($idMsg, j.message || '사용 가능한 ID입니다.', '#74F27A');
        else           flash($idMsg, j.message || '이미 사용 중인 ID입니다.', 'red');
      })
      .catch(function(){
        flash($idMsg, '요청 실패 또는 응답 파싱 실패', 'red');
      });
    }

    if ($email) { $email.addEventListener('focus', checkPwMatch); }
    if ($pw2)   { $pw2.addEventListener('blur',  checkPwMatch);  }

    function checkPwMatch(){
      if (!$pw || !$pw2 || !$pwMsg) return;
      if (!userInteracted) return;
      var p1 = ($pw.value  || '').trim();
      var p2 = ($pw2.value || '').trim();
      if (p2 === '') {
        flash($pwMsg, '비밀번호를 한번더 입력해주세요.', 'red');
        return;
      }
      if (p1 !== p2) {
        flash($pwMsg, '비밀번호가 일치하지 않습니다.', 'red');
      } else {
        flash($pwMsg, '비밀번호가 일치합니다.', '#74F27A');
      }
    }

    // 비밀번호 변경 사전검증
    var forgotForm   = document.getElementById('login');
    var forgotId     = document.getElementById('username_f');
    var forgotEmail  = document.getElementById('email');
    var forgotPw     = document.getElementById('password_f');

	// 비밀번호 변경 AJAX
	if (forgotForm) {
	  forgotForm.addEventListener('submit', function(e){
		e.preventDefault();

		var acc = (forgotId && forgotId.value || '').trim();
		var eml = (forgotEmail && forgotEmail.value || '').trim();
		var p1  = (document.getElementById('password_f').value || '');
		var p2  = (document.getElementById('passwordVerify_f').value || '');
		var vcF = (document.getElementById('verification_code_f') && document.getElementById('verification_code_f').value || '').trim();

		// 클라이언트 검증 - 현재 모달 유지 + 팝업만
		if (!acc) { showPopup('Enter account', { preserveModals: true }); return; }
		if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(eml)) { showPopup('올바른 이메일을 입력해주세요.', { preserveModals: true }); return; }
		if (!p1) { showPopup('Enter password', { preserveModals: true }); return; }
		if (p1 !== p2) { showPopup('비밀번호가 일치하지 않습니다.', { preserveModals: true }); return; }
		if (p1.length < 6 || p1.length > 16) { showPopup('비밀번호 길이는 6 ~ 16 자 여야합니다.', { preserveModals: true }); return; }
		if (!sessionStorage.getItem('verified_forgot')) { showPopup('이메일 인증을 완료해주세요.', { preserveModals: true }); return; }
        if (!vcF) { showPopup('인증번호를 입력해주세요.', { preserveModals: true }); return; }

		var submitBtn = forgotForm.querySelector('input[type=submit]');
		if (submitBtn) submitBtn.disabled = true;

		fetch('', {
		  method: 'POST',
		  headers: {'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8'},
		  credentials: 'same-origin',
		  body: new URLSearchParams({ forgot_ajax:'1', username:acc, email:eml, password:p1, passwordVerify:p2, verification_code:vcF })
		})
		.then(r=>r.text())
		.then(function(raw){
		  var j = extractJson(raw);
		  if (!j) throw new Error('parse');
		  var msg = j.message || (j.success ? '비밀번호가 변경되었습니다.' : '실패했습니다.');
		  if (j.success){
			queuePopupAfterHide('modalForgot', msg, function(){
			  try { forgotForm.reset(); } catch(_){}
			}, { reloadOnClose: true });
		  } else {
			// 실패 팝업도 모달 유지
			showPopup(msg, { preserveModals: true });
		  }
		})
		.catch(function(){
		  showPopup('요청 실패 또는 응답 파싱 실패', { preserveModals: true });
		})
		.finally(function(){ if (submitBtn) submitBtn.disabled = false; });
	  });
	}

    // 이메일 인증 흐름
    var btnSend = document.getElementById('btnSendCode');
    var btnVerify = document.getElementById('btnVerifyCode');
    var msgEmail = document.getElementById('emailMsg');
    var msgCode  = document.getElementById('codeMsg');

    if (btnSend) btnSend.addEventListener('click', function(){
      var email = document.getElementById('email_reg').value.trim();
      btnSend.style.display = 'none';
      msgEmail.style.color = '#bbb';
      msgEmail.textContent = '메일 발송 중...';
	  msgEmail.style.display = 'block';
	  function restoreBtn(delay){ setTimeout(function(){ btnSend.style.display=''; msgEmail.textContent=''; msgEmail.style.display='none'; }, delay); }

      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        msgEmail.style.color = 'red';
        msgEmail.textContent = '올바른 이메일을 입력해주세요.';
        restoreBtn(2000);
        return;
      }

      fetch('', {
        method: 'POST',
        headers: {'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8'},
        credentials: 'same-origin',
        body: new URLSearchParams({ send_code: '1', email })
      })
      .then(r => r.text())
      .then(raw => {
        var j = extractJson(raw);
        if (!raw || !raw.trim()) {
          msgEmail.style.color = 'red';
          btnSend.style.display = '';
          return;
        }
        if (!j || typeof j.success === 'undefined') {
          msgEmail.style.color = 'red';
          msgEmail.textContent = '요청 실패 또는 응답 파싱 실패';
          restoreBtn(3000);
          return;
        }
        msgEmail.style.color = j.success ? '#74F27A' : 'red';
        msgEmail.textContent = j.message || (j.success ? 'OK' : '메일 발송 실패');
		if (!j.success) {
          if (/재전송|쿨타임|초\s*후\s*가능/.test(j.message||'')) restoreBtn(3000);
          else restoreBtn(3000);
        }
      })
      .catch(() => {
        msgEmail.style.color = 'red';
        msgEmail.textContent = '메일 발송 실패: 네트워크 오류';
        restoreBtn(5000);
      });
    });

    if (btnVerify) btnVerify.addEventListener('click', function(){
      var email = document.getElementById('email_reg').value.trim();
      var code  = document.getElementById('verification_code').value.trim();
      btnVerify.disabled = true;
      msgCode.textContent = '';
	  msgCode.style.display = 'block';
	  function restoreVerify(delay){ setTimeout(function(){ btnVerify.style.display=''; msgCode.textContent=''; msgCode.style.display='none'; }, delay); }

      fetch('', {
        method: 'POST',
        headers: {'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8'},
        credentials: 'same-origin',
        body: new URLSearchParams({ verify_code:'1', email, verification_code:code })
      })
      .then(r => r.text())
      .then(raw => {
        var j = extractJson(raw);
        if (!j) { throw new Error('parse'); }
        msgCode.style.color = j.success ? '#74F27A' : 'red';
        msgCode.textContent = j.message || (j.success ? '인증 완료' : '인증 실패');
		msgCode.style.display = 'block'; // 숨김 상태였어도 다시 보이게

        if (j.success) {
          sessionStorage.setItem('verified', '1');
          btnVerify.style.display = 'none';
        } else {
          sessionStorage.removeItem('verified');
          btnVerify.style.display = 'none';
		  restoreVerify(2000);
        }
      })
      .catch(()=>{
        msgCode.style.color='red';
        msgCode.textContent='요청 실패 또는 응답 파싱 실패';
		msgCode.style.display='block'; // 에러도 확실히 노출
        btnVerify.style.display='none';
        restoreVerify(5000);
      })
      .finally(()=>{ btnVerify.disabled = false; });
    });

	// ===== NEW: 비번 변경용 인증메일 발송 =====
  var btnSendF = document.getElementById('btnSendCode_f');
  var msgEmailF = document.getElementById('emailForgotMsg');
  if (btnSendF) btnSendF.addEventListener('click', function(){
    var email = (document.getElementById('email').value || '').trim();
	var accF  = (document.getElementById('username_f').value || '').trim();

    btnSendF.style.display = 'none';
    if (msgEmailF){ msgEmailF.style.color='#bbb'; msgEmailF.textContent='메일 발송 중...'; msgEmailF.style.display='block'; }
	// helper: 버튼/메시지 복구
    function restoreBtnF(delayMs){
      setTimeout(function(){
        btnSendF.style.display = '';
        if (msgEmailF){ msgEmailF.textContent=''; msgEmailF.style.display='none'; }
      }, delayMs);
    }

    // 계정 미입력 → 1초 후 복구
    if (!accF) {
      if (msgEmailF){ msgEmailF.style.color='red'; msgEmailF.textContent='계정을 먼저 입력해주세요.'; }
      restoreBtnF(2000);
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      if (msgEmailF){ msgEmailF.style.color='red'; msgEmailF.textContent='올바른 이메일을 입력해주세요.'; }
      restoreBtnF(3000);
      return;
    }
    fetch('', {
      method: 'POST',
      headers: {'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8'},
      credentials: 'same-origin',
      body: new URLSearchParams({ send_code:'1', email:email, username:accF })
    })
    .then(r=>r.text())
    .then(function(raw){
      var j = extractJson(raw);
      if (!j || typeof j.success==='undefined') {
        if (msgEmailF){ msgEmailF.style.color='red'; msgEmailF.textContent='요청 실패 또는 응답 파싱 실패'; }
        restoreBtnF(3000);
        return;
      }
      if (msgEmailF){
        msgEmailF.style.color = j.success ? '#74F27A' : 'red';
        msgEmailF.textContent = j.message || (j.success ? 'OK' : '메일 발송 실패');
      }
      if (!j.success) {
        var m = j.message || '';
        if (/재전송|쿨타임|초\s*후\s*가능/.test(m)) {
          restoreBtnF(3000);        // 쿨타임은 3초 유지
        } else if (/일치/.test(m)) {
          restoreBtnF(3000);        // 계정/이메일 불일치 → 1초
        } else {
          restoreBtnF(3000);        // 기타 실패도 1초
        }
      }
    })
    .catch(function(){
      if (msgEmailF){ msgEmailF.style.color='red'; msgEmailF.textContent='메일 발송 실패: 네트워크 오류'; }
      restoreBtnF(5000);
    });
  });

  // ===== NEW: 비번 변경용 인증번호 확인 =====
  var btnVerifyF = document.getElementById('btnVerifyCode_f');
  var msgCodeF   = document.getElementById('codeMsg_f');
  if (btnVerifyF) btnVerifyF.addEventListener('click', function(){
    var email = (document.getElementById('email').value || '').trim();
    var code  = (document.getElementById('verification_code_f').value || '').trim();
    btnVerifyF.disabled = true;
    if (msgCodeF) msgCodeF.textContent='';
	function restoreVerifyF(delay){ setTimeout(function(){ btnVerifyF.style.display=''; if (msgCodeF){ msgCodeF.textContent=''; msgCodeF.style.display='none'; } }, delay); }
    fetch('', {
      method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8'},
      credentials:'same-origin',
      body:new URLSearchParams({ verify_code:'1', email:email, verification_code:code })
    })
    .then(r=>r.text())
    .then(function(raw){
      var j = extractJson(raw);
      if (!j) throw new Error('parse');
      if (msgCodeF){
        msgCodeF.style.color = j.success ? '#74F27A' : 'red';
        msgCodeF.textContent = j.message || (j.success ? '인증 완료' : '인증 실패');
        msgCodeF.style.display='block';
      }
      if (j.success) {
        sessionStorage.setItem('verified_forgot','1');
        btnVerifyF.style.display='none';
      } else {
        sessionStorage.removeItem('verified_forgot');
        btnVerifyF.style.display='none';
		restoreVerifyF(3000);
      }
    })
    .catch(function(){
      if (msgCodeF){ msgCodeF.style.color='red'; msgCodeF.textContent='요청 실패 또는 응답 파싱 실패'; msgCodeF.style.display='block'; }
      btnVerifyF.style.display='none';
      restoreVerifyF(3000);
    })
    .finally(function(){ btnVerifyF.disabled=false; });
  });

    // (선택) ACM iframe 모달 자동 높이
    (function(){
      var modal=document.getElementById('modalAcm'), frame=document.getElementById('acmFrame'), dialog=document.getElementById('acmDialog');
      var ro=null, onWinResizeBound=null;
      function syncWidth(){ if(dialog) dialog.style.maxWidth='min(95vw, 600px)'; }
      function syncHeight(){
        try{
          var doc=frame && frame.contentWindow && frame.contentWindow.document; if(!doc) return;
          var form=doc.getElementById('accountForm'); if(!form) return;
          var h=Math.max(form.scrollHeight, form.getBoundingClientRect().height);
          var vh=Math.max(document.documentElement.clientHeight, window.innerHeight||0);
          frame.style.height=Math.min(Math.ceil(h*1.2), Math.floor(vh*0.9))+'px';
        }catch(e){}
      }
      if (modal && frame){
        modal.addEventListener('shown.bs.modal', function(){ syncWidth(); frame.src='../acm/index.php'; });
        frame.addEventListener('load', function(){
          syncWidth(); syncHeight();
          if(ro&&ro.disconnect){try{ro.disconnect();}catch(e){} ro=null;}
          try{
            var doc=frame.contentWindow.document;
            ro=new ResizeObserver(syncHeight);
            ro.observe(doc.body);
            var f=doc.getElementById('accountForm'); if(f) ro.observe(f);
          }catch(e){ setTimeout(syncHeight,200); }
          if(onWinResizeBound) window.removeEventListener('resize', onWinResizeBound);
          onWinResizeBound=function(){ syncWidth(); syncHeight(); };
          window.addEventListener('resize', onWinResizeBound);
        });
        modal.addEventListener('hidden.bs.modal', function(){
          if(ro&&ro.disconnect){try{ro.disconnect();}catch(e){}}
          ro=null;
          if(onWinResizeBound){ window.removeEventListener('resize', onWinResizeBound); onWinResizeBound=null; }
          frame.src=''; frame.style.height='60vh';
        });
      }
    })();

  });
})();
</script>
<br><br>
<center><font color=white>※ 캐릭터 생성을 하지 않으면 계정이 삭제됩니다. ※</font></center>
<br><br>