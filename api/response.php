<?php
function json_success($arg1 = [], $arg2 = null)
{
    // 기본 구조
    $base = ['success' => true];

    // 1) json_success(['token' => ..., 'account' => ...]) 형태
    if (is_array($arg1) && $arg2 === null) {
        // success 키에 나머지 배열 병합
        $base += $arg1;
    }
    // 2) json_success('ok', ['online' => 123]) 형태
    else {
        if (is_string($arg1)) {
            $base['message'] = $arg1;
        }
        if (is_array($arg2)) {
            $base['data'] = $arg2;
        }
    }

    echo json_encode($base, JSON_UNESCAPED_UNICODE);
    exit;
}

function json_error($msg, $code = null)
{
    $data = [
        'success' => false,
        'error'   => $msg,
    ];

    // 선택 사항: HTTP 코드나 에러 코드를 같이 넘길 때 사용
    if ($code !== null) {
        $data['code'] = (int)$code;
    }

    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}
