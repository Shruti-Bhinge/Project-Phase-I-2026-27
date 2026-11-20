<?php
$secureCookie = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
session_set_cookie_params([
    'httponly' => true,
    'samesite' => 'Lax',
    'secure' => $secureCookie,
    'path' => '/',
]);
session_start();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

function geminiProxyRespond(array $data, int $status = 200): void
{
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

function geminiProxyRateLimit(PDO $pdo, int $userId, int $maxPerMinute): void
{
    $pdo->beginTransaction();
    try {
        $insert = $pdo->prepare('INSERT IGNORE INTO rate_limits (user_id, window_start, count) VALUES (?, CURRENT_TIMESTAMP, 0)');
        $insert->execute([$userId]);
        $select = $pdo->prepare('SELECT window_start, count, TIMESTAMPDIFF(SECOND, window_start, CURRENT_TIMESTAMP) AS age FROM rate_limits WHERE user_id = ? FOR UPDATE');
        $select->execute([$userId]);
        $limit = $select->fetch();
        if (!$limit) {
            $pdo->rollBack();
            geminiProxyRespond(['reply' => 'The AI service is temporarily unavailable.'], 503);
        }

        if ((int) $limit['age'] >= 60) {
            $update = $pdo->prepare('UPDATE rate_limits SET window_start = CURRENT_TIMESTAMP, count = 1 WHERE user_id = ?');
            $update->execute([$userId]);
        } elseif ((int) $limit['count'] >= $maxPerMinute) {
            $pdo->commit();
            geminiProxyRespond(['reply' => 'Please wait a minute before trying again.'], 429);
        } else {
            $update = $pdo->prepare('UPDATE rate_limits SET count = count + 1 WHERE user_id = ?');
            $update->execute([$userId]);
        }
        $pdo->commit();
    } catch (PDOException $exception) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log('Gemini proxy rate-limit query failed: ' . $exception->getMessage());
        geminiProxyRespond(['reply' => 'The AI service is temporarily unavailable.'], 503);
    }
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    geminiProxyRespond(['reply' => 'Method not allowed.'], 405);
}
if (empty($_SESSION['user_id'])) {
    geminiProxyRespond(['reply' => 'Please log in again.'], 401);
}

$contentType = strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0]));
if ($contentType !== 'application/json') {
    geminiProxyRespond(['reply' => 'A JSON request is required.'], 415);
}
$rawInput = file_get_contents('php://input');
if (!is_string($rawInput) || strlen($rawInput) > 16000) {
    geminiProxyRespond(['reply' => 'The request is too large.'], 413);
}
$input = json_decode($rawInput, true);
if (!is_array($input) || !is_string($input['message'] ?? null)) {
    geminiProxyRespond(['reply' => 'Enter a question up to 4,000 characters long.'], 400);
}
$userMessage = trim($input['message']);
$messageLength = function_exists('mb_strlen') ? mb_strlen($userMessage, 'UTF-8') : strlen($userMessage);
if ($userMessage === '' || $messageLength > 4000) {
    geminiProxyRespond(['reply' => 'Enter a question up to 4,000 characters long.'], 400);
}

$apiKey = getenv('GEMINI_API_KEY');
if (!is_string($apiKey) || trim($apiKey) === '') {
    $privateConfigPath = dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'phishshield-gemini.php';
    if (is_file($privateConfigPath)) {
        $privateApiKey = require $privateConfigPath;
        if (is_string($privateApiKey)) {
            $apiKey = $privateApiKey;
        }
    }
}
if (!is_string($apiKey) || trim($apiKey) === '') {
    geminiProxyRespond(['reply' => 'AI chat is not configured. Set GEMINI_API_KEY for Apache or create C:\\xampp\\phishshield-gemini.php outside htdocs.'], 503);
}
if (!function_exists('curl_init')) {
    geminiProxyRespond(['reply' => 'The PHP cURL extension is required.'], 503);
}

require_once __DIR__ . '/config.php';
geminiProxyRateLimit($pdo, (int) $_SESSION['user_id'], 15);

$systemPrompt = 'You are the PhishShield AI Assistant. Be helpful, concise, and answer questions about the PhishShield cybersecurity project. The project has a Dashboard, a Live Scanner with real-time typing and bulk scanning of up to 50 lines, a Threat Map, and a History page. It detects phishing in URLs, emails, messages, and QR codes using PHP rules and an optional machine-learning service. Answer directly and helpfully based on this context. Keep answers under three short paragraphs.';
$model = getenv('GEMINI_MODEL') ?: 'gemini-3.8-flash';
if (!is_string($model) || !preg_match('/^[a-zA-Z0-9._-]{1,80}$/', $model)) {
    geminiProxyRespond(['reply' => 'The AI model setting is invalid.'], 503);
}
$requestBody = [
    'systemInstruction' => ['parts' => [['text' => $systemPrompt]]],
    'contents' => [['role' => 'user', 'parts' => [['text' => $userMessage]]]],
    'generationConfig' => [
        'temperature' => 0.3,
        'maxOutputTokens' => 1024,
    ],
];
$requestJson = json_encode($requestBody, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
if (!is_string($requestJson)) {
    geminiProxyRespond(['reply' => 'The AI request could not be prepared.'], 500);
}

$url = 'https://generativelanguage.googleapis.com/v1beta/models/' . rawurlencode($model) . ':generateContent';
$handle = curl_init($url);
if ($handle === false) {
    geminiProxyRespond(['reply' => 'Could not initialize the AI request.'], 500);
}
curl_setopt_array($handle, [
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => $requestJson,
    CURLOPT_HTTPHEADER => [
        'Content-Type: application/json',
        'x-goog-api-key: ' . trim($apiKey),
    ],
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_TIMEOUT => 35,
    CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
]);
$response = curl_exec($handle);
$httpCode = (int) curl_getinfo($handle, CURLINFO_HTTP_CODE);
if ($response === false) {
    error_log('Gemini proxy request failed: ' . curl_error($handle));
    curl_close($handle);
    geminiProxyRespond(['reply' => 'Sorry, I could not connect to the AI server.'], 502);
}
curl_close($handle);

$result = json_decode($response, true);
$parts = $result['candidates'][0]['content']['parts'] ?? [];
$reply = '';
if (is_array($parts)) {
    foreach ($parts as $part) {
        if (is_array($part) && is_string($part['text'] ?? null)) {
            $reply .= $part['text'];
        }
    }
}
if ($httpCode < 200 || $httpCode >= 300 || trim($reply) === '') {
    error_log('Gemini proxy returned HTTP status ' . $httpCode . ' or an empty reply.');
    geminiProxyRespond(['reply' => 'Sorry, I could not generate a response.'], 502);
}

geminiProxyRespond(['reply' => trim($reply)]);
