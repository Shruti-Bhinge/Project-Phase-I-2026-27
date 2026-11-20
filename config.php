<?php
// XAMPP defaults: MySQL user "root" with an empty password.
// If you set a MySQL password, put it here or set PHISHING_DB_PASSWORD in Apache.
$dbHost = getenv('PHISHING_DB_HOST') ?: '127.0.0.1';
$dbName = getenv('PHISHING_DB_NAME') ?: 'phishshield';
$dbUser = getenv('PHISHING_DB_USER') ?: 'root';
$dbPassword = getenv('PHISHING_DB_PASSWORD') ?: '';

$dsn = "mysql:host={$dbHost};dbname={$dbName};charset=utf8mb4";

try {
    $pdo = new PDO($dsn, $dbUser, $dbPassword, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
} catch (PDOException $exception) {
    http_response_code(500);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error' => 'Cannot connect to MySQL. Check that XAMPP MySQL is running and config.php is correct.']);
    exit;
}
