<?php

function sendVerificationEmail($email, $name, $code)
{
    $autoload = __DIR__ . '/vendor/autoload.php';
    if (!is_file($autoload)) {
        throw new RuntimeException('Email delivery is not installed. Run Composer install in the PhishShield folder.');
    }
    require_once $autoload;

    $host = getenv('PHISHSHIELD_SMTP_HOST');
    $username = getenv('PHISHSHIELD_SMTP_USERNAME');
    $password = getenv('PHISHSHIELD_SMTP_PASSWORD');
    $fromEmail = getenv('PHISHSHIELD_MAIL_FROM');
    if (!$host || !$username || !$password || !$fromEmail || !filter_var($fromEmail, FILTER_VALIDATE_EMAIL)) {
        throw new RuntimeException('Email delivery is not configured. Set the PhishShield SMTP environment variables.');
    }

    $encryption = strtolower(getenv('PHISHSHIELD_SMTP_ENCRYPTION') ?: 'tls');
    if (!in_array($encryption, ['tls', 'ssl'], true)) {
        throw new RuntimeException('SMTP encryption must be tls or ssl.');
    }
    $defaultPort = $encryption === 'ssl' ? 465 : 587;
    $port = (int) (getenv('PHISHSHIELD_SMTP_PORT') ?: $defaultPort);

    $mail = new PHPMailer\PHPMailer\PHPMailer(true);
    $mail->isSMTP();
    $mail->Host = $host;
    $mail->SMTPAuth = true;
    $mail->Username = $username;
    $mail->Password = $password;
    $mail->SMTPSecure = $encryption;
    $mail->Port = $port;
    $mail->Timeout = 15;
    $mail->CharSet = 'UTF-8';
    $mail->setFrom($fromEmail, getenv('PHISHSHIELD_MAIL_FROM_NAME') ?: 'PhishShield');
    $mail->addAddress($email, $name);
    $mail->isHTML(true);
    $mail->Subject = 'Your PhishShield verification code';
    $safeName = htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $mail->Body = '<p>Hello ' . $safeName . ',</p>'
        . '<p>Your PhishShield email verification code is:</p>'
        . '<p style="font-size:24px;font-weight:bold;letter-spacing:5px">' . $code . '</p>'
        . '<p>This code expires in 10 minutes. If you did not request it, you can ignore this email.</p>';
    $mail->AltBody = "Hello {$name}, your PhishShield verification code is {$code}. It expires in 10 minutes.";
    $mail->send();
}
