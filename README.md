# PhishShield

## Setup

1. Start Apache and MySQL in XAMPP.
2. Import `database.sql` into MySQL using phpMyAdmin.
3. Open `http://localhost/phishshield/login.html`.

## Signup and login

Sign up with a name, email address, password, and matching password confirmation. Names must be 2-60 characters and use letters, spaces, periods, apostrophes, or hyphens. Passwords must be 8-64 characters and include a lowercase letter, an uppercase letter, a number, and a symbol. Disposable email providers are not accepted.

After signup, PhishShield switches directly to Login and fills in the email address. No email verification code is required.

## Ask PhishShield AI

The chatbot uses the Gemini API through `api.php`; its API key is never sent to the browser. Configure `GEMINI_API_KEY` as a Windows environment variable available to the Apache process, or create `C:\xampp\phishshield-gemini.php` outside `htdocs` with the following content:

```php
<?php
return 'YOUR_GEMINI_API_KEY';
```

Replace the placeholder with your key. Do not put the key in an HTML, JavaScript, or other web-accessible project file. Optionally set `GEMINI_MODEL`; the default is `gemini-3.8-flash`.

After setting the environment variable, fully restart the XAMPP Control Panel and Apache so Apache inherits the updated environment. The private PHP config file is loaded on each request and does not require an Apache restart. If Apache runs as a Windows service, set the variable in the system environment available to that service. Ensure PHP's cURL extension is enabled. Without a usable key or cURL, the chatbot displays an explicit configuration error instead of returning a canned answer.

The assistant sends the current message and up to 10 prior conversation messages to Google Gemini. Current-information questions may also use Google Search grounding; returned grounding links are shown as sources. Conversation history stays in the current page and the **New chat** button clears it. Scan history and scanner inputs are not loaded or sent automatically. Do not include private scan content in a chat unless you intend to send that text to Google.
