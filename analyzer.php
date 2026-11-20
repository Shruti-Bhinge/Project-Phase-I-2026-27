<?php

// Well-known domains. A host is trusted only if it IS the domain or a true subdomain of it
// (so google.com.evil.xyz is NOT trusted). The community blocklist still applies to trusted hosts.
function trustedDomainList(): array
{
    return [
        'google.com', 'google.co.in', 'google.co.uk', 'youtube.com', 'gmail.com', 'googlemail.com',
        'microsoft.com', 'microsoft365.com', 'office.com', 'office365.com', 'outlook.com', 'live.com',
        'bing.com', 'apple.com', 'icloud.com', 'amazon.com', 'amazon.in', 'amazon.co.uk',
        'github.com', 'wikipedia.org', 'linkedin.com', 'facebook.com', 'instagram.com',
        'whatsapp.com', 'whatsapp.net', 'twitter.com', 'x.com', 'netflix.com', 'paypal.com', 'paypal.me',
        'yahoo.com', 'chatgpt.com', 'openai.com', 'anthropic.com', 'claude.ai',
        'flipkart.com', 'paytm.com', 'phonepe.com', 'phon.pe', 'sbi.co.in', 'onlinesbi.sbi', 'hdfcbank.com',
        'icicibank.com', 'axisbank.com', 'nptel.ac.in', 'python.org', 'php.net', 'mozilla.org',
        'stackoverflow.com', 'zoom.us', 'zoom.com', 'dropbox.com', 'cloudflare.com',
    ];
}

// Returns the registrable name of a host, e.g. "www.goog.com" => "goog", "mail.sbi.co.in" => "sbi".
function registrableName(string $host): string
{
    $labels = explode('.', $host);
    $count = count($labels);
    if ($count < 2) {
        return $host;
    }
    $secondLevel = ['co', 'com', 'ac', 'org', 'net', 'gov', 'edu'];
    if ($count >= 3 && strlen($labels[$count - 1]) === 2 && in_array($labels[$count - 2], $secondLevel, true)) {
        return $labels[$count - 3];
    }
    return $labels[$count - 2];
}

// Big infrastructure / hosting platforms. Their names contain brands (amazonaws, googleapis ...)
// so they must not be reported as look-alikes, but they are NOT trusted either: normal scoring applies.
function isKnownInfraHost(string $host): bool
{
    $infra = ['amazonaws.com', 'googleapis.com', 'googleusercontent.com', 'gstatic.com', 'windows.net',
        'azurewebsites.net', 'microsoftonline.com', 'cloudfront.net', 'githubusercontent.com', 'github.io'];
    foreach ($infra as $domain) {
        if ($host === $domain || substr($host, -(strlen($domain) + 1)) === '.' . $domain) {
            return true;
        }
    }
    return false;
}

// Reduces a name to a comparable "skeleton": g00gle / googIe / gooogle / goog-le all become "gogle".
function spoofSkeleton(string $s): string
{
    $s = strtolower(str_replace('-', '', $s));
    $s = strtr($s, ['0' => 'o', '1' => 'l', 'i' => 'l', '3' => 'e', '4' => 'a', '5' => 's', '7' => 't', '$' => 's']);
    $s = str_replace(['rn', 'vv'], ['m', 'w'], $s);
    return (string) preg_replace('/(.)\1+/', '$1', $s);
}

// True when $a differs from $b only by two neighbouring letters being swapped (gmial / gmail).
function oneSwapAway(string $a, string $b): bool
{
    if (strlen($a) !== strlen($b)) {
        return false;
    }
    for ($i = 0, $n = strlen($a) - 1; $i < $n; $i++) {
        if ($a[$i] !== $b[$i]) {
            return $a[$i] === $b[$i + 1] && $a[$i + 1] === $b[$i] && substr($a, $i + 2) === substr($b, $i + 2);
        }
    }
    return false;
}

// Detects hosts that imitate a trusted domain. Returns null when the host is trusted or unrelated.
// Result: ['brand' => trusted domain, 'rule' => ..., 'weight' => ..., 'detail' => ...]
function detectBrandSpoof(string $host): ?array
{
    $host = rtrim(strtolower($host), '.');
    if ($host === '' || filter_var($host, FILTER_VALIDATE_IP) || isTrustedDomain($host) || isKnownInfraHost($host)) {
        return null;
    }
    $name = registrableName($host);
    $skName = spoofSkeleton($name);
    $parents = array_slice(explode('.', $host), 0, -2); // labels left of the registrable domain + its ending
    $best = null;
    $consider = static function (array $hit) use (&$best): void {
        if ($best === null || $hit['weight'] > $best['weight']) {
            $best = $hit;
        }
    };

    foreach (trustedDomainList() as $domain) {
        $brand = registrableName($domain);
        $len = strlen($brand);
        if ($len < 4) {
            continue;
        }
        $skBrand = spoofSkeleton($brand);

        // 1. Same name on a different ending: gmail.co, paypal.net
        if ($name === $brand) {
            if ($len >= 5) {
                $consider(['brand' => $domain, 'rule' => 'brand_wrong_tld', 'weight' => 45,
                    'detail' => '"' . $host . '" uses the name of ' . $domain . ' with a different domain ending.']);
            }
            continue;
        }
        // 2. Extra / missing / swapped / look-alike characters: gooogle.com, g00gle.com, gmial.com
        $limit = $len >= 8 ? 2 : 1;
        if ($skName === $skBrand
            || ($len >= 5 && (levenshtein($skName, $skBrand) <= $limit || oneSwapAway($skName, $skBrand)))) {
            $consider(['brand' => $domain, 'rule' => $skName === $skBrand ? 'lookalike_domain' : 'similar_name_domain', 'weight' => 80,
                'detail' => '"' . $host . '" looks like a misspelling of the trusted site ' . $domain . ' (extra, missing, swapped or look-alike characters).']);
            continue;
        }
        if ($len < 5) {
            continue;
        }
        // 3. Brand plus extra words: gmail-login.com, paypalsecure.net
        if (strpos($skName, $skBrand) !== false) {
            $consider(['brand' => $domain, 'rule' => 'brand_embedded', 'weight' => 60,
                'detail' => '"' . $host . '" contains the brand "' . $brand . '" but is not ' . $domain . '.']);
            continue;
        }
        // 4. Brand placed in a sub-domain: google.com.evil.xyz, gmail.secure-mail.net
        foreach ($parents as $label) {
            if ($label !== '' && spoofSkeleton($label) === $skBrand) {
                $consider(['brand' => $domain, 'rule' => 'brand_in_subdomain', 'weight' => 60,
                    'detail' => '"' . $host . '" puts "' . $brand . '" in a sub-domain to look like ' . $domain . '.']);
                break;
            }
        }
    }
    return $best;
}

// Temporary / throw-away mail services. Their addresses are used for scams and spam because they cannot be traced.
function disposableDomainList(): array
{
    return [
        'maxxspace.com', 'mailinator.com', 'tempmail.com', 'temp-mail.org', 'temp-mail.io', 'tempmail.plus', 'tempmail.dev',
        'tempmailo.com', 'tempail.com', 'tempr.email', 'tempinbox.com', 'mytemp.email', '10minutemail.com', '10minutemail.net',
        'guerrillamail.com', 'guerrillamail.net', 'guerrillamail.org', 'guerrillamail.biz', 'guerrillamail.de', 'guerrillamailblock.com',
        'sharklasers.com', 'grr.la', 'throwawaymail.com', 'yopmail.com', 'yopmail.fr', 'yopmail.net', 'trashmail.com', 'trashmail.net',
        'getnada.com', 'nada.email', 'dispostable.com', 'maildrop.cc', 'mailnesia.com', 'fakeinbox.com', 'fakemail.net', 'emailfake.com',
        'mohmal.com', 'emailondeck.com', 'mintemail.com', 'spamgourmet.com', 'burnermail.io', 'moakt.com', 'tmail.ws', '1secmail.com',
        '1secmail.org', '1secmail.net', 'mail.tm', 'inboxkitten.com', 'discard.email', 'dropmail.me', 'harakirimail.com', 'spambox.us',
        'jetable.org', 'crazymailing.com', 'gmailnator.com', 'tmpmail.org', 'tmpmail.net', 'mailtemp.net', 'mailcatch.com', 'mailsac.com',
        'throwam.com', 'trbvm.com', 'getairmail.com', 'anonbox.net', 'wegwerfmail.de', 'byom.de', 'mvrht.net', 'luxusmail.org',
    ];
}

function isDisposableDomain(string $domain): bool
{
    $domain = rtrim(strtolower(trim($domain)), '.');
    if ($domain === '') {
        return false;
    }
    foreach (disposableDomainList() as $bad) {
        if ($domain === $bad || substr($domain, -(strlen($bad) + 1)) === '.' . $bad) {
            return true;
        }
    }
    // Names of throw-away services that are not on the list yet.
    return (bool) preg_match('/(?:temp-?mail|trash-?mail|throw-?away|10-?minute|guerrilla|disposable|fake-?inbox|burner|mailinator|yopmail)/', $domain);
}

// Machine-generated mailbox names such as "47eaed3c5857" (hex) or "x8k2m9q4w1" are typical of throw-away addresses.
function looksRandomLocalPart(string $local): bool
{
    $local = strtolower($local);
    if (preg_match('/^[0-9a-f]{8,}$/', $local) && preg_match('/\d/', $local)) {
        return true;
    }
    $len = strlen($local);
    $digits = preg_match_all('/\d/', $local);
    $letters = preg_match_all('/[a-z]/', $local);
    return $len >= 10 && preg_match('/^[a-z0-9]+$/', $local) && $digits / $len >= 0.3 && $letters >= 3 && !preg_match('/[a-z]{4,}/', $local);
}

function isTrustedDomain(string $host): bool
{
    foreach (trustedDomainList() as $domain) {
        if ($host === $domain) {
            return true;
        }
        $suffix = '.' . $domain;
        if (strlen($host) > strlen($suffix) && substr($host, -strlen($suffix)) === $suffix) {
            return true;
        }
    }
    return false;
}

// True only if the input looks like a real URL / domain. Single letters ("h"), single words
// ("google") and text with spaces ("hello world") are rejected.
// Accepted: http/https links, bare domains (example.com), localhost, and IP addresses.
function isValidUrlInput(string $input): bool
{
    $input = trim($input);
    if ($input === '' || strlen($input) > 2048 || preg_match('/[\s\x00-\x1f\x7f\\\\<>"\'`]/', $input)) {
        return false;
    }
    if (preg_match('~^[a-z][a-z0-9+.-]*://~i', $input)) {
        if (!preg_match('~^https?://~i', $input)) {
            return false; // only http / https are accepted
        }
        $candidate = $input;
    } else {
        $candidate = 'http://' . $input;
    }
    $parts = parse_url($candidate);
    if ($parts === false || empty($parts['host'])) {
        return false;
    }
    $host = strtolower($parts['host']);
    if ($host === 'localhost' || filter_var(trim($host, '[]'), FILTER_VALIDATE_IP)) {
        return true;
    }
    // Needs at least one dot and a real ending such as .com, .in, .co.in
    return (bool) preg_match(
        '/^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/',
        $host
    );
}

// ---------------------------------------------------------------------------
// Input validation for the Email and SMS tabs.
// ---------------------------------------------------------------------------

// Very common English / Hinglish words. Real emails and SMS texts always contain a few of them;
// random keyboard letters ("hhhh shajkh uyuonbkjsh") contain none.
function commonWordSet(): array
{
    static $set = null;
    if ($set === null) {
        $set = array_flip(preg_split('/\s+/', trim('a aap aapka aapki aapko ab abhi about above account across action activity actually add address admin after again against age agree ahead all allow almost alone along already also although always am amount an and another answer any anyone anything apna apne app application apply approved are area around as ask asked at atm attached attention aur available avoid away baad back bad balance bank based bata batao be because become been before begin behind being believe below benefit benefits best better between bhai bhejo big bill bit block blocked both box bring brother build business busy but buy by call called came can cancel candidate cannot car card care case cash cashback center certificate chance change charge charges check claim class clear click close closed code collect come comes coming common company complete completed confirm congratulations connect contact content continue copy cost could count course credit credited crore current customer daily data date day days deal dear debit debited december decide delay delivered delivery department detail details dhanyavad did didn die different digital do document does doing done dont door down download due during each early earn easy education either else email end enjoy enough enter entry even evening ever every everyone everything exam example expire expired expires extra face fact fail fall family far fast father fee feel fees few fill final find fine finish first five fix follow food for forget form found four free friend friends from front full fund future game gave get gets getting gift girl give given glad go goes going gone good got government great group grow guess had hai hain half ham hand happen happy hard has have he head hear heard hello help her here hey hi high him his ho hoga hogi hold holiday home hope hour hours house how however hr hu hum hun hundred i id idea if ifsc immediately important imps in include info information instant instead interest interview into invite is issue it item its jaiye jao ji job join july june just ka kab kahan kaise kare karen karna karo ke keep key ki kind kindly knew know known ko kripya kuch kya kyc kyun land language large last late later launch learn least leave left less let letter level life light like limit line link list little live liye loan local login long look lost lot love low lucky made mail main make man many march mark match matter may maybe me mean meet meeting mein member mera meri message might million mind minute minutes miss missed mobile mom money month months more morning most mother move much must my nahi nahin namaste name near need needs neft net never new news next night no none noon not note nothing notice now number of off offer office official often ok old on once one online only open or order other otp our out over own pack page paid par parcel part party pass password pay paying payment pe people per period person phone pin place plan plans play please plus point police policy position post power prefer present press price prize problem process product profile program promo provide public purchase put query question quick quite raha rahe rahi rate reach read ready real reason receive received recharge record reduce refund regards register registered registration relax remain remember repeat reply report request required reset response rest result resume return reward rewards right role rs run sab safe said salary sale same sat save say scan school score se search second secure see seem seen select selected send sent service services set seven several share she shipped shop short shortlisted should show sign simple since sincerely sir sister sit six size sleep slow small sms so social some someone something sometimes son soon sorry sound speak special spend sport staff stand start started state status stay step still stop store story student study subject submit success such suddenly suggest sun sunday support sure system table tak take taken talk tax team tell ten tera teri term terms test text tha than thank thanks that the their them then there these they thi thing things think third this those though thought three through thursday ticket till time times to today together told tomorrow tonight too took top total touch town track train transaction transfer travel true try tuesday tum turn two type under understand unit until up update upi upto us use used user using usual valid value verify very via video view visit wait wake walk want warning was watch water way we wear weather web website wednesday week weekend welcome well went were what when where whether which while white who whole why wife will win winner wish with within without wo woh woman won wonder word words work working world worry would write wrong ye year years yeh yes yesterday yet you young your yours')));
        foreach (extraCommonWords() as $extraWord) {
            $set[$extraWord] = true;
        }
        // Brand names are valid words too (Jio, PhonePe, Google ...).
        foreach (trustedDomainList() as $domain) {
            $set[registrableName($domain)] = true;
        }
        foreach (['jio', 'jiohotstar', 'hotstar', 'gemini', 'airtel', 'vodafone', 'bsnl', 'hdfc', 'icici', 'axis'] as $brand) {
            $set[$brand] = true;
        }
    }
    return $set;
}

// Stretched letters (veryyy), laughter (ahahh), keyboard mash (no vowels, long consonant runs).
function isJunkWord(string $word): bool
{
    return (bool) preg_match('/(.)\1{2,}/u', $word)
        || (bool) preg_match('/^(?:ha|ah|he|eh|hm|mm|lo|ol)+h*$/', $word)
        || (bool) preg_match('/[^aeiouy]{6,}/', $word)
        || (strlen($word) >= 3 && !preg_match('/[aeiouy]/', $word));
}

// True when the text is HTML, a script or program source instead of a normal email / message.
function looksLikeCodeOrMarkup(string $text): bool
{
    if (preg_match('/^\s*(?:<!doctype|<\?php|<html|<head|<body|<script|<style|<svg|<\?xml)/i', $text)) {
        return true;
    }
    // Three or more real tags (<div>, <a href="...">, </p> ...). "<name@mail.com>" is not a tag.
    if (preg_match_all('~</?[a-z][a-z0-9-]*(?:\s[^<>]*)?/?>~i', $text) >= 3) {
        return true;
    }
    $hits = 0;
    $patterns = [
        '/\bfunction\s*\w*\s*\(/', '/=>/', '/\b(?:const|let|var)\s+\w+\s*=/', '/\b(?:document|window|console|localStorage|sessionStorage)\./',
        '/\$\w+\s*=/', '/<\?php/', '/\b(?:foreach|isset|require_once|include_once)\b\s*\(/', '/\bSELECT\b.+\bFROM\b/i',
        '/^\s*(?:import|from)\s+[\w.]+\s+import\b/m', '/\{\s*[\w-]+\s*:[^}]*;\s*\}/', '/\bif\s*\(.+\)\s*\{/',
    ];
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $text)) {
            $hits++;
        }
    }
    if ($hits >= 2) {
        return true;
    }
    $symbols = preg_match_all('/[{};<>]/', $text);
    return strlen($text) >= 40 && $symbols / max(1, strlen($text)) > 0.04;
}

// Extra everyday and SMS words that the base list above does not cover.
function extraCommonWords(): array
{
    return preg_split('/\s+/', trim('urgent urgently asap suspended suspend locked lock unlock security alert alerts required immediately hurry limited expiring reward won winner lottery bonus invoice pending failed unusual suspicious detected verification confirmation identity support regards request requested deposit withdraw withdrawal wire bitcoin crypto investment invest profit discount voucher coupon courier tracking shipment ordered subscription renewal renew terminated deactivated deactivate disabled restricted exceeded storage mailbox upgrade changed attachment attached tap respond following instructions documents file files tomorrow monday friday saturday january february april august september october november december sad angry excited tired okay pls plz thx ty btw tmrw msg txt ur omg lol brb idk hmm sorry regarding received sending sending account accounts blocked block bank banking dear customer congratulations selected claim kindly verify card cvv otp pin upi kyc pan aadhaar aadhar'));
}

// Words every real sentence contains (pronouns, helper verbs, prepositions ...). A line made only of
// content words ("urgent need money") is a fragment, not a sentence.
function functionWordSet(): array
{
    static $set = null;
    if ($set === null) {
        $set = array_flip(preg_split('/\s+/', trim('a an the i you he she it we they me him her us them my your his its our their this that these those is are am was were be been being do does did have has had will would can could should shall may might must to of in on at for with from by about as into and or but if so not no ur u')));
    }
    return $set;
}

// A word from the common list, also with a plain ending (-s, -ed, -ing, -ly ...).
function isKnownWord(string $token, array $set): bool
{
    if (isset($set[$token])) {
        return true;
    }
    $len = strlen($token);
    foreach (['ies' => 'y', 'es' => '', 'ed' => '', 'd' => '', 'ing' => '', 'ly' => '', 'ers' => '', 'er' => '', 's' => ''] as $suffix => $replacement) {
        $cut = strlen($suffix);
        if ($len > $cut + 2 && substr($token, -$cut) === $suffix) {
            $stem = substr($token, 0, $len - $cut);
            if (isset($set[$stem . $replacement]) || isset($set[$stem]) || isset($set[$stem . 'e'])) {
                return true;
            }
        }
    }
    return false;
}

// "veryy", "happyyy", "goood": a real word with stretched letters. Not a word you would find in a proper message.
function isStretchedWord(string $token, array $set): bool
{
    if (isset($set[$token]) || !preg_match('/(.)\1/u', $token)) {
        return false;
    }
    preg_match_all('/(.)\1*/u', $token, $runs);
    $repeatedRuns = 0;
    foreach ($runs[0] as $run) {
        if (mb_strlen($run) >= 2) {
            $repeatedRuns++;
        }
    }
    if ($repeatedRuns > 6) {
        return true;
    }
    $variants = [''];
    foreach ($runs[0] as $run) {
        $char = mb_substr($run, 0, 1);
        $options = mb_strlen($run) >= 2 ? [$char, $char . $char] : [$char];
        $next = [];
        foreach ($variants as $prefix) {
            foreach ($options as $option) {
                $next[] = $prefix . $option;
            }
        }
        $variants = $next;
    }
    foreach ($variants as $variant) {
        if ($variant !== $token && isKnownWord($variant, $set)) {
            return true;
        }
    }
    return false;
}

// Returns an error message when the Email / SMS input is not a real email or message, otherwise null.
// Email tab  : a full email (greeting / body / sign-off, links allowed inside it). A bare link, bare address or short line is refused.
// Message tab: a complete text message of at least 5 words. Fragments, stretched or random words are refused.
function validateTextInput(string $content, string $channel): ?string
{
    $isEmail = $channel === 'email';
    $label = $isEmail ? 'email' : 'text message';
    $content = trim($content);

    if (looksLikeCodeOrMarkup($content)) {
        return 'This looks like HTML or program code, not a real ' . $label . '. Paste the actual ' . $label . ' text instead.';
    }

    // Each tab does its own job: a lone address or link belongs elsewhere.
    if (!preg_match('/\s/u', $content)) {
        if (preg_match('/^[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}$/i', $content)) {
            return 'That is only an email address, not a ' . $label . '. Paste the full ' . $label . ' (subject and body) to scan it.';
        }
        if (isValidUrlInput($content)) {
            return 'That is only a link, not a ' . $label . '. Paste the full ' . $label . ' here, or use the Website tab to check a link.';
        }
    }

    // Text without the links and addresses, so those cannot hide gibberish or pad a short line.
    $residue = preg_replace('~(?:https?://|www\.)\S+~i', ' ', $content);
    $residue = trim((string) preg_replace('/[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}/i', ' ', (string) $residue));

    preg_match_all('/\p{L}[\p{L}\'’]*/u', $residue, $found);
    $words = $found[0];
    $minWords = $isEmail ? 8 : 5;
    if (count($words) < $minWords) {
        return $isEmail
            ? 'This is too short to be a real email. Paste the full email (subject and body, at least a couple of complete sentences).'
            : 'This is not a complete text message. Enter a full sentence of at least ' . $minWords . ' words (links and addresses do not count).';
    }

    // Texts in other scripts (Hindi, Marathi, Arabic ...) cannot be checked against the English word list.
    if (preg_match('/[^\p{Latin}\P{L}]/u', $residue)) {
        return null;
    }

    $nonSpace = (string) preg_replace('/\s+/u', '', $residue);
    $letters = preg_match_all('/\p{L}/u', $nonSpace);
    if (strlen($nonSpace) >= 15 && $letters / max(1, strlen($nonSpace)) < 0.4) {
        return 'This text is mostly numbers or symbols, so it cannot be a real ' . $label . '. Paste normal readable text.';
    }

    $tokens = [];
    foreach ($words as $word) {
        $word = trim(mb_strtolower($word), "'’");
        if (mb_strlen($word) >= 1) {
            $tokens[] = $word;
        }
    }
    $total = count($tokens);

    $set = commonWordSet();
    $functionWords = functionWordSet();
    $known = 0;
    $junk = 0;
    $functionCount = 0;
    $badWord = '';
    foreach ($tokens as $token) {
        $isKnown = isKnownWord($token, $set);
        if ($isKnown) {
            $known++;
        }
        if (isset($functionWords[$token])) {
            $functionCount++;
        }
        if (!$isKnown && mb_strlen($token) >= 2 && (isJunkWord($token) || isStretchedWord($token, $set))) {
            $junk++;
            if ($badWord === '') {
                $badWord = mb_substr($token, 0, 20);
            }
        }
    }

    // Stretched letters ("veryy"), laughter or keyboard mashing.
    $junkAllowed = $isEmail ? max(1, (int) floor($total * 0.05)) : 0;
    if ($junk > $junkAllowed) {
        return 'This text contains words that are not real words (for example "' . $badWord . '"). Write the ' . $label . ' in normal, correctly spelled words.';
    }

    // A real message is mostly ordinary words, and uses several different ones.
    $minKnown = $isEmail ? 0.40 : 0.55;
    if ($known / $total < $minKnown) {
        return 'This text is not readable (it looks like random or meaningless words). Paste a real ' . $label . ' written in normal words.';
    }
    if (count(array_unique($tokens)) < 3 || count(array_unique($tokens)) / $total < 0.5) {
        return 'This text repeats the same words and is not a real ' . $label . '. Paste a real ' . $label . '.';
    }

    // Sentence check: fragments like "urgent need money now please" have no pronouns or helper words.
    $minFunction = $isEmail ? 3 : 1;
    if ($functionCount < $minFunction) {
        return $isEmail
            ? 'This does not read like a real email. Paste the full email as you received it.'
            : 'This is an incomplete sentence. Write a complete text message (for example "Your account is blocked, verify now").';
    }
    return null;
}

function analyzeContent(string $type, string $content, ?PDO $pdo = null, string $channel = 'text'): array
{
    // Wording used in explanations: "email", "message" or "text".
    $what = in_array($channel, ['email', 'message'], true) ? $channel : 'text';

    if (!in_array($type, ['url', 'text'], true)) {
        throw new InvalidArgumentException('Analysis type must be url or text.');
    }

    $content = trim($content);

    // Reject anything that is not a real URL before any scoring happens.
    if ($type === 'url' && !isValidUrlInput($content)) {
        throw new InvalidArgumentException('Please enter a valid URL to inspect (for example https://example.com or example.com). A single letter or word cannot be scanned.');
    }

    $indicators = [];
    $risk = 0;
    $urls = [];

    $addIndicator = static function (string $rule, int $weight, string $detail) use (&$risk, &$indicators): void {
        $risk += $weight;
        $indicators[] = ['rule' => $rule, 'weight' => $weight, 'detail' => $detail];
    };

    if ($type === 'url') {
        $urls[] = $content;
    } else {
        preg_match_all('~(?:https?://|www\.)[^\s<>"\']+~i', $content, $matches);
        $urls = array_values(array_unique(array_map(
            static function ($url) {
                return rtrim($url, '.,;:!?)\]}');
            },
            $matches[0] ?? []
        )));
    }

    if ($type === 'url') {
        $candidate = preg_match('~^[a-z][a-z0-9+.-]*://~i', $content) ? $content : 'http://' . $content;
        $localHost = strtolower((string) (parse_url($candidate, PHP_URL_HOST) ?: ''));
        if (in_array($localHost, ['localhost', '127.0.0.1', '::1'], true)) {
            return [
                'label' => 'safe',
                'phishing_probability' => 0.01,
                'confidence' => 0.96,
                'score' => 1,
                'percentage' => 1,
                'indicators' => [['rule' => 'trusted_local_host', 'weight' => 0, 'detail' => 'Trusted local development host.']],
                'urls' => $urls,
            ];
        }
    }

    $checkedHosts = [];
    foreach ($urls as $url) {
        $normalizedUrl = preg_match('~^[a-z][a-z0-9+.-]*://~i', $url) ? $url : 'http://' . $url;
        $host = rtrim(strtolower((string) (parse_url($normalizedUrl, PHP_URL_HOST) ?: '')), '.');
        $checkedHosts[] = $host;
        $path = strtolower((string) (parse_url($normalizedUrl, PHP_URL_PATH) ?: ''));
        $trusted = isTrustedDomain($host);

        // Only mention a URL's presence for pasted text; the user already knows they are scanning a URL.
        if ($type === 'text' && !$trusted) {
            $addIndicator('url_present', 0, 'The ' . $what . ' contains a link to "' . $host . '". Check it is the real site before opening it.');
        }

        if ($trusted) {
            $addIndicator('trusted_domain', 0, $type === 'text'
                ? 'The link to "' . $host . '" in this ' . $what . ' belongs to a well-known trusted domain.'
                : $host . ' belongs to a well-known trusted domain.');
            // Trusted brands also host user-made pages that phishers abuse (fake Google Docs / Drive / Sites).
            foreach (['sites.google.com', 'docs.google.com', 'drive.google.com', 'dropbox.com'] as $sharedHost) {
                if ($host === $sharedHost || substr($host, -(strlen($sharedHost) + 1)) === '.' . $sharedHost) {
                    $addIndicator('user_content_host', 8, $host . ' hosts content made by anyone; the page itself may not be official.');
                    break;
                }
            }
        } else {
            if (preg_match('/^\d{1,3}(?:\.\d{1,3}){3}$/', $host)) {
                $addIndicator('raw_ip_host', 25, 'The link uses a numeric IP address instead of a recognizable domain.');
            }
            if (strpos($url, '@') !== false) {
                $addIndicator('at_symbol_url', 22, 'An @ symbol in a URL can obscure the actual destination.');
            }
            if (strpos($host, 'xn--') !== false) {
                $addIndicator('punycode_host', 28, 'The host uses punycode, which can disguise look-alike characters.');
            }
            if (preg_match('/^(?:www\.)?(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|cutt\.ly|rb\.gy|is\.gd)$/i', $host)) {
                $addIndicator('url_shortener', 18, 'A URL shortener hides the final destination.');
            }
            if (preg_match('/\.(?:top|xyz|click|work|support|gq|tk|ml|cf|zip)$/i', $host)) {
                $addIndicator('risky_tld', 14, 'The domain uses a top-level domain commonly associated with suspicious links.');
            }
            if (preg_match('/(?:login|verify|account|update|secure|signin|confirm|password|banking|wallet)/i', $path)) {
                $addIndicator('sensitive_path', 12, 'The URL path refers to account access or sensitive information.');
            }
            if (preg_match('/(?:form|apply|register|registration|survey|signup|kyc)/i', $path)) {
                $addIndicator('form_path', 3, 'The link opens a form on "' . $host . '" that may collect personal details.');
            }
            // Four or more dots (five labels) is unusual; three dots is normal for sites like colab.research.google.com.
            if (substr_count($host, '.') >= 4) {
                $addIndicator('many_subdomains', 7, 'The host has many subdomains, which can make the real domain harder to identify.');
            }
            if (substr_count($host, '-') >= 2) {
                $addIndicator('many_hyphens', 6, 'The host contains multiple hyphens.');
            }

            $spoof = detectBrandSpoof($host);
            if ($spoof !== null) {
                $addIndicator($spoof['rule'], $spoof['weight'], $spoof['detail']);
            } else {
                $brands = ['paypal', 'google', 'gmail', 'youtube', 'facebook', 'instagram', 'whatsapp', 'linkedin', 'amazon', 'apple', 'microsoft', 'outlook', 'netflix', 'chatgpt', 'openai', 'bank', 'sbi', 'hdfc', 'icici', 'axis', 'flipkart', 'phonepe', 'paytm'];
                foreach ($brands as $brand) {
                    if (strpos($host, $brand) !== false && !preg_match('/(?:^|\.)' . preg_quote($brand, '/') . '\.(?:com|in|net|org)$/i', $host)) {
                        $addIndicator('brand_impersonation', 26, 'The host contains "' . $brand . '" but is not its basic official domain.');
                        break;
                    }
                }
                if (preg_match('/paypa1|g00gle|faceb00k|amaz0n|app1e|micr0soft/i', $host)) {
                    $addIndicator('homoglyph_pattern', 30, 'The host contains characters commonly substituted to imitate a known brand.');
                }
            }
            if (preg_match('/[^\x00-\x7F]/', $host)) {
                $addIndicator('non_ascii_host', 28, 'The host contains non-English characters that can imitate familiar letters.');
            }

            // Graded reputation signals so different sites get different scores.
            $name = registrableName($host);
            $tld = strpos($host, '.') !== false ? substr(strrchr($host, '.'), 1) : '';
            $isIp = (bool) preg_match('/^\d{1,3}(?:\.\d{1,3}){3}$/', $host);
            $lowReputationTlds = ['online', 'site', 'shop', 'club', 'live', 'info', 'buzz', 'icu', 'vip', 'green', 'pw', 'cc', 'ws', 'cam', 'rest', 'bid', 'loan', 'men', 'stream', 'download', 'review', 'win', 'fit', 'monster', 'cyou', 'sbs'];
            if (in_array($tld, $lowReputationTlds, true)) {
                $addIndicator('low_reputation_tld', 8, 'The .' . $tld . ' extension is frequently used by low-reputation or short-lived sites.');
            }
            if (preg_match('/movierulz|tamilrockers|123movies|filmyzilla|vegamovies|hdhub4u|9xmovies|mkvcinemas|moviesda|torrent|crack(?:ed)?|keygen/i', $host)) {
                $addIndicator('piracy_site_pattern', 20, 'The domain name matches pirated-content sites, which often carry malicious ads and fake download buttons.');
            }
            $urlLength = strlen($normalizedUrl);
            if ($urlLength > 120) {
                $addIndicator('very_long_url', 9, 'The URL is unusually long (' . $urlLength . ' characters).');
            } elseif ($urlLength > 75) {
                $addIndicator('long_url', 5, 'The URL is longer than normal (' . $urlLength . ' characters).');
            }
            if (!$isIp && preg_match_all('/\d/', $name) >= 3) {
                $addIndicator('digits_in_domain', 6, 'The domain name contains several digits.');
            }
            if (!$isIp && strlen($name) >= 14) {
                $addIndicator('long_domain_name', 5, 'The domain name is unusually long.');
            }
            $query = (string) (parse_url($normalizedUrl, PHP_URL_QUERY) ?: '');
            if ($query !== '' && substr_count($query, '&') + 1 >= 4) {
                $addIndicator('many_parameters', 4, 'The URL carries many query parameters.');
            }
        }

        if (stripos($normalizedUrl, 'https://') !== 0) {
            $addIndicator('unencrypted_scheme', 6, 'The URL does not use HTTPS.');
        }

        if ($pdo !== null && $host !== '') {
            $blocklist = $pdo->prepare('SELECT reason FROM threat_blocklist WHERE domain = ? LIMIT 1');
            $blocklist->execute([$host]);
            $reason = $blocklist->fetchColumn();
            if ($reason !== false) {
                $addIndicator('community_blocklist', 35, 'This domain is on the community blocklist: ' . (string) $reason);
            }
        }
    }

    $allUrlsTrusted = $checkedHosts !== [] && count(array_filter($checkedHosts, 'isTrustedDomain')) === count($checkedHosts);

    if ($type === 'text') {
        if (preg_match('/\b(?:otp|one[- ]time password|verification code|pin|cvv|password|aadhaar|pan card)\b/i', $content)) {
            $addIndicator('credential_request', 30, 'The ' . $what . ' mentions a credential or sensitive identifier.');
        }
        if (preg_match('/\b(?:share|send|reply with|provide|enter|confirm|verify)\b.{0,40}\b(?:otp|one[- ]time password|verification code|pin|cvv|password|aadhaar|pan card|code)\b/i', $content)) {
            $addIndicator('credential_action', 28, 'The ' . $what . ' asks the recipient to provide a credential or code.');
        }
        if (preg_match('/\b(?:urgent|immediately|final warning|within\s+\d+\s+(?:hours?|minutes?)|expires?)\b/i', $content)) {
            $addIndicator('urgency', 16, 'Urgent wording or an expiry deadline pressures the recipient.');
        }
        if (preg_match('/\b(?:account|card|profile)\b.{0,30}\b(?:suspend(?:ed)?|block(?:ed)?|clos(?:e|ed)|freeze|frozen|disabl(?:e|ed))\b|\b(?:suspend(?:ed)?|block(?:ed)?|clos(?:e|ed)|freeze|frozen|disabl(?:e|ed))\b.{0,30}\b(?:account|card|profile)\b/i', $content)) {
            $addIndicator('account_threat', 18, 'The ' . $what . ' threatens to suspend, block, close, freeze, or disable an account, card, or profile.');
        }
        if (preg_match('/\b(?:click|tap|follow)\b.{0,40}\b(?:link|here|below)\b/i', $content)) {
            $addIndicator('link_instruction', 15, 'The recipient is instructed to follow a link.');
        }
        if (preg_match('/\b(?:payment|pay|fee|refund|delivery|parcel|prize|rewards?|claim|winner|lottery|recharge|cashback)\b|(?:\x{20B9}|\bRs\.?)\s?\d+/iu', $content)) {
            $addIndicator('money_or_prize_lure', $allUrlsTrusted ? 4 : 10, $allUrlsTrusted
                ? 'The ' . $what . ' mentions money or rewards, but every link in it goes to a trusted domain.'
                : 'The ' . $what . ' mentions a payment, recharge, reward, prize or claim.');
        }
        if (preg_match('/\b(?:last date|deadline|apply (?:by|before))\b/i', $content)) {
            $addIndicator('deadline_pressure', 2, 'A deadline ("last date") is used, which can push you to act without checking.');
        }
        if (preg_match('/\b(?:kyc|aadhaar|pan card)\b/i', $content) && preg_match('/\b(?:update|click|verify)\b/i', $content)) {
            $addIndicator('regional_kyc_scam', 25, 'KYC or identity details are paired with an instruction to update, click, or verify.');
        }
        if (preg_match('/\b(?:dear customer|dear user|valued|sir\/madam|account holder)\b/i', $content)) {
            $addIndicator('generic_greeting', 8, 'The ' . $what . ' uses a generic greeting rather than identifying the recipient.');
        }
        if (preg_match('/\b(?:valued costumer|acount|recieve|verifcation|securty)\b/i', $content)) {
            $addIndicator('grammar_typos', 10, 'The ' . $what . ' contains common spelling errors.');
        }
        if (preg_match('/^\s*Reply-To:\s*.*?@([A-Z0-9.-]+\.[A-Z]{2,})/im', $content, $replyMatch)
            && preg_match('/^\s*From:\s*.*?@([A-Z0-9.-]+\.[A-Z]{2,})/im', $content, $fromMatch)
            && strcasecmp(rtrim($replyMatch[1], '.'), rtrim($fromMatch[1], '.')) !== 0) {
            $addIndicator('reply_to_mismatch', 22, 'The Reply-To domain differs from the From domain.');
        }
        // Sender / contact e-mail addresses: support@gooogle.com or 47eaed3c5857@maxxspace.com must be caught even without a link.
        preg_match_all('/([A-Z0-9._%+\-]+)@([A-Z0-9.\-]+\.[A-Z]{2,})/i', $content, $mailMatches, PREG_SET_ORDER);
        $seenAddresses = [];
        foreach ($mailMatches as $mailMatch) {
            $mailLocal = strtolower($mailMatch[1]);
            $mailDomain = rtrim(strtolower($mailMatch[2]), '.');
            $address = $mailLocal . '@' . $mailDomain;
            if (isset($seenAddresses[$address]) || count($seenAddresses) >= 5) {
                continue;
            }
            $seenAddresses[$address] = true;

            if (isDisposableDomain($mailDomain)) {
                $addIndicator('disposable_email', 40, 'The address "' . $address . '" belongs to a disposable (temporary) mail service, which is widely used for scams and cannot be traced to a real sender.');
            }
            if (!isTrustedDomain($mailDomain) && looksRandomLocalPart($mailLocal)) {
                $addIndicator('random_email_name', 10, 'The part before @ in "' . $address . '" looks randomly generated, not like a real person or company mailbox.');
            }
            if (in_array($mailDomain, $checkedHosts, true)) {
                continue;
            }
            $spoof = detectBrandSpoof($mailDomain);
            if ($spoof !== null) {
                $addIndicator('email_' . $spoof['rule'], $spoof['weight'], 'E-mail domain: ' . $spoof['detail']);
            }
        }
        if ($risk < 15 && preg_match('/\b(?:nptel|thanks and regards|dear learners|assignment submission)\b/i', $content)) {
            return [
                'label' => 'safe',
                'phishing_probability' => 0.03,
                'confidence' => 0.95,
                'score' => 3,
                'percentage' => 3,
                'indicators' => [['rule' => 'trusted_educational_phrase', 'weight' => 0, 'detail' => 'Recognized educational or announcement wording.']],
                'urls' => $urls,
            ];
        }
    }

    usort($indicators, static function ($left, $right) {
        return $right['weight'] <=> $left['weight'];
    });

    $probability = min(0.98, max(0.02, 0.02 + 0.96 * ($risk / ($risk + 15))));
    $percentage = (int) round($probability * 100);
    return [
        'label' => $probability >= 0.75 ? 'phishing' : ($probability >= 0.30 ? 'caution' : 'safe'),
        'phishing_probability' => $probability,
        'confidence' => min(0.96, 0.55 + abs($probability - 0.5) * 0.85),
        'score' => $percentage,
        'percentage' => $percentage,
        'indicators' => $indicators,
        'urls' => $urls,
    ];
}