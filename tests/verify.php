<?php

/**
 * Here is a very quick way to generate a verify a known hash using this
 * library.
 */

require_once '../src/Miva_Password.php';
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title></title>
</head>
<body>

<?php
//In this example, we're going to use a known hash provided by Miva directly
//@see http://extranet.mivamerchant.com/forums/showthread.php?110099-Miva-Merchant-5-Production-Release-8-Update-7-Customer-Password-Encryption-Info
$password = 'pr8-update-7';
$good_hash = 'PBKDF1:sha1:1000:ozeRgGuxkRU=:S3lRcJ3sV0v7pZf/EDPROqJThKo=';
if (Miva_Password::verify($password, $good_hash) === true) {
    echo '<span style="color:#0F0;">Successfully verified!</span><br>' . "\n";
} else {
    echo '<strong style="color:#F00;">Failed!</strong><br>' . "\n";
}
unset($password, $salt, $good_hash);
?>

</body>
</html>