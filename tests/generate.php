<?php

/**
 * Here is a very quick way to generate a random password (or 12) using this
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
//generate 12 quick, random passwords
for ($i=0; $i<12; $i++) {
    $password = Miva_Password::generate(10); //specify the length of the password

    echo $password . '<br>' . "\n";
    echo Miva_Password::create_hash($password) . '<br>' . "\n";
    echo '<br>' . "\n";
    unset($password);
}
?>

</body>
</html>