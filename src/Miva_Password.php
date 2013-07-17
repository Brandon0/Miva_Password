<?php

/**
* Miva_Password
*
* Copyright (c) 2013, Brandon Kahre <brandonkahre@charter.net>.
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
*  - Redistributions of source code must retain the above copyright notice, this
*    list of conditions and the following disclaimer.
*  - Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
* USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
* @author Brandon Kahre <brandonkahre@charter.net>
* @copyright 2013 Brandon Kahre <brandonkahre@charter.net>
* @license http://opensource.org/licenses/BSD-2-Clause The BSD 2-Clause License
* @link http://www.github.com/Brandon0/Miva_Password
*/
class Miva_Password {
    /**
     * Miva's default length for a password salt
     * @var integer
     */
    static protected $salt_length = 8;

    /**
     * Create a unique salt string using the best source of random we can find
     *
     * @return string MIME base64
     */
    public static function create_salt() {
        $length = self::$salt_length;
        $salt = '';

        //mcrypt is our first choice
        if (function_exists('mcrypt_create_iv')) {
            $salt = mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
            if (strlen($salt) >= $length) {
                return substr($salt, 0, $length);
            }
        }

        //else let's try /dev/urandom (doesn't work with Windows)
        if (is_readable('/dev/urandom') && ($fh = fopen('/dev/urandom', 'rb'))) {
            $salt = fread($fh, $length);
            fclose($fh);
            if (strlen($salt) >= $length) {
                return substr($salt, 0, $length);
            }
        }

        //worst case scenario we'll use a binary md5 hash pasted together
        $salt = '';
        for ($i=0; $i<$length; $i+=16) { //16 is the length of a raw md5 hash
            $salt .= md5(microtime(), true);
        }
        return substr($salt, 0, $length);
    }

    /**
     * Create a Miva Merchant compatible password hash. Follows the following format:
     *     PBKDF:hash-algorithim:iterations:salt-base64:ciphertext-base64
     *
     * @see http://extranet.mivamerchant.com/forums/showthread.php?110099-Miva-Merchant-5-Production-Release-8-Update-7-Customer-Password-Encryption-Info
     *
     * @param  string $password            The plain-text password to hash
     * @param  string $salt                The plain-text salt to use in the hash
     * @param  string $pbkdf_version       The PBKDF version to use; PBKDF1 by default
     * @param  string $hash_algo           The hashing algorithim to use; sha1 by default
     * @param  integer $iterations         The number of times to run the hashing algorithim; 1000 by default
     * @param  integer $derived_key_length The maximum string length enforced on the derived key; 20 by default
     * @return string                      A secure password hash string
     */
    public static function create_hash($password, $salt='', $pbkdf_version='PBKDF1', $hash_algo='sha1', $iterations=1000, $derived_key_length=20) {
        if ($salt === '') {
            $salt = self::create_salt();
        }

        if (!in_array($pbkdf_version, array('PBKDF1', 'PBKDF2'))) {
            #throw new InvalidArgumentException($pbkdf_version . ' not supported');
            return false;
        }

        switch ($pbkdf_version) {
            case 'PBKDF1':
                $derived_key = self::pbkdf1($password, $salt, $hash_algo, $iterations, $derived_key_length);
                break;

            case 'PBKDF2':
                $derived_key = self::pbkdf2($password, $salt, $hash_algo, $iterations, $derived_key_length);
                break;

            //@Note: There are traces of a SHA1 hash function in the LSK (features/cus/cus_ut.mv), but it appears to be unused
        }

        if (!$derived_key) {
            return false;
        }

        return strtoupper($pbkdf_version) . ':' . strtolower($hash_algo) . ':' . $iterations . ':'  . base64_encode($salt) . ':'  . base64_encode($derived_key);
    }

    /**
     * Extract the algorithim details from the given hash such as:
     *     PBKDF version
     *     Hashing algorithim used
     *     Number of iterations used in hashing
     *     Salt
     *     Derived key
     *
     * @param string $hash      A PBKDF hash; separated by colons
     * @param string $option='' The key of the spcific detail you want returned
     * @return mixed            Returns an array unless an option param is passed.
     */
    public static function extract_algorithim_info($good_hash, $option='') {
        //make sure we have the proper formatted hash
        $good_hash_infoArray = explode(':', $good_hash);
        if (count($good_hash_infoArray) < 5) {
            return;
        }

        list($pbkdf_version, $hash_algorithim, $iterations, $salt, $derived_key) = $good_hash_infoArray;
        $salt = base64_decode($salt);
        $derived_key = base64_decode($derived_key);

        $algo_infoArray = array(
            'PBKDF_version'      => $pbkdf_version,
            'hash_algorithim'    => $hash_algorithim,
            'iterations'         => $iterations,
            'salt'               => $salt,
            'derived_key'        => $derived_key,
            'derived_key_length' => strlen($derived_key),
            );

        if ($option !== '') {
            if (isset($algo_infoArray[$option])) {
                return $algo_infoArray[$option];
            }
            return;
        }

        return $algo_infoArray;
    }

    /**
     * Generate a unique and secure password. This password will be returned as plain
     * text and is NOT TO BE STORED ANYWHERE!
     *
     * @param int $pw_min_len The minimum length required for the new password.
     *      Quick note: Specifiying a minimum does not guarantee that the
     *      password will be exactly that length, it could be longer based on
     *      the $pw_complex parameter.
     * @param int $pw_complex The password complexity level
     *      0 = No requirements
     *      1 = Requires a letter and either a digit or special character
     *      2 = Requires an upper case letter, a lower case letter, and either a
     *          digit or special character
     * @return string
     */
    public static function generate($pw_min_len=6, $pw_complex=0) {
        if ($pw_min_len < 6) $pw_min_len = 6;
        if ($pw_complex < 0) $pw_complex = 0;

        $uppers = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $lowers = 'abcdefghijklmnopqrstuvwxyz';
        $digits = '0123456789';
        $others = '!@$%&*=';
        $character_set = $uppers . $lowers . $digits . $others;

        $has_upper = $has_lower = $has_digit = $has_other = false;

        $password = '';
        for ($i=0;$i<$pw_min_len;$i++) {
            $char = $character_set[mt_rand(0, strlen($character_set)-1)];
            $password .= $char;

            if (strpos($uppers, $char) !== false) {
                $has_upper = true;
            } elseif (strpos($lowers, $char) !== false) {
                $has_lower = true;
            } elseif (strpos($digits, $char) !== false) {
                $has_digit = true;
            } elseif (strpos($others, $char) !== false) {
                $has_other = true;
            }
        }

        //check password requirements
        switch ($pw_complex) {
            case 0:
                //no requirements
              break;

            case 1:
                //require either an upper or lower and either a digit or other
                if ($has_upper === false || $has_lower === false) {
                    $password = self::insertrandom($password, $uppers . $lowers);
                }
                if ($has_digit === false || $has_other === false) {
                    $password = self::insertrandom($password, $digits . $others);
                }
                break;

            case 2:
                //require an upper, lower, and either a digit or other
                if ($has_upper === false) {
                    $password = self::insertrandom($password, $uppers);
                }
                if ($has_lower === false) {
                    $password = self::insertrandom($password, $lowers);
                }
                if ($has_digit === false || $has_other === false) {
                    $password = self::insertrandom($password, $digits . $others);
                }
                break;
        }

        return $password;
    }

    /**
     * Verify that a given password matches the given password hash
     *
     * @param  string $password  The plain-text password to check
     * @param  string $good_hash The hash string we are checking against
     * @return boolean           True if the two strings contain the same password
     */
    public static function verify($password, $good_hash) {
        //first get all of the settings and details used in the creation of the good hash
        $algorithim_infoArray = self::extract_algorithim_info($good_hash);
        if (empty($algorithim_infoArray)) {
            return false;
        }

        //generate a hash from the given password using the settings from good hash
        $unknown_hash = self::create_hash($password, $algorithim_infoArray['salt'], $algorithim_infoArray['PBKDF_version'], $algorithim_infoArray['hash_algorithim'], $algorithim_infoArray['iterations'], $algorithim_infoArray['derived_key_length']);

        return (bool)($unknown_hash === $good_hash);
    }

    /**
     * Insert a random character from the given character set in to the given password.
     *
     * @Note: This is a helper function for self::generate()
     *
     * @param  string $password
     * @param  string $character_set
     * @return string
     */
    protected static function insertrandom($password, $character_set) {
        $random_position = mt_rand(0, strlen($password)-1);
        $random_char = $character_set[mt_rand(0, strlen($character_set)-1)];

        return substr($password, 0, $random_position) . $random_char . substr($password, $random_position);
    }

    /**
     * Standard implementation of PBKDF1
     *
     * @param  string  $password           The plain-text password to hash
     * @param  string  $salt               The plain-text salt to use in the hash
     * @param  string  $hash_algo          MD2, MD5 or SHA1; SHA1 by default
     * @param  integer $iterations         The number of iterations to run the hashing algorithim; 1000 by default
     * @param  integer $derived_key_length The maximum length of the resulting key; 20 by default
     * @return string                      A PBKDF1 password hash string
     */
    protected static function pbkdf1($password, $salt, $hash_algo, $iterations, $derived_key_length) {
        $hash_algo = strtolower($hash_algo);
        $iterations = (int)$iterations;
        $derived_key_length = (int)$derived_key_length;

        //supported hash algorithims
        if (!in_array($hash_algo, array('md2', 'md5', 'sha1'))) {
            #throw new InvalidArgumentException($hash_algo . ' hash algorithim not supported');
            return false;
        }
        //iterations and derived key length must be positive
        if ($iterations <= 0) {
            #throw new InvalidArgumentException('Iterations must be a positive integer');
            return false;
        }
        if ($derived_key_length <= 0) {
            #throw new InvalidArgumentException('Derived key must be a positive integer');
            return false;
        }
        //derived key length is enforced for PBKDF1 based on hash algorithim
        if ($hash_algo === 'md5' && $derived_key_length > 16) {
            #throw new Exception('derived key too long');
            return false;
        }
        if ($hash_algo === 'sha1' && $derived_key_length > 20) {
            #throw new Exception('derived key too long');
            return false;
        }

        //hash password and salt
        $derived_key = $password . $salt;
        for ($i=0; $i<$iterations; $i++) {
            $derived_key = hash($hash_algo, $derived_key, true);
        }

        //truncate derived key based on given key length
        $derived_key = substr($derived_key, 0, $derived_key_length);

        return $derived_key;
    }

    /**
     * Standard implementation of PBKDF2
     *
     * @param  string  $password           The plain-text password to hash
     * @param  string  $salt               The plain-text salt to use in the hash
     * @param  string  $hash_algo          Hashing algorithim to use; SHA1 by default
     * @param  integer $iterations         The number of iterations to run the hashing algorithim; 1000 by default
     * @param  integer $derived_key_length The maximum length of the resulting key; 20 by default
     * @return string                      A PBKDF2 password hash string
     */
    protected static function pbkdf2($password, $salt, $hash_algo, $iterations, $derived_key_length) {
        $hash_algo = strtolower($hash_algo);
        $iterations = (int)$iterations;
        $derived_key_length = (int)$derived_key_length;

        //supported hash algorithims
        if(!in_array($hash_algo, hash_algos())) {
            #throw new InvalidArgumentException($hash_algo . ' hash algorithim not supported');
            return false;
        }
        //iterations and derived key length must be positive
        if ($iterations <= 0) {
            #throw new InvalidArgumentException('Iterations must be a positive integer');
            return false;
        }
        if ($derived_key_length <= 0) {
            #throw new InvalidArgumentException('Derived key must be a positive integer');
            return false;
        }

        //@Note: This is straight from https://defuse.ca/php-pbkdf2.htm
        //get the hash string length of the algorithim being used
        $hash_length = strlen(hash($hash_algo, '', true));
        $block_count = ceil($derived_key_length / $hash_length);
        $derived_key = '';
        for($i=1; $i<=$block_count; $i++) {
            //$i encoded as 4 bytes, big endian.
            $last = $salt . pack('N', $i);
            //first iteration
            $last = $xorsum = hash_hmac($hash_algo, $last, $password, true);
            //perform the other $iterations - 1 iterations
            for ($j=1; $j<$iterations; $j++) {
                $xorsum ^= ($last = hash_hmac($hash_algo, $last, $password, true));
            }
            $derived_key .= $xorsum;
        }

        //truncate derived key based on given key length
        $derived_key = substr($derived_key, 0, $derived_key_length);

        return $derived_key;
    }
}