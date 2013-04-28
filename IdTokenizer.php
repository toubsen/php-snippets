<?php

/**
 * Generates a token from an Integer ID, which allows for verification, that
 * ID + token have been issued by ourselves and has not been altered.
 * 
 * For this use case, the ID is obfuscated and prepended with a cryptographic
 * HMAC. As a result, the tokenized ID can be used as an access token, e.g.
 * for giving out links to a user, that shall be granted access to a single
 * resource without any other auth checks, but make it (nearly) impossible
 * for anyone else to guess or construct another valid token.
 * 
 * The HMAC can be truncated to generate shorter tokenized IDs, e.g. to
 * allow for easier manual type in by a user (f.e. printed out codes). The
 * truncation will affect the security of this construct, as the probability
 * of collisions will improve, so depending on your use case you probably
 * want a number >= 64 bits up to even the complete hash size. Anything below
 * 32 bits will drastically increase the number of collisions and most
 * probably bring you into severe trouble.
 * 
 * Encryption is not implemented here, as the focus laid on the shortest
 * possible tamper proof and non-reconstructable representation, especially
 * for small IDs (which competes with the requirements for secure encryption,
 * like a fixed block size >= 128 bit, an IV and a HMAC).
 * 
 * READ CAREFULLY:
 * 
 * Tokenization will just protect you from people trying to probe for ids
 * to access resources that don't have any access control. It will not
 * help against leaked tokens / replay attacks.
 * 
 * The id will just be encoded to another format (base32), not encrypted,
 * so consider it still as "visible" to any user and thus also leaking
 * information (e.g. number of records, growth rates). If this is a problem,
 * You should be using encrypted ids.
 * 
 * Most importantly, always use different keys for each type of resource to
 * protect, else valid tokens from one resource can be reused on other
 * resources, if an item with the same id exists!
 * 
 * @author Tobias Vogel  <tobi089@web.de>
 */
class IdTokenizer {

    /**
     * @var string Hashing algoorithm to use
     */
    private $hashFn = 'sha256';

    /**
     * @var integer Length of truncated HMAC in bits 
     */
    private $hmacLen = 0;

    /**
     * @var integer Length of the HMAC in Hex encoding
     */
    private $hmacLenHex = 0;
    
    /**
     * @var integer Length of the HMAX in Base32 encoding
     */
    private $hmacLenBase32 = 0;
    
    /**
     * @var mixed The key to use for HMAC creation and verification
     */
    private $key = null;
    
    
    /**
     * Creates a new ID obfuscator.
     * 
     * @param string $password A password to generate a key from
     * @param string $salt The salt to use for key creation
     * @param integer $hmacLen Length of the HMAC, defaults to 64 bits
     */
    public function __construct($password, $salt, $hmacLen = 64) {
        $this->key = $this->genKey($password, $salt);
        $this->hmacLen = $hmacLen;
        $this->hmacLenHex = ceil($hmacLen / 4);
        $this->hmacLenBase32 = ceil($hmacLen / 5);
    }

    /**
     * Abbreviated PBKDF2 function to create a HMAC key (we only need a
     * single block here, and paremeters are fixed).
     * 
     * @link https://defuse.ca/php-pbkdf2.htm
     */
    private function genKey($password, $salt) {
        $algorithm = 'sha256';
        $count = 1000;

        $last = $salt . pack("N", 1);
        $last = $xorsum = hash_hmac($algorithm, $last, $password, true);
        for ($j = 1; $j < $count; $j++) {
            $xorsum ^= ($last = hash_hmac($algorithm, $last, $password, true));
        }

        return $xorsum;
    }

    /**
     * Base convert alternative for big integers, that works with
     * integers of any size and up to base 62.
     * 
     * Assembled from the information in the following thread:
     * @link http://stackoverflow.com/questions/1938029/php-how-to-base-convert-up-to-base-62
     * 
     * @param string $numstring number to convert
     * @param integer $frombase The base the number is encoded in
     * @param integer $tobase The base the number willbe converted to
     * @return string The converted number
     */
    public function bcBaseConvert($numstring, $frombase, $tobase) {
        $alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

        $chars = substr($alphabet, 0, $frombase);
        $tostring = substr($alphabet, 0, $tobase);

        $numstring = (string) $numstring;
        $length = strlen($numstring);
        $result = '';
        for ($i = 0; $i < $length; $i++) {
            $number[$i] = strpos($chars, $numstring{$i});
        }
        do {
            $divide = 0;
            $newlen = 0;
            for ($i = 0; $i < $length; $i++) {
                $divide = $divide * $frombase + $number[$i];
                if ($divide >= $tobase) {
                    $number[$newlen++] = (int) ($divide / $tobase);
                    $divide = $divide % $tobase;
                } elseif ($newlen > 0) {
                    $number[$newlen++] = 0;
                }
            }
            $length = $newlen;
            $result = $tostring{$divide} . $result;
        } while ($newlen != 0);
        return $result;
    }

    /**
     * Encodes / Obfuscates an ID in crockford base32 encoding and prepends it
     * with a message HMAC of the defined size.
     * 
     * @param integer $id The id to encode
     * @return string base36 encoded HMAC + id
     */
    public function encode($id) {
        $idEnc = $this->bcBaseConvert($id, 10, 32);
        $hmac = $this->getHmac($id);
        $hmacEnc = $this->bcBaseConvert($hmac, 16, 32);
        return str_pad($hmacEnc, $this->hmacLenBase32, '0', STR_PAD_LEFT) . $idEnc;
    }

    /**
     * Decodes / De-Obfuscates an ID in crockford base32 encoding and verifies the
     * integrity with the given HMAC.
     * 
     * @param string $code The code to encode
     * @return id The given id if valid, else 0
     */
    public function decode($code) {
        $idEnc = substr($code, $this->hmacLenBase32);
        $id = $this->bcBaseConvert($idEnc, 32, 10);

        $hmacEnc = substr($code, 0, $this->hmacLenBase32);
        $hmacTrunc = $this->bcBaseConvert($hmacEnc, 32, 16);
        $hmacUser = str_pad($hmacTrunc, $this->hmacLenHex, '0', STR_PAD_LEFT);
        $hmacData = $this->getHmac($id);

        // Compare MD5 hashes to prevent timing attacks
        if (md5($hmacData) !== md5($hmacUser)) {
//            if (PHP_SAPI === 'cli') {
//                echo "tampered data detected!\n";
//            }
            return 0;
        }

        return $id;
    }

    /**
     * Creates a HMAC for a message m with key k, truncated to the
     * number of bits defined in HMAC_LEN. The result is a string with
     * lowercase hexits.
     * 
     * @param string $message The message to create a HMAC for
     * @return string The (possibly truncated) message HMAC
     */
    private function getHmac($message) {
        $hmac = hash_hmac($this->hashFn, $message, $this->key);
        $hmac_short = substr($hmac, 0, $this->hmacLenHex);
        return $hmac_short;
    }

}
