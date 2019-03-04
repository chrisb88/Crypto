<?php /** @noinspection PhpComposerExtensionStubsInspection */

namespace cmb\Crypto;

/**
 * Crypto class provides functionality to encrypt certain data in a special way to be used by other parties.
 */
class Crypto
{
    /**
     * The shared secret key.
     * You can produce a key with:
     * <code>
     * echo bin2hex(openssl_random_pseudo_bytes(32, $cryptoStrong));
     * </code>
     *
     * @var string 
     */
    const SECRET_KEY = '5cb0322fe658bf0e22c326019d132cc1af9857d3ce5980690a1c3c7f8beaa3e9';

    /**
     * The hash algorithm to use in hash_hmac().
     *
     * @var string
     */
    const HASH_ALGO  = 'sha256';

    /**
     * The length of the produced hash from self::HASH_ALGO.
     *
     * @var int
     */
    const HASH_LEN   = 32;

    /**
     * Defines the cipher to use, see openssl_get_cipher_methods() for a list of potential values.
     * 
     * @var string
     */
    const CIPHER     = 'AES-256-CBC';

    /** @var array */
    private $params;

    /**
     * Crypto constructor.
     *
     * @param array $params
     */
    public function __construct(array $params = [])
    {
        $this->params = $params;
    }

    /**
     * @return array
     */
    public function getParams()
    {
        return $this->params;
    }

    /**
     * @param array $params
     * @return Crypto
     */
    public function setParams($params)
    {
        $this->params = $params;
        return $this;
    }

    /**
     * @return string
     */
    public function toJson()
    {
        return json_encode($this->params);
    }

    /**
     * Runs the encryption and returns the encrypted string
     * @return string
     */
    public function encrypt()
    {
        $hashedKey = openssl_digest(self::SECRET_KEY, self::HASH_ALGO, true);

        $ivlen         = openssl_cipher_iv_length(self::CIPHER);
        $iv            = openssl_random_pseudo_bytes($ivlen, $cryptoStrong);
        $ciphertextRaw = openssl_encrypt($this->toJson(), self::CIPHER, $hashedKey, OPENSSL_RAW_DATA, $iv);
        $hmac          = hash_hmac(self::HASH_ALGO, $ciphertextRaw, $hashedKey, true);
        $ciphertext    = base64_encode($iv . $hmac . $ciphertextRaw);

        if ($cryptoStrong === false || $iv === false) {
            throw new \RuntimeException('Problem with Iv.');
        }

        return $ciphertext;
    }

    /**
     * Decrypts the given string
     * @param string $ciphertext
     * @return mixed|null Returns the decrypted data or null in case of an invalid signature
     */
    public static function decrypt($ciphertext)
    {
        $hashedKey         = openssl_digest(self::SECRET_KEY, self::HASH_ALGO, true);
        $c                 = base64_decode($ciphertext);
        $ivlen             = openssl_cipher_iv_length(self::CIPHER);
        $iv                = substr($c, 0, $ivlen);
        $hmac              = substr($c, $ivlen, self::HASH_LEN);
        $ciphertextRaw     = substr($c, $ivlen + self::HASH_LEN);
        $originalPlaintext = openssl_decrypt($ciphertextRaw, self::CIPHER, $hashedKey, OPENSSL_RAW_DATA, $iv);
        $calcmac           = hash_hmac(self::HASH_ALGO, $ciphertextRaw, $hashedKey, true);

        return $hmac === $calcmac ? json_decode($originalPlaintext, true) : null;
    }
}
