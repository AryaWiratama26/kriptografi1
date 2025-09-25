<?php
class EncryptionHelper {
    
    /**
     * @param string $data Data yang akan dienkripsi
     * @return string Base64 URL-safe encoded encrypted data dengan key dan IV
     */
    public static function encryptData($data) {
        
        $key = random_bytes(32);
        
        
        $iv = random_bytes(12);
        
        
        $encrypted = openssl_encrypt(
            $data, 
            'aes-256-gcm', 
            $key, 
            OPENSSL_RAW_DATA, 
            $iv, 
            $tag
        );
        
        if ($encrypted === false) {
            throw new Exception('Enkripsi gagal');
        }
        
        
        $result = $key . $iv . $tag . $encrypted;
        
        
        return self::base64UrlEncode($result);
    }
    
    /**
     * Mendekripsi data
     * @param string $encryptedData Base64 URL-safe encoded data
     * @return string Decrypted data
     */
    public static function decryptData($encryptedData) {
        
        $data = self::base64UrlDecode($encryptedData);
        
        if (strlen($data) < 32 + 12 + 16) { 
            throw new Exception('Data tidak valid - terlalu pendek');
        }
        
        
        $key = substr($data, 0, 32);        
        $iv = substr($data, 32, 12);         
        $tag = substr($data, 44, 16);      
        $encrypted = substr($data, 60);     
        
        // Dekripsi
        $decrypted = openssl_decrypt(
            $encrypted,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );
        
        if ($decrypted === false) {
            throw new Exception('Dekripsi gagal - data mungkin rusak atau tidak valid');
        }
        
        return $decrypted;
    }
    
    /**
     * Base64 URL-safe encoding
     */
    private static function base64UrlEncode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
    
    /**
     * Base64 URL-safe decoding
     */
    private static function base64UrlDecode($data) {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
    
    /**
     * Validasi apakah string adalah URL yang valid
     */
    public static function isValidUrl($url) {
        return filter_var($url, FILTER_VALIDATE_URL) !== false;
    }
    
    /**
     * Extract data parameter dari URL
     */
    public static function extractDataFromUrl($url) {
        $parsedUrl = parse_url($url);
        if (!isset($parsedUrl['query'])) {
            return null;
        }
        
        parse_str($parsedUrl['query'], $queryParams);
        return isset($queryParams['data']) ? $queryParams['data'] : null;
    }
}
?>