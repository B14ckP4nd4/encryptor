<?php

    namespace blackpanda\encryptor;

    use phpseclib\Crypt\Random;

    class SSLEncryption
    {
        private $digest_alg;
        private $private_key_bits;
        private $private_key_type;

        /**
         * SSLEncryption constructor.
         * @param $digest_alg
         * @param $private_key_bits
         * @param $private_key_type
         */
        public function __construct(string $digest_alg = "sha512",int $private_key_bits = 4096,int $private_key_type = OPENSSL_KEYTYPE_RSA)
        {
            $this->digest_alg = $digest_alg;
            $this->private_key_bits = $private_key_bits;
            $this->private_key_type = $private_key_type;
        }


        // Generate new Public and Private Key
        public function generateNewKeyPair()
        {
            $config = array(
                "digest_alg" => $this->digest_alg,
                "private_key_bits" => $this->private_key_bits,
                "private_key_type" => $this->private_key_type,
            );

            // Create the private and public key
            $res = openssl_pkey_new($config);

            if(!$res){
                throw new \Exception("Generate Pair Key Failed!");
            }

            // Extract the private key from $res to $privKey
            openssl_pkey_export($res, $privKey);

            // Extract the public key from $res to $pubKey
            $pubKey = openssl_pkey_get_details($res);

            return [
                'private' => $privKey,
                'public' => $pubKey["key"],
                'type' => $config,
            ];

        }

        // Save Private Key in a Secure File
        public function savePublicKey(string $publicKey)
        {
            $publicFileName = md5(EncryptorFacade::getSecureFilePrefix() .'public.key');
            $envContent = EncryptorFacade::getENV('public_key');
            if(is_string($envContent) && isJson($envContent) && isset(json_decode($envContent,true)['hash'])) throw new \Exception("Key Already set");

            $path = base_path($publicFileName);
            if(!file_exists($path))
            {
                $publicKeyArg = [];
                $publicKeyArg['path'] = $path;
                $publicKeyArg['hash'] = sha1($publicKey);

                file_put_contents($path,$publicKey);
                EncryptorFacade::validateGitIgnore($publicFileName);
                EncryptorFacade::setENV('public_key',json_encode($publicKeyArg));
                return true;
            }

            throw new \Exception("Key File Already exist");
        }

        // Save Private Key HASH in Secure ENV file
        public function savePrivateHash(string $privateKey)
        {
            $privateKey = $this->parseKey($privateKey);
            $hash = password_hash($privateKey,PASSWORD_DEFAULT);
            return EncryptorFacade::setENV('private_hash',$hash);
        }

        // return Public Key
        public function getPublicKey()
        {
            $publicKeyFile = EncryptorFacade::getENV('public_key');
            if(!is_string($publicKeyFile) && !isJson($publicKeyFile) && !isset(json_decode($publicKeyFile,true)['hash'])) throw new \Exception("public Key doesn't set!");

            $publicKeyFile = json_decode($publicKeyFile,true);
            if(file_exists($publicKeyFile['path']))
            {
                $content = file_get_contents($publicKeyFile['path']);
                if(sha1($content) == $publicKeyFile['hash']) return $content;
                throw new \Exception("public key has been tampered!");
            }
            return false;
        }

        // Encrypt Data with openssl_public_encrypt
        public function publicEncrypt(string $data)
        {
            try {
                $publicKey = $this->getPublicKey();
            } catch (\Exception $e) {
                throw new \Exception("Wrong Public key! \n {$e->getMessage()}");
            }

            $publicKey = $this->parseKey($this->getPublicKey());
            // Encrypt the data using the public key
            openssl_public_encrypt($data, $encryptedData, $publicKey);

            // Return encrypted data
            return $encryptedData;
        }


        // Decrypt Data with openssl_private_decrypt
        public function privateDecrypt(string $encrypted ,string $privateKey)
        {
            if(!$this->validatePrivateKey($privateKey)) throw new \Exception("Private Key Verification Failed!");

            $privateKey = $this->parseKey($privateKey);
            // Decrypt the data using the private key
            openssl_private_decrypt($encrypted, $decryptedData, $privateKey);

            // Return decrypted data
            return $decryptedData;
        }


        // validate Private key based on PrivateKey hash on Secure ENV File
        public function validatePrivateKey(string $privateKey)
        {
            $privateKeyHash = EncryptorFacade::getENV('private_hash');
            $privateKey = $this->parseKey($privateKey);
            if(!password_verify($privateKey,$privateKeyHash)) return false;

            return true;
        }

        // Getters And Setters


        /**
         * @return string
         */
        public function getDigestAlg(): string
        {
            return $this->digest_alg;
        }

        /**
         * @param string $digest_alg
         */
        public function setDigestAlg(string $digest_alg): void
        {
            $this->digest_alg = $digest_alg;
        }

        /**
         * @return int
         */
        public function getPrivateKeyBits(): int
        {
            return $this->private_key_bits;
        }

        /**
         * @param int $private_key_bits
         */
        public function setPrivateKeyBits(int $private_key_bits): void
        {
            $this->private_key_bits = $private_key_bits;
        }

        /**
         * @return int
         */
        public function getPrivateKeyType(): int
        {
            return $this->private_key_type;
        }

        /**
         * @param int $private_key_type
         */
        public function setPrivateKeyType(int $private_key_type): void
        {
            $this->private_key_type = $private_key_type;
        }


        // Parse Private And Public Keys and return in Standard Format
        private function parseKey($key)
        {
            preg_match('/(?<prefix>-{5}BEGIN (?<type>(PRIVATE|PUBLIC)) KEY-{5})\s+?(?<key>.*)\s+?(?<suffix>-{5}END (PRIVATE|PUBLIC) KEY-{5})/ism',$key,$match);
            if(!empty($match) && isset($match['key']) && isset($match['type'])){
                $parse = "-----BEGIN {$match['type']} KEY-----\n";
                $parse .= wordwrap($match['key'], 64, "\n", true);
                $parse .= "\n-----END {$match['type']} KEY-----";
                return $parse;
            }

            return false;
        }




    }
