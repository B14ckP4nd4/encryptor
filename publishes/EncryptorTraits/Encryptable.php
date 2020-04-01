<?php


    namespace App\EncryptorTraits;

    use blackpanda\encryptor\Encryptor;
    use Illuminate\Contracts\Encryption\DecryptException;
    use Illuminate\Contracts\Encryption\EncryptException;
    use Illuminate\Encryption\Encrypter;

    trait Encryptable
    {
        /**
         * Decrypt the column value if it is in the encrypted array.
         *
         * @param $key
         *
         * @return mixed
         */
        public function getAttribute($key)
        {
            $value = parent::getAttribute($key);
            if($this->shouldEncrypt($key) && $this->isEncrypted($value))
            {
                $value = $this->decryptAttribute($value);
            }
            return $value;
        }


        /**
         * Set the value, encrypting it if it is in the encrypted array.
         *
         * @param $key
         * @param $value
         *
         * @return
         */
        public function setAttribute($key, $value)
        {
            if ($value !== null && $this->shouldEncrypt($key) && !$this->isEncrypted($value)) {
                $value = $this->encryptAttribute($value);
            }
            return parent::setAttribute($key, $value);
        }

        /**
         * Retrieves all values and decrypts them if needed.
         *
         * @return mixed
         */
        public function attributesToArray()
        {
            $attributes = parent::attributesToArray();
            foreach ($this->getEncryptableList() as $key) {
                if (isset($attributes[$key])) {
                    $attributes[$key] = $this->decryptAttribute($attributes[$key]);
                }
            }
            return $attributes;
        }


        protected function castAttribute($key, $value)
        {
            return parent::castAttribute($key, $this->doDecryptAttribute($key, $value));
        }


        // Encryption Methods


        public function doEncryptAttributes($key)
        {
            if($this->shouldEncrypt($key) && !$this->isEncrypted($this->attributes[$key])){
                $this->attributes[$key] = $this->encryptAttribute($this->attributes[$key]);
            }

            return $this;
        }

        public function encryptAttribute($value)
        {

            try {
                $encrypted = $this->getEncrypter()->encrypt($value);
            } catch (EncryptException $e) {
                throw $e;
            }

            return $this->getEncryptionPrefix() . $encrypted;
        }

        public function decryptAttribute($value)
        {
            if( !$this->isEncrypted($value) ) return $value;

            try{
                $decrypted = $this->getEncrypter()->decrypt(str_replace($this->getEncryptionPrefix(), '', $value));
            }
            catch (DecryptException $e)
            {
                throw $e;
            }

            return $decrypted;
        }

        public function doDecryptAttribute($key , $val)
        {
            if($this->shouldEncrypt($key) && $this->isEncrypted($val))
            {
                return $this->decryptAttribute($val);
            }

            return $val;
        }

        public function doDecryptAttributes($attributes)
        {
            foreach ($attributes as $key => $val)
            {
                $attributes[$key] = $this->doDecryptAttribute($key,$val);
            }

            return $attributes;
        }

        // Encryption Properties

        protected function getEncryptionPrefix()
        {
            return config('encryptor.db_encryption_prefix');
        }

        protected function getEncryptableList() : array
        {
            return (isset($this->encryptable)) ? $this->encryptable : [];
        }

        protected function shouldEncrypt($key) : bool
        {
            $encryptableList = $this->getEncryptableList();

            return (in_array($key, $encryptableList));
        }

        protected function isEncrypted($value)
        {
            return strpos((string)$value, $this->getEncryptionPrefix()) === 0;
        }

        protected function getEncrypter()
        {
            return new Encrypter($this->getEncryptionSecret(),'AES-256-CBC');
        }

        protected function getEncryptionSecret()
        {
            $encryptor = new Encryptor();
            return $encryptor->getDatabaseSecret();
        }
    }
