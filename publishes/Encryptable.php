<?php


    namespace App\EncryptorTraits;


    use blackpanda\encryptor\Encryptor;
    use Illuminate\Contracts\Encryption\DecryptException;
    use Illuminate\Contracts\Encryption\EncryptException;
    use Illuminate\Encryption\Encrypter;

    trait Encryptable
    {

        public function setAttribute($key,$val)
        {
            parent::setAttribute($key,$val);

            $this->doEncryptAttributes($key);
        }

        public function getAttributeFromArray($key)
        {
            return $this->doDecryptAttribute($key,parent::getAttributeFromArray($key));
        }

        public function getArrayableAttributes()
        {
            return $this->doDecryptAttributes(parent::getArrayableAttributes());
        }

        public function getAttributes()
        {
            return $this->doDecryptAttributes(parent::getAttributes());
        }


        protected function castAttribute($key, $value)
        {
            return parent::castAttribute($key, $this->doDecryptAttribute($key, $value));
        }

        public function getDirty()
        {
            $dirty = [];
            foreach ($this->attributes as $key => $value) {
                if (! $this->originalIsEquivalent($key, $value)) {
                    $dirty[$key] = $value;
                }
            }
            return $dirty;
        }





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





        protected function getEncryptionPrefix()
        {
            return config('encryptor.db_encryption_prefix');
        }

        protected function getEncryptableList()
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
