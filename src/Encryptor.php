<?php


    namespace blackpanda\encryptor;


    use Defuse\Crypto\Key;
    use Psecio\SecureDotenv\Parser;

    class Encryptor
    {
        private $keyPath;
        private $secureENVPath;
        private $secureENV;


        private $dbEncryptionPrefix;
        private $dbSecretKeyName;
        private $keyFileName;
        private $secureEnvName;

        public function __construct()
        {
            $this->dbEncryptionPrefix = config('encryptor.db_encryption_prefix');
            $this->dbSecretKeyName = config('encryptor.db_secret_key_name');

            $this->keyFileName = config('encryptor.key_file_name');
            $this->keyFileName = $this->convertToMD5($this->keyFileName);

            $this->secureEnvName = config('encryptor.secure_env_name');
            $this->secureEnvName = $this->convertToMD5($this->secureEnvName);


            $this->keyPath = base_path($this->keyFileName);
            $this->secureENVPath = base_path($this->secureEnvName);
            $this->validateKeyFile();
            $this->validateSecureENV();
            $this->validateGitIgnore($this->keyFileName);
            $this->validateGitIgnore($this->secureEnvName);
            $this->secureENV = new Parser($this->keyPath , $this->secureENVPath);
            $this->setDatabaseSecret();
        }

        public function getENV(string $keyName = null){
            return $this->secureENV->getContent($keyName);
        }

        public function setENV(string $key,string $value)
        {
            if(!$this->secureENV->save($key,$value,true)) throw new \Exception('add New LINE TO ENV has been Failed');
            return true;
        }

        public function keyExist($key)
        {
            return (!empty($this->secureENV->getContent($key)));
        }

        public function getDatabaseSecret()
        {
            return ($this->keyExist($this->dbSecretKeyName)) ? $this->getENV($this->dbSecretKeyName) : false;
        }

        private function validateKeyFile(){
            if($this->getSecureKey() && strlen($this->getSecureKey()) > 0) return true;
            $key = Key::createNewRandomKey();
            file_put_contents($this->keyPath,$key->saveToAsciiSafeString());
        }

        private function getSecureKey(){
            if(!file_exists($this->keyPath)) return false;

            return file_get_contents($this->keyPath);
        }

        private function validateGitIgnore(string $file){
            $gitIgnore = file_get_contents(base_path('.gitignore'));
            $find = preg_quote($file);
            $preg = preg_match_all("/$find/i",$gitIgnore);
            if($preg == 0){
                file_put_contents(base_path('.gitignore'),"\n$file",FILE_APPEND);
            }
        }

        private function validateSecureENV(){
            if(file_exists($this->secureENVPath)) return true;
            $secureENV = fopen($this->secureENVPath,"w");
            fwrite($secureENV,"");
            fclose($secureENV);
        }

        private function setDatabaseSecret(){
            if($this->keyExist($this->dbSecretKeyName)) return false;
            $strong = false;
            while (!$strong)
            {
                $secret = openssl_random_pseudo_bytes(32, $strong);
            }
            $this->setENV($this->dbSecretKeyName,$secret);
        }

        /**
         * @return string
         */
        public function getDbEncryptionPrefix(): string
        {
            return $this->dbEncryptionPrefix;
        }

        private function convertToMD5(string $string)
        {
            return md5($string);
        }



    }
