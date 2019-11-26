<?php


    namespace blackpanda\encryptor;


    use Defuse\Crypto\Key;
    use Psecio\SecureDotenv\Crypto;
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
        private $secureFilePrefix;
        private $crypto;

        CONST OVERWRITE_ENV_VALUES = false;

        public function __construct()
        {
            $this->dbEncryptionPrefix = config('encryptor.db_encryption_prefix');
            $this->dbSecretKeyName = config('encryptor.db_secret_key_name');

            $this->keyFileName = config('encryptor.key_file_name');
            $this->keyFileName = $this->convertToMD5($this->keyFileName);

            $this->secureEnvName = config('encryptor.secure_env_name');
            $this->secureEnvName = $this->convertToMD5($this->secureEnvName);

            $this->secureFilePrefix = config('encryptor.secure_file_prefix');


            $this->keyPath = base_path($this->keyFileName);
            $this->secureENVPath = base_path($this->secureEnvName);
            $this->validateKeyFile();
            $this->validateSecureENV();
            $this->validateGitIgnore($this->keyFileName);
            $this->validateGitIgnore($this->secureEnvName);
            $this->secureENV = new Parser($this->keyPath , $this->secureENVPath);
            $this->setDatabaseSecret();

            $this->crypto = new Crypto($this->keyPath);
        }

        // GET ENV Values with KEY OR ALL OF The Content
        public function getENV(string $keyName = null){
            return $this->secureENV->getContent($keyName);
        }

        // SET or or OverWrite keys
        public function setENV(string $key,string $value)
        {
            // Save new Data
            if(!$this->secureENV->save($key,$value,self::OVERWRITE_ENV_VALUES)) throw new \Exception('add New LINE TO ENV has been Failed');
            return true;
        }

        // Check keys Entity
        public function keyExist($key)
        {
            return (!empty($this->secureENV->getContent($key)));
        }

        // Manual Encrypt Based on Psecio\SecureDotenv\Crypto
        public function encrypt($value)
        {
            return $this->crypto->encrypt($value);
        }

        // Manual Decrypt Based on Psecio\SecureDotenv\Crypto
        public function decrypt($value)
        {
            return $this->secureENV->decryptValues($value);
        }

        // return database Secret
        public function getDatabaseSecret()
        {
            return ($this->keyExist($this->dbSecretKeyName)) ? $this->getENV($this->dbSecretKeyName) : false;
        }

        // Generate and Store Key file
        private function validateKeyFile(){
            if($this->getSecureKey() && strlen($this->getSecureKey()) > 0) return true;
            $key = Key::createNewRandomKey();
            file_put_contents($this->keyPath,$key->saveToAsciiSafeString());
        }

        // get Security key for Encryption ENV values
        private function getSecureKey(){
            if(!file_exists($this->keyPath)) return false;

            return file_get_contents($this->keyPath);
        }

        // Add Sensitive and Secure Files to git ignore
        public function validateGitIgnore(string $file){
            $gitIgnore = file_get_contents(base_path('.gitignore'));
            $find = preg_quote($file);
            $preg = preg_match_all("/$find/i",$gitIgnore);
            if($preg == 0){
                file_put_contents(base_path('.gitignore'),"\n$file",FILE_APPEND);
            }
        }

        // create Secure ENV File if it's doesn't exist
        private function validateSecureENV(){
            if(file_exists($this->secureENVPath)) return true;
            $secureENV = fopen($this->secureENVPath,"w");
            fwrite($secureENV,"");
            fclose($secureENV);
        }

        // Set the Secret of db encryption
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
         * @return \Illuminate\Config\Repository|mixed
         */
        public function getSecureFilePrefix()
        {
            return $this->secureFilePrefix;
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
