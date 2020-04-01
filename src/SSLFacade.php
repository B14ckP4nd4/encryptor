<?php

    namespace blackpanda\encryptor;


    use Illuminate\Support\Facades\Facade;

    class SSLFacade extends Facade
    {
        protected static function getFacadeAccessor()
        {
            return SSLEncryption::class;
        }
    }
