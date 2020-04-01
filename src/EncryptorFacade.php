<?php

    namespace blackpanda\encryptor;

    use Illuminate\Support\Facades\Facade;

    class EncryptorFacade extends Facade
    {
        protected static function getFacadeAccessor()
        {
            return Encryptor::class;
        }

    }
