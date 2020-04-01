<?php

    namespace blackpanda\encryptor;

    use Illuminate\Foundation\AliasLoader;
    use Illuminate\Support\ServiceProvider;

    class EncryptorServiceProvider extends ServiceProvider
    {

        public function register()
        {
            // Register Package
            $this->app->bind('Encryptor',function (){
                return new EncryptorServiceProvider();
            });

            // register Facade
            $loader = AliasLoader::getInstance();
            $loader->alias('Encryptor','blackpanda\encryptor\EncryptorFacade');
            $loader->alias('SSLEncryption','blackpanda\encryptor\SSLFacade');
        }

        public function boot()
        {
            // Publishes
            $this->publishes([
                __DIR__ . '/../publishes/config' => config_path(),
            ], 'configs');

            $this->publishes([
                __DIR__ . '/../publishes/EncryptorTraits' => app_path('/EncryptorTraits'),
            ], 'traits');
        }

    }
