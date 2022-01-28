<?php

namespace Shitein\Auth\Providers;

use Illuminate\Support\ServiceProvider;

class AuthServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $this->loadRoutesFrom(__DIR__ . '../src/routes/web.php');
        $this->loadViewsFrom(__DIR__ . '../src/resources/views', 'auth');
        $this->loadMigrationsFrom(__DIR__.'../src/database/migrations');

        /*$this->publishes([
            __DIR__.'/public' => public_path('vendor/auth'),
        ], 'public');*/
    }

    public function register() 
    {

    }
}
