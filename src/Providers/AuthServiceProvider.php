<?php

namespace Shitein\Auth\Providers;

use Illuminate\Support\ServiceProvider;

class AuthServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $this->loadRoutesFrom(__DIR__ . '/../routes/web.php');
        $this->loadViewsFrom(__DIR__ . '/../resources/views', 'auth');
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

        $this->publishes([
            __DIR__.'/public' => public_path('vendor/auth'),
        ], 'public');
        
        $this->publishes([
            __DIR__.'/resources' => public_path('vendor/shite-auth/views'),
        ], 'views');
    }

    public function register() 
    {

    }
}
