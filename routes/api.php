<?php

use App\Http\Controllers\Api\V1\AuthController;
use Illuminate\Support\Facades\Route;

Route::group([
    'prefix' => 'v1',
    'middleware' => 'api',
], function () {
    // auth
    Route::post('/register', [AuthController::class, 'register']);
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/logout', [AuthController::class, 'logout'])->middleware('auth:sanctum');
    
    // password reset
    Route::post('/forgot-password', [AuthController::class, 'forgotPassword']);
    Route::post('/reset-password', [AuthController::class, 'resetPassword']);

    // social media login
    Route::get('/auth/{provider}/redirect', [AuthController::class, 'redirect'])
        ->where('provider', 'google|facebook|twitter|x');
    Route::get('/auth/{provider}/callback', [AuthController::class, 'callback'])
        ->where('provider', 'google|facebook|twitter|x');
});
