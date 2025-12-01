<?php

use App\Http\Controllers\Api\V1\AuthController;
use App\Http\Controllers\Api\V1\ScanFileController;
use App\Http\Controllers\Api\V1\ScanUrlController;
use Illuminate\Support\Facades\Route;

Route::group([
    'prefix' => 'v1',
    'middleware' => 'api',
], function () {
    // auth
    Route::post('/register', [AuthController::class, 'register']);
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/verify-otp', [AuthController::class, 'verifyOtp']);
    Route::post('/logout', [AuthController::class, 'logout'])->middleware('auth:sanctum');
    Route::get('/me', [AuthController::class, 'me'])->middleware('auth:sanctum');

    // password reset
    Route::post('/forgot-password', [AuthController::class, 'forgotPassword']);
    Route::post('/reset-password', [AuthController::class, 'resetPassword']);

    // email verification
    Route::get('/email/verify/{id}/{hash}', [AuthController::class, 'verifyEmail'])
        ->name('verification.verify');
    Route::post('/email/verification-notification', [AuthController::class, 'resendVerificationEmail']);

    // social media login
    Route::get('/auth/{provider}/redirect', [AuthController::class, 'redirect'])
        ->where('provider', 'google|facebook|twitter|x');
    Route::get('/auth/{provider}/callback', [AuthController::class, 'callback'])
        ->where('provider', 'google|facebook|twitter|x');

    Route::middleware(['auth:sanctum', 'verified'])->group(function () {
        Route::post('scan-url', [ScanUrlController::class, 'scan']);
        Route::post('scan-file', [ScanFileController::class, 'scan']);
    });
});
