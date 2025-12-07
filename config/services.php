<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Third Party Services
    |--------------------------------------------------------------------------
    |
    | This file is for storing the credentials for third party services such
    | as Mailgun, Postmark, AWS and more. This file provides the de facto
    | location for this type of information, allowing packages to have
    | a conventional file to locate the various service credentials.
    |
    */

    'postmark' => [
        'token' => env('POSTMARK_TOKEN'),
    ],

    'resend' => [
        'key' => env('RESEND_KEY'),
    ],

    'ses' => [
        'key' => env('AWS_ACCESS_KEY_ID'),
        'secret' => env('AWS_SECRET_ACCESS_KEY'),
        'region' => env('AWS_DEFAULT_REGION', 'us-east-1'),
    ],

    'slack' => [
        'notifications' => [
            'bot_user_oauth_token' => env('SLACK_BOT_USER_OAUTH_TOKEN'),
            'channel' => env('SLACK_BOT_USER_DEFAULT_CHANNEL'),
        ],
    ],

    'google' => [
        'client_id' => env('GOOGLE_CLIENT_ID'),
        'client_secret' => env('GOOGLE_CLIENT_SECRET'),
        'redirect' => env('APP_URL').'/api/v1/auth/google/callback',
    ],

    'twitter' => [
        'client_id' => env('TWITTER_CLIENT_ID'),
        'client_secret' => env('TWITTER_CLIENT_SECRET'),
        'redirect' => env('APP_URL').'/api/v1/auth/twitter/callback',
    ],

    'twitter' => [
        'client_id' => env('TWITTER_CLIENT_ID'),
        'client_secret' => env('TWITTER_CLIENT_SECRET'),
        'redirect' => env('APP_URL').'/api/v1/auth/twitter/callback',
    ],

    'facebook' => [
        'client_id' => env('FACEBOOK_CLIENT_ID'),
        'client_secret' => env('FACEBOOK_CLIENT_SECRET'),
        'redirect' => env('APP_URL').'/api/v1/auth/facebook/callback',
    ],

    'remote_server' => [
        'url_scanning_url' => env('URL_SCANNING_URL', 'http://5.182.33.91:3000/scan'),
        'file_scanning_url' => env('FILE_SCANNING_URL', 'http://5.182.33.91:5000/mb/upload'),
        'url_scanning_url_standard' => env('URL_SCANNING_URL_STANDARD', 'https://postlachrymal-tabatha-nondestructively.ngrok-free.dev/predict'),
        'file_scanning_url_standard' => env('FILE_SCANNING_URL_STANDARD', 'https://postlachrymal-tabatha-nondestructively.ngrok-free.dev/predict'),
        'email_scanning_url_standard' => env('EMAIL_SCANNING_URL_STANDARD', 'https://postlachrymal-tabatha-nondestructively.ngrok-free.dev/predict'),
    ],

];
