<?php

namespace App\Services;

use App\Models\User;
use App\Notifications\ResetPasswordNotification;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

class PasswordResetService
{
    /**
     * Send password reset token.
     */
    public function sendResetToken(string $email): void
    {
        $user = User::where('email', $email)->firstOrFail();

        $token = Str::random(64);

        // Delete old tokens for this email
        DB::table('password_reset_tokens')
            ->where('email', $email)
            ->delete();

        // Insert new token
        DB::table('password_reset_tokens')->insert([
            'email' => $email,
            'token' => Hash::make($token),
            'created_at' => now(),
        ]);

        $user->notify(new ResetPasswordNotification($token));
    }

    /**
     * Reset user password with token.
     */
    public function resetPassword(string $email, string $token, string $newPassword): void
    {
        $passwordReset = DB::table('password_reset_tokens')
            ->where('email', $email)
            ->first();

        if (!$passwordReset) {
            throw ValidationException::withMessages([
                'token' => ['Invalid or expired password reset token.'],
            ]);
        }

        if (!Hash::check($token, $passwordReset->token)) {
            throw ValidationException::withMessages([
                'token' => ['Invalid or expired password reset token.'],
            ]);
        }

        // Check if token is expired
        $expiresAt = now()->subMinutes(config('auth.passwords.users.expire', 60));
        if (strtotime($passwordReset->created_at) < $expiresAt->timestamp) {
            DB::table('password_reset_tokens')
                ->where('email', $email)
                ->delete();

            throw ValidationException::withMessages([
                'token' => ['This password reset token has expired.'],
            ]);
        }

        // Update user password
        $user = User::where('email', $email)->firstOrFail();
        $user->password = Hash::make($newPassword);
        $user->save();

        // Revoke all existing tokens for security
        $user->tokens()->delete();

        // Delete used token
        DB::table('password_reset_tokens')
            ->where('email', $email)
            ->delete();
    }
}

