<?php

namespace App\Services;

use App\Models\User;
use App\Notifications\VerifyEmailNotification;
use Illuminate\Support\Facades\URL;
use Illuminate\Validation\ValidationException;

class EmailVerificationService
{
    /**
     * Send email verification notification.
     */
    public function sendVerificationEmail(User $user): void
    {
        if ($user->hasVerifiedEmail()) {
            return;
        }

        $user->notify(new VerifyEmailNotification);
    }

    /**
     * Verify user email with signed URL.
     */
    public function verifyEmail(string $id, string $hash): void
    {
        $user = User::findOrFail($id);

        if ($user->hasVerifiedEmail()) {
            throw ValidationException::withMessages([
                'email' => ['Email has already been verified.'],
            ]);
        }

        // Verify the hash matches
        if (! hash_equals((string) $hash, sha1($user->getEmailForVerification()))) {
            throw ValidationException::withMessages([
                'email' => ['Invalid verification link.'],
            ]);
        }

        $user->markEmailAsVerified();
    }

    /**
     * Resend verification email.
     */
    public function resendVerificationEmail(string $email): void
    {
        $user = User::where('email', $email)->firstOrFail();

        if ($user->hasVerifiedEmail()) {
            throw ValidationException::withMessages([
                'email' => ['Email has already been verified.'],
            ]);
        }

        $this->sendVerificationEmail($user);
    }
}
