<?php

namespace App\Services;

use App\Models\User;
use App\Notifications\OtpNotification;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class OtpService
{
    private const OTP_EXPIRY_MINUTES = 10;

    private const OTP_LENGTH = 6;

    /**
     * Generate and send OTP to user.
     */
    public function generateAndSendOtp(User $user): void
    {
        // Delete old unused OTPs for this email
        DB::table('otps')
            ->where('email', $user->email)
            ->where('used', false)
            ->where('expires_at', '>', now())
            ->delete();

        // Generate 6-digit OTP
        $code = str_pad((string) random_int(0, 999999), self::OTP_LENGTH, '0', STR_PAD_LEFT);

        // Store OTP (hashed for security)
        DB::table('otps')->insert([
            'email' => $user->email,
            'code' => Hash::make($code),
            'expires_at' => now()->addMinutes(self::OTP_EXPIRY_MINUTES),
            'used' => false,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        // Send OTP via email
        $user->notify(new OtpNotification($code));
    }

    /**
     * Verify OTP and return user if valid.
     */
    public function verifyOtp(string $email, string $code): User
    {
        $user = User::where('email', $email)->firstOrFail();

        // Get the most recent unused OTP for this email
        $otp = DB::table('otps')
            ->where('email', $email)
            ->where('used', false)
            ->where('expires_at', '>', now())
            ->orderBy('created_at', 'desc')
            ->first();

        if (! $otp) {
            throw ValidationException::withMessages([
                'code' => ['Invalid or expired OTP code.'],
            ]);
        }

        // Verify the code
        if (! Hash::check($code, $otp->code)) {
            throw ValidationException::withMessages([
                'code' => ['Invalid OTP code.'],
            ]);
        }

        // Mark OTP as used
        DB::table('otps')
            ->where('id', $otp->id)
            ->update(['used' => true]);

        // Clean up expired OTPs
        $this->cleanupExpiredOtps($email);

        return $user;
    }

    /**
     * Clean up expired OTPs for an email.
     */
    private function cleanupExpiredOtps(string $email): void
    {
        DB::table('otps')
            ->where('email', $email)
            ->where(function ($query) {
                $query->where('expires_at', '<=', now())
                    ->orWhere('used', true);
            })
            ->delete();
    }
}
