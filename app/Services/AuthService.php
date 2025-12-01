<?php

namespace App\Services;

use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class AuthService
{
    private const TOKEN_NAME = 'auth-token';

    public function __construct(
        private EmailVerificationService $emailVerificationService,
        private OtpService $otpService
    ) {}

    /**
     * Register a new user.
     */
    public function register(array $data): array
    {
        $user = User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => Hash::make($data['password']),
        ]);

        // Send email verification notification
        $this->emailVerificationService->sendVerificationEmail($user);

        $token = $user->createToken(self::TOKEN_NAME)->plainTextToken;

        return [
            'user' => $user,
            'token' => $token,
        ];
    }

    /**
     * Authenticate user credentials and send OTP (2FA).
     */
    public function login(string $email, string $password): User
    {
        $user = User::where('email', $email)->first();

        if (! $user || ! Hash::check($password, $user->password)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        // Send OTP instead of generating token
        $this->otpService->generateAndSendOtp($user);

        return $user;
    }

    /**
     * Verify OTP and generate token.
     */
    public function verifyOtpAndLogin(string $email, string $code): array
    {
        $user = $this->otpService->verifyOtp($email, $code);

        $token = $user->createToken(self::TOKEN_NAME)->plainTextToken;

        return [
            'user' => $user,
            'token' => $token,
        ];
    }

    /**
     * Revoke the current access token.
     */
    public function logout(?User $user): bool
    {
        if (! $user) {
            return false;
        }

        $token = $user->currentAccessToken();
        if ($token) {
            $token->delete();

            return true;
        }

        return false;
    }
}
