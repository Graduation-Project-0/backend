<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\ForgotPasswordRequest;
use App\Http\Requests\Api\V1\LoginRequest;
use App\Http\Requests\Api\V1\LogoutRequest;
use App\Http\Requests\Api\V1\RegisterRequest;
use App\Http\Requests\Api\V1\ResetPasswordRequest;
use App\Models\User;
use App\Notifications\ResetPasswordNotification;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    /**
     * Register a new user.
     */
    public function register(RegisterRequest $request): JsonResponse
    {
        $user = User::create([
            'name' => $request->get('name'),
            'email' => $request->get('email'),
            'password' => Hash::make($request->get('password')),
        ]);

        $token = $user->createToken('auth-token')->plainTextToken;

        return response()->json([
            'message' => 'User registered successfully',
            'user' => $user,
            'token' => $token,
        ], 201);
    }

    /**
     * Login user and create token.
     */
    public function login(LoginRequest $request): JsonResponse
    {
        $user = User::where('email', $request->get('email'))->first();

        if (!$user || !Hash::check($request->get('password'), $user->password)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        $token = $user->createToken('auth-token')->plainTextToken;

        return response()->json([
            'message' => 'Login successful',
            'user' => $user,
            'token' => $token,
        ]);
    }

    /**
     * Logout user (Revoke the token).
     */
    public function logout(): JsonResponse
    {
        /** @var \App\Models\User|null $user */
        $user = auth('sanctum')->user();

        if ($user) {
            /** @var \Laravel\Sanctum\PersonalAccessToken|null $token */
            $token = $user->currentAccessToken();
            if ($token) {
                $token->delete();
            }
        }

        return response()->json([
            'message' => 'Logged out successfully',
        ]);
    }

    /**
     * Send password reset link.
     */
    public function forgotPassword(ForgotPasswordRequest $request): JsonResponse
    {
        $user = User::where('email', $request->get('email'))->first();

        $token = Str::random(64);

        DB::table('password_reset_tokens')
            ->where('email', $request->get('email'))
            ->delete();

        DB::table('password_reset_tokens')->insert([
            'email' => $request->get('email'),
            'token' => Hash::make($token),
            'created_at' => now(),
        ]);

        $user->notify(new ResetPasswordNotification($token));

        return response()->json([
            'message' => 'Password reset link has been sent to your email address.',
        ]);
    }

    /**
     * Reset user password.
     */
    public function resetPassword(ResetPasswordRequest $request): JsonResponse
    {
        $passwordReset = DB::table('password_reset_tokens')
            ->where('email', $request->get('email'))
            ->first();

        if (!$passwordReset) {
            throw ValidationException::withMessages([
                'token' => ['Invalid or expired password reset token.'],
            ]);
        }

        if (!Hash::check($request->get('token'), $passwordReset->token)) {
            throw ValidationException::withMessages([
                'token' => ['Invalid or expired password reset token.'],
            ]);
        }

        $expiresAt = now()->subMinutes(config('auth.passwords.users.expire', 60));
        if (strtotime($passwordReset->created_at) < $expiresAt->timestamp) {
            DB::table('password_reset_tokens')
                ->where('email', $request->get('email'))
                ->delete();

            throw ValidationException::withMessages([
                'token' => ['This password reset token has expired.'],
            ]);
        }

        User::where('email', $request->get('email'))
            ->update([
                'password' => Hash::make($request->get('password')),
            ]);

        DB::table('password_reset_tokens')
            ->where('email', $request->get('email'))
            ->delete();

        return response()->json([
            'message' => 'Password has been reset successfully.',
        ]);
    }
}
