<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\ForgotPasswordRequest;
use App\Http\Requests\Api\V1\LoginRequest;
use App\Http\Requests\Api\V1\RegisterRequest;
use App\Http\Requests\Api\V1\ResetPasswordRequest;
use App\Services\AuthService;
use App\Services\PasswordResetService;
use App\Services\SocialAuthService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Laravel\Socialite\Facades\Socialite;

class AuthController extends Controller
{
    public function __construct(
        private AuthService $authService,
        private PasswordResetService $passwordResetService,
        private SocialAuthService $socialAuthService
    ) {}

    /**
     * Register a new user.
     */
    public function register(RegisterRequest $request): JsonResponse
    {
        $validated = $request->validated();
        $result = $this->authService->register($validated);

        return response()->json([
            'message' => 'User registered successfully',
            'user' => $result['user'],
            'token' => $result['token'],
        ], 201);
    }

    /**
     * Login user and create token.
     */
    public function login(LoginRequest $request): JsonResponse
    {
        $validated = $request->validated();
        $result = $this->authService->login($validated['email'], $validated['password']);

        return response()->json([
            'message' => 'Login successful',
            'user' => $result['user'],
            'token' => $result['token'],
        ]);
    }

    /**
     * Logout user (Revoke the token).
     */
    public function logout(): JsonResponse
    {
        /** @var \App\Models\User|null $user */
        $user = auth('sanctum')->user();
        
        $this->authService->logout($user);

        return response()->json([
            'message' => 'Logged out successfully',
        ]);
    }

    /**
     * Send password reset link.
     */
    public function forgotPassword(ForgotPasswordRequest $request): JsonResponse
    {
        $validated = $request->validated();
        $this->passwordResetService->sendResetToken($validated['email']);

        return response()->json([
            'message' => 'Password reset link has been sent to your email address.',
        ]);
    }

    /**
     * Reset user password.
     */
    public function resetPassword(ResetPasswordRequest $request): JsonResponse
    {
        $validated = $request->validated();
        $this->passwordResetService->resetPassword(
            $validated['email'],
            $validated['token'],
            $validated['password']
        );

        return response()->json([
            'message' => 'Password has been reset successfully.',
        ]);
    }

    /**
     * Redirect to social provider for authentication.
     */
    public function redirect(string $provider): RedirectResponse
    {
        $driver = $this->socialAuthService->getDriver($provider);

        return Socialite::driver($driver)
            ->stateless()
            ->redirect();
    }

    /**
     * Handle social provider callback.
     */
    public function callback(string $provider): JsonResponse
    {
        $driver = $this->socialAuthService->getDriver($provider);
        $providerName = $this->socialAuthService->getProviderName($provider);

        try {
            $socialUser = Socialite::driver($driver)->stateless()->user();
        } catch (\Exception $e) {
            return response()->json([
                'message' => 'Authentication failed.',
                'error' => $e->getMessage(),
            ], 401);
        }

        $user = $this->socialAuthService->findOrCreateUser($socialUser, $providerName);
        $result = $this->socialAuthService->generateAuthResponse($user);

        return response()->json([
            'message' => 'Login successful',
            'user' => $result['user'],
            'token' => $result['token'],
        ]);
    }
}
