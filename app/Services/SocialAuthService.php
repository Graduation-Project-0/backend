<?php

namespace App\Services;

use App\Models\User;
use Laravel\Socialite\Contracts\User as SocialiteUser;

class SocialAuthService
{
    private const SUPPORTED_PROVIDERS = ['google', 'facebook', 'twitter', 'x'];

    /**
     * Get the Socialite driver name for a provider.
     */
    public function getDriver(string $provider): string
    {
        $this->validateProvider($provider);

        return $provider === 'x' ? 'twitter' : $provider;
    }

    /**
     * Get the provider name for database storage.
     */
    public function getProviderName(string $provider): string
    {
        $this->validateProvider($provider);

        return $provider === 'x' ? 'twitter' : $provider;
    }

    /**
     * Validate that the provider is supported.
     */
    public function validateProvider(string $provider): void
    {
        if (! in_array($provider, self::SUPPORTED_PROVIDERS)) {
            abort(404, 'Provider not supported');
        }
    }

    /**
     * Find or create a user from social provider data.
     */
    public function findOrCreateUser(SocialiteUser $socialUser, string $provider): User
    {
        // Try to find user by provider_id and provider
        $user = User::where('provider', $provider)
            ->where('provider_id', $socialUser->getId())
            ->first();

        if ($user) {
            return $user;
        }

        // Try to find user by email (in case they registered with email first)
        if ($socialUser->getEmail()) {
            $user = User::where('email', $socialUser->getEmail())->first();

            if ($user) {
                // Update existing user with social provider info
                $user->update([
                    'provider' => $provider,
                    'provider_id' => $socialUser->getId(),
                    'social_media_login' => true,
                ]);

                return $user;
            }
        }

        // Create new user
        return User::create([
            'name' => $socialUser->getName() ?? $socialUser->getNickname() ?? 'User',
            'email' => $socialUser->getEmail() ?? $socialUser->getId().'@'.$provider.'.local',
            'password' => null,
            'provider' => $provider,
            'provider_id' => $socialUser->getId(),
            'social_media_login' => true,
            'email_verified_at' => $socialUser->getEmail() ? now() : null,
        ]);
    }

    /**
     * Generate authentication response for social login.
     */
    public function generateAuthResponse(User $user): array
    {
        $token = $user->createToken('auth-token')->plainTextToken;

        return [
            'user' => $user,
            'token' => $token,
        ];
    }
}
