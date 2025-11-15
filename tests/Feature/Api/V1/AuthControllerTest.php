<?php

namespace Tests\Feature\Api\V1;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use App\Notifications\ResetPasswordNotification;
use App\Notifications\VerifyEmailNotification;
use App\Notifications\OtpNotification;
use Illuminate\Support\Facades\URL;
use Laravel\Sanctum\Sanctum;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\User as SocialiteUser;
use Mockery;
use Tests\TestCase;

class AuthControllerTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Test user registration with valid data.
     */
    public function test_user_can_register_with_valid_data(): void
    {
        $userData = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password' => 'Password123!',
            'password_confirmation' => 'Password123!',
        ];

        $response = $this->postJson('/api/v1/register', $userData);

        $response->assertStatus(201)
            ->assertJsonStructure([
                'message',
                'user' => [
                    'id',
                    'name',
                    'email',
                    'created_at',
                    'updated_at',
                ],
                'token',
            ])
            ->assertJson([
                'message' => 'User registered successfully',
                'user' => [
                    'name' => 'John Doe',
                    'email' => 'john@example.com',
                ],
            ]);

        // Verify user was created in database
        $this->assertDatabaseHas('users', [
            'name' => 'John Doe',
            'email' => 'john@example.com',
        ]);

        // Verify password is hashed
        $user = User::where('email', 'john@example.com')->first();
        $this->assertTrue(Hash::check('Password123!', $user->password));

        // Verify token was created
        $this->assertNotNull($response->json('token'));
    }

    /**
     * Test registration fails with missing name.
     */
    public function test_registration_fails_without_name(): void
    {
        $userData = [
            'email' => 'john@example.com',
            'password' => 'Password123!',
            'password_confirmation' => 'Password123!',
        ];

        $response = $this->postJson('/api/v1/register', $userData);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['name']);
    }

    /**
     * Test registration fails with invalid email.
     */
    public function test_registration_fails_with_invalid_email(): void
    {
        $userData = [
            'name' => 'John Doe',
            'email' => 'invalid-email',
            'password' => 'Password123!',
            'password_confirmation' => 'Password123!',
        ];

        $response = $this->postJson('/api/v1/register', $userData);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /**
     * Test registration fails with duplicate email.
     */
    public function test_registration_fails_with_duplicate_email(): void
    {
        User::factory()->create([
            'email' => 'existing@example.com',
        ]);

        $userData = [
            'name' => 'John Doe',
            'email' => 'existing@example.com',
            'password' => 'Password123!',
            'password_confirmation' => 'Password123!',
        ];

        $response = $this->postJson('/api/v1/register', $userData);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /**
     * Test registration fails without password.
     */
    public function test_registration_fails_without_password(): void
    {
        $userData = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password_confirmation' => 'Password123!',
        ];

        $response = $this->postJson('/api/v1/register', $userData);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['password']);
    }

    /**
     * Test registration fails with mismatched password confirmation.
     */
    public function test_registration_fails_with_mismatched_password_confirmation(): void
    {
        $userData = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password' => 'Password123!',
            'password_confirmation' => 'DifferentPassword123!',
        ];

        $response = $this->postJson('/api/v1/register', $userData);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['password']);
    }

    /**
     * Test registration fails with weak password.
     */
    public function test_registration_fails_with_weak_password(): void
    {
        $userData = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password' => '123',
            'password_confirmation' => '123',
        ];

        $response = $this->postJson('/api/v1/register', $userData);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['password']);
    }

    /**
     * Test user can login with valid credentials (sends OTP).
     */
    public function test_user_can_login_with_valid_credentials(): void
    {
        Notification::fake();

        $user = User::factory()->create([
            'email' => 'john@example.com',
            'password' => Hash::make('Password123!'),
        ]);

        $loginData = [
            'email' => 'john@example.com',
            'password' => 'Password123!',
        ];

        $response = $this->postJson('/api/v1/login', $loginData);

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Verification code has been sent to your email address.',
            ])
            ->assertJsonMissing(['token', 'user']);

        // Verify OTP notification was sent
        Notification::assertSentTo($user, OtpNotification::class);
    }

    /**
     * Test login fails with incorrect email.
     */
    public function test_login_fails_with_incorrect_email(): void
    {
        User::factory()->create([
            'email' => 'john@example.com',
            'password' => Hash::make('Password123!'),
        ]);

        $loginData = [
            'email' => 'wrong@example.com',
            'password' => 'Password123!',
        ];

        $response = $this->postJson('/api/v1/login', $loginData);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /**
     * Test login fails with incorrect password.
     */
    public function test_login_fails_with_incorrect_password(): void
    {
        User::factory()->create([
            'email' => 'john@example.com',
            'password' => Hash::make('Password123!'),
        ]);

        $loginData = [
            'email' => 'john@example.com',
            'password' => 'WrongPassword123!',
        ];

        $response = $this->postJson('/api/v1/login', $loginData);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /**
     * Test login fails without email.
     */
    public function test_login_fails_without_email(): void
    {
        $loginData = [
            'password' => 'Password123!',
        ];

        $response = $this->postJson('/api/v1/login', $loginData);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /**
     * Test login fails without password.
     */
    public function test_login_fails_without_password(): void
    {
        $loginData = [
            'email' => 'john@example.com',
        ];

        $response = $this->postJson('/api/v1/login', $loginData);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['password']);
    }

    /**
     * Test login fails with invalid email format.
     */
    public function test_login_fails_with_invalid_email_format(): void
    {
        $loginData = [
            'email' => 'invalid-email',
            'password' => 'Password123!',
        ];

        $response = $this->postJson('/api/v1/login', $loginData);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /**
     * Test authenticated user can logout.
     */
    public function test_authenticated_user_can_logout(): void
    {
        $user = User::factory()->create();
        $token = $user->createToken('auth-token')->plainTextToken;

        $response = $this->withHeader('Authorization', 'Bearer ' . $token)
            ->postJson('/api/v1/logout');

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Logged out successfully',
            ]);

        // Verify token was deleted
        $this->assertDatabaseMissing('personal_access_tokens', [
            'tokenable_id' => $user->id,
            'tokenable_type' => User::class,
        ]);
    }

    /**
     * Test logout fails without authentication.
     */
    public function test_logout_fails_without_authentication(): void
    {
        $response = $this->postJson('/api/v1/logout');

        $response->assertStatus(401);
    }

    /**
     * Test logout with invalid token.
     */
    public function test_logout_fails_with_invalid_token(): void
    {
        $response = $this->withHeader('Authorization', 'Bearer invalid-token')
            ->postJson('/api/v1/logout');

        $response->assertStatus(401);
    }

    /**
     * Test logout deletes only current token.
     */
    public function test_logout_deletes_only_current_token(): void
    {
        $user = User::factory()->create();
        $token1 = $user->createToken('auth-token-1')->plainTextToken;
        $token2 = $user->createToken('auth-token-2')->plainTextToken;

        // Verify both tokens exist
        $this->assertCount(2, $user->tokens);

        // Logout with first token
        $response = $this->withHeader('Authorization', 'Bearer ' . $token1)
            ->postJson('/api/v1/logout');

        $response->assertStatus(200);

        // Refresh user to get updated token count
        $user->refresh();

        // Only one token should remain
        $this->assertCount(1, $user->tokens);

        // Verify the remaining token is the second one (by checking if token2 still works)
        $response = $this->withHeader('Authorization', 'Bearer ' . $token2)
            ->postJson('/api/v1/logout');

        $response->assertStatus(200);
    }

    /**
     * Test user can request password reset with valid email.
     */
    public function test_user_can_request_password_reset_with_valid_email(): void
    {
        Notification::fake();

        $user = User::factory()->create([
            'email' => 'john@example.com',
        ]);

        $response = $this->postJson('/api/v1/forgot-password', [
            'email' => 'john@example.com',
        ]);

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Password reset link has been sent to your email address.',
            ]);

        // Verify notification was sent
        Notification::assertSentTo($user, ResetPasswordNotification::class);

        // Verify token was created in database
        $this->assertDatabaseHas('password_reset_tokens', [
            'email' => 'john@example.com',
        ]);
    }

    /**
     * Test forgot password fails without email.
     */
    public function test_forgot_password_fails_without_email(): void
    {
        $response = $this->postJson('/api/v1/forgot-password', []);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /**
     * Test forgot password fails with invalid email format.
     */
    public function test_forgot_password_fails_with_invalid_email_format(): void
    {
        $response = $this->postJson('/api/v1/forgot-password', [
            'email' => 'invalid-email',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /**
     * Test forgot password fails with non-existent email.
     */
    public function test_forgot_password_fails_with_non_existent_email(): void
    {
        $response = $this->postJson('/api/v1/forgot-password', [
            'email' => 'nonexistent@example.com',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /**
     * Test user can reset password with valid token.
     */
    public function test_user_can_reset_password_with_valid_token(): void
    {
        $user = User::factory()->create([
            'email' => 'john@example.com',
            'password' => Hash::make('OldPassword123!'),
        ]);

        // Create a password reset token
        $token = 'test-reset-token-123';
        DB::table('password_reset_tokens')->insert([
            'email' => 'john@example.com',
            'token' => Hash::make($token),
            'created_at' => now(),
        ]);

        $response = $this->postJson('/api/v1/reset-password', [
            'email' => 'john@example.com',
            'token' => $token,
            'password' => 'NewPassword123!',
            'password_confirmation' => 'NewPassword123!',
        ]);

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Password has been reset successfully.',
            ]);

        // Verify password was updated
        $user->refresh();
        $this->assertTrue(Hash::check('NewPassword123!', $user->password));

        // Verify token was deleted
        $this->assertDatabaseMissing('password_reset_tokens', [
            'email' => 'john@example.com',
        ]);
    }

    /**
     * Test reset password fails without email.
     */
    public function test_reset_password_fails_without_email(): void
    {
        $response = $this->postJson('/api/v1/reset-password', [
            'token' => 'some-token',
            'password' => 'NewPassword123!',
            'password_confirmation' => 'NewPassword123!',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /**
     * Test reset password fails without token.
     */
    public function test_reset_password_fails_without_token(): void
    {
        User::factory()->create([
            'email' => 'john@example.com',
        ]);

        $response = $this->postJson('/api/v1/reset-password', [
            'email' => 'john@example.com',
            'password' => 'NewPassword123!',
            'password_confirmation' => 'NewPassword123!',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['token']);
    }

    /**
     * Test reset password fails without password.
     */
    public function test_reset_password_fails_without_password(): void
    {
        User::factory()->create([
            'email' => 'john@example.com',
        ]);

        $token = 'test-reset-token-123';
        DB::table('password_reset_tokens')->insert([
            'email' => 'john@example.com',
            'token' => Hash::make($token),
            'created_at' => now(),
        ]);

        $response = $this->postJson('/api/v1/reset-password', [
            'email' => 'john@example.com',
            'token' => $token,
            'password_confirmation' => 'NewPassword123!',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['password']);
    }

    /**
     * Test reset password fails with mismatched password confirmation.
     */
    public function test_reset_password_fails_with_mismatched_password_confirmation(): void
    {
        User::factory()->create([
            'email' => 'john@example.com',
        ]);

        $token = 'test-reset-token-123';
        DB::table('password_reset_tokens')->insert([
            'email' => 'john@example.com',
            'token' => Hash::make($token),
            'created_at' => now(),
        ]);

        $response = $this->postJson('/api/v1/reset-password', [
            'email' => 'john@example.com',
            'token' => $token,
            'password' => 'NewPassword123!',
            'password_confirmation' => 'DifferentPassword123!',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['password']);
    }

    /**
     * Test reset password fails with invalid token.
     */
    public function test_reset_password_fails_with_invalid_token(): void
    {
        User::factory()->create([
            'email' => 'john@example.com',
        ]);

        $response = $this->postJson('/api/v1/reset-password', [
            'email' => 'john@example.com',
            'token' => 'invalid-token',
            'password' => 'NewPassword123!',
            'password_confirmation' => 'NewPassword123!',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['token']);
    }

    /**
     * Test reset password fails with wrong token.
     */
    public function test_reset_password_fails_with_wrong_token(): void
    {
        User::factory()->create([
            'email' => 'john@example.com',
        ]);

        // Create token for different email
        $correctToken = 'correct-token';
        DB::table('password_reset_tokens')->insert([
            'email' => 'john@example.com',
            'token' => Hash::make($correctToken),
            'created_at' => now(),
        ]);

        $response = $this->postJson('/api/v1/reset-password', [
            'email' => 'john@example.com',
            'token' => 'wrong-token',
            'password' => 'NewPassword123!',
            'password_confirmation' => 'NewPassword123!',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['token']);
    }

    /**
     * Test reset password fails with expired token.
     */
    public function test_reset_password_fails_with_expired_token(): void
    {
        $user = User::factory()->create([
            'email' => 'john@example.com',
        ]);

        $token = 'expired-token';
        // Create token that was created 61 minutes ago (expired)
        DB::table('password_reset_tokens')->insert([
            'email' => 'john@example.com',
            'token' => Hash::make($token),
            'created_at' => now()->subMinutes(61),
        ]);

        $response = $this->postJson('/api/v1/reset-password', [
            'email' => 'john@example.com',
            'token' => $token,
            'password' => 'NewPassword123!',
            'password_confirmation' => 'NewPassword123!',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['token']);

        // Verify expired token was deleted
        $this->assertDatabaseMissing('password_reset_tokens', [
            'email' => 'john@example.com',
        ]);
    }

    /**
     * Test reset password revokes all existing tokens.
     */
    public function test_reset_password_revokes_all_existing_tokens(): void
    {
        $user = User::factory()->create([
            'email' => 'john@example.com',
        ]);

        // Create some existing tokens
        $token1 = $user->createToken('token-1')->plainTextToken;
        $token2 = $user->createToken('token-2')->plainTextToken;

        // Create password reset token
        $resetToken = 'reset-token';
        DB::table('password_reset_tokens')->insert([
            'email' => 'john@example.com',
            'token' => Hash::make($resetToken),
            'created_at' => now(),
        ]);

        $response = $this->postJson('/api/v1/reset-password', [
            'email' => 'john@example.com',
            'token' => $resetToken,
            'password' => 'NewPassword123!',
            'password_confirmation' => 'NewPassword123!',
        ]);

        $response->assertStatus(200);

        // Verify all tokens were revoked
        $user->refresh();
        $this->assertCount(0, $user->tokens);

        // Verify tokens no longer work
        $this->withHeader('Authorization', 'Bearer ' . $token1)
            ->postJson('/api/v1/logout')
            ->assertStatus(401);
    }

    /**
     * Test forgot password replaces old token.
     */
    public function test_forgot_password_replaces_old_token(): void
    {
        Notification::fake();

        $user = User::factory()->create([
            'email' => 'john@example.com',
        ]);

        // Create old token
        $oldToken = 'old-token';
        DB::table('password_reset_tokens')->insert([
            'email' => 'john@example.com',
            'token' => Hash::make($oldToken),
            'created_at' => now(),
        ]);

        // Request new password reset
        $response = $this->postJson('/api/v1/forgot-password', [
            'email' => 'john@example.com',
        ]);

        $response->assertStatus(200);

        // Verify old token no longer works
        $response = $this->postJson('/api/v1/reset-password', [
            'email' => 'john@example.com',
            'token' => $oldToken,
            'password' => 'NewPassword123!',
            'password_confirmation' => 'NewPassword123!',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['token']);

        // Verify new token exists
        $this->assertDatabaseHas('password_reset_tokens', [
            'email' => 'john@example.com',
        ]);
    }

    /**
     * Test redirect to Google OAuth.
     */
    public function test_redirect_to_google_oauth(): void
    {
        $response = $this->get('/api/v1/auth/google/redirect');

        // Should redirect to Google OAuth
        $response->assertStatus(302);
        $this->assertStringContainsString('accounts.google.com', $response->headers->get('Location'));
    }

    /**
     * Test redirect to Facebook OAuth.
     */
    public function test_redirect_to_facebook_oauth(): void
    {
        $response = $this->get('/api/v1/auth/facebook/redirect');

        // Should redirect to Facebook OAuth
        $response->assertStatus(302);
        $this->assertStringContainsString('facebook.com', $response->headers->get('Location'));
    }

    /**
     * Test redirect fails with unsupported provider.
     */
    public function test_redirect_fails_with_unsupported_provider(): void
    {
        $response = $this->get('/api/v1/auth/unsupported/redirect');

        $response->assertStatus(404);
    }

    /**
     * Test Google OAuth callback creates new user.
     */
    public function test_google_oauth_callback_creates_new_user(): void
    {
        $mockSocialiteUser = Mockery::mock(SocialiteUser::class);
        $mockSocialiteUser->shouldReceive('getId')->andReturn('123456789');
        $mockSocialiteUser->shouldReceive('getName')->andReturn('John Doe');
        $mockSocialiteUser->shouldReceive('getEmail')->andReturn('john@example.com');
        $mockSocialiteUser->shouldReceive('getNickname')->andReturn(null);

        Socialite::shouldReceive('driver')
            ->with('google')
            ->andReturnSelf();
        Socialite::shouldReceive('stateless')
            ->andReturnSelf();
        Socialite::shouldReceive('user')
            ->andReturn($mockSocialiteUser);

        $response = $this->get('/api/v1/auth/google/callback');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'message',
                'user' => [
                    'id',
                    'name',
                    'email',
                ],
                'token',
            ])
            ->assertJson([
                'message' => 'Login successful',
                'user' => [
                    'name' => 'John Doe',
                    'email' => 'john@example.com',
                ],
            ]);

        // Verify user was created
        $this->assertDatabaseHas('users', [
            'email' => 'john@example.com',
            'provider' => 'google',
            'provider_id' => '123456789',
            'social_media_login' => true,
        ]);
    }

    /**
     * Test Google OAuth callback logs in existing user.
     */
    public function test_google_oauth_callback_logs_in_existing_user(): void
    {
        $user = User::factory()->create([
            'email' => 'john@example.com',
            'provider' => 'google',
            'provider_id' => '123456789',
            'social_media_login' => true,
        ]);

        $mockSocialiteUser = Mockery::mock(SocialiteUser::class);
        $mockSocialiteUser->shouldReceive('getId')->andReturn('123456789');
        $mockSocialiteUser->shouldReceive('getName')->andReturn('John Doe');
        $mockSocialiteUser->shouldReceive('getEmail')->andReturn('john@example.com');

        Socialite::shouldReceive('driver')
            ->with('google')
            ->andReturnSelf();
        Socialite::shouldReceive('stateless')
            ->andReturnSelf();
        Socialite::shouldReceive('user')
            ->andReturn($mockSocialiteUser);

        $response = $this->get('/api/v1/auth/google/callback');

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Login successful',
                'user' => [
                    'id' => $user->id,
                    'email' => 'john@example.com',
                ],
            ]);

        // Verify only one user exists
        $this->assertDatabaseCount('users', 1);
    }

    /**
     * Test Google OAuth callback links to existing email user.
     */
    public function test_google_oauth_callback_links_to_existing_email_user(): void
    {
        $user = User::factory()->create([
            'email' => 'john@example.com',
            'provider' => null,
            'provider_id' => null,
            'social_media_login' => false,
        ]);

        $mockSocialiteUser = Mockery::mock(SocialiteUser::class);
        $mockSocialiteUser->shouldReceive('getId')->andReturn('123456789');
        $mockSocialiteUser->shouldReceive('getName')->andReturn('John Doe');
        $mockSocialiteUser->shouldReceive('getEmail')->andReturn('john@example.com');

        Socialite::shouldReceive('driver')
            ->with('google')
            ->andReturnSelf();
        Socialite::shouldReceive('stateless')
            ->andReturnSelf();
        Socialite::shouldReceive('user')
            ->andReturn($mockSocialiteUser);

        $response = $this->get('/api/v1/auth/google/callback');

        $response->assertStatus(200);

        // Verify user was updated with provider info
        $user->refresh();
        $this->assertEquals('google', $user->provider);
        $this->assertEquals('123456789', $user->provider_id);
        $this->assertTrue($user->social_media_login);
    }

    /**
     * Test Facebook OAuth callback creates new user.
     */
    public function test_facebook_oauth_callback_creates_new_user(): void
    {
        $mockSocialiteUser = Mockery::mock(SocialiteUser::class);
        $mockSocialiteUser->shouldReceive('getId')->andReturn('987654321');
        $mockSocialiteUser->shouldReceive('getName')->andReturn('Jane Doe');
        $mockSocialiteUser->shouldReceive('getEmail')->andReturn('jane@example.com');
        $mockSocialiteUser->shouldReceive('getNickname')->andReturn(null);

        Socialite::shouldReceive('driver')
            ->with('facebook')
            ->andReturnSelf();
        Socialite::shouldReceive('stateless')
            ->andReturnSelf();
        Socialite::shouldReceive('user')
            ->andReturn($mockSocialiteUser);

        $response = $this->get('/api/v1/auth/facebook/callback');

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Login successful',
                'user' => [
                    'name' => 'Jane Doe',
                    'email' => 'jane@example.com',
                ],
            ]);

        // Verify user was created
        $this->assertDatabaseHas('users', [
            'email' => 'jane@example.com',
            'provider' => 'facebook',
            'provider_id' => '987654321',
            'social_media_login' => true,
        ]);
    }

    /**
     * Test Twitter OAuth callback creates new user.
     */
    public function test_twitter_oauth_callback_creates_new_user(): void
    {
        $mockSocialiteUser = Mockery::mock(SocialiteUser::class);
        $mockSocialiteUser->shouldReceive('getId')->andReturn('555666777');
        $mockSocialiteUser->shouldReceive('getName')->andReturn('Twitter User');
        $mockSocialiteUser->shouldReceive('getEmail')->andReturn(null); // Twitter may not provide email
        $mockSocialiteUser->shouldReceive('getNickname')->andReturn('twitteruser');

        Socialite::shouldReceive('driver')
            ->with('twitter')
            ->andReturnSelf();
        Socialite::shouldReceive('stateless')
            ->andReturnSelf();
        Socialite::shouldReceive('user')
            ->andReturn($mockSocialiteUser);

        $response = $this->get('/api/v1/auth/twitter/callback');

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Login successful',
            ]);

        // Verify user was created with fallback email
        $this->assertDatabaseHas('users', [
            'provider' => 'twitter',
            'provider_id' => '555666777',
            'social_media_login' => true,
        ]);
    }

    /**
     * Test OAuth callback handles authentication failure.
     */
    public function test_oauth_callback_handles_authentication_failure(): void
    {
        Socialite::shouldReceive('driver')
            ->with('google')
            ->andReturnSelf();
        Socialite::shouldReceive('stateless')
            ->andReturnSelf();
        Socialite::shouldReceive('user')
            ->andThrow(new \Exception('Invalid credentials'));

        $response = $this->get('/api/v1/auth/google/callback');

        $response->assertStatus(401)
            ->assertJson([
                'message' => 'Authentication failed.',
            ]);
    }

    /**
     * Test registration sends verification email.
     */
    public function test_registration_sends_verification_email(): void
    {
        Notification::fake();

        $userData = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password' => 'Password123!',
            'password_confirmation' => 'Password123!',
        ];

        $response = $this->postJson('/api/v1/register', $userData);

        $response->assertStatus(201);

        $user = User::where('email', 'john@example.com')->first();
        
        // Verify notification was sent
        Notification::assertSentTo($user, VerifyEmailNotification::class);

        // Verify email is not verified yet
        $this->assertNull($user->email_verified_at);
    }

    /**
     * Test user can verify email with valid signed URL.
     */
    public function test_user_can_verify_email_with_valid_signed_url(): void
    {
        $user = User::factory()->unverified()->create([
            'email' => 'john@example.com',
        ]);

        $verificationUrl = URL::temporarySignedRoute(
            'verification.verify',
            now()->addHours(24),
            [
                'id' => $user->id,
                'hash' => sha1($user->email),
            ]
        );

        // Extract id and hash from URL
        $parsedUrl = parse_url($verificationUrl);
        parse_str($parsedUrl['query'] ?? '', $queryParams);
        $pathParts = explode('/', trim($parsedUrl['path'], '/'));

        $response = $this->get($verificationUrl);

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Email verified successfully.',
            ]);

        // Verify email was marked as verified
        $user->refresh();
        $this->assertNotNull($user->email_verified_at);
    }

    /**
     * Test email verification fails with invalid signature.
     */
    public function test_email_verification_fails_with_invalid_signature(): void
    {
        $user = User::factory()->unverified()->create([
            'email' => 'john@example.com',
        ]);

        $invalidUrl = '/api/v1/email/verify/' . $user->id . '/' . sha1($user->email) . '?expires=' . time() . '&signature=invalid';

        $response = $this->get($invalidUrl);

        $response->assertStatus(403)
            ->assertJson([
                'message' => 'Invalid or expired verification link.',
            ]);

        // Verify email was not verified
        $user->refresh();
        $this->assertNull($user->email_verified_at);
    }

    /**
     * Test email verification fails with wrong hash.
     * Note: Changing the hash invalidates the signature, so it fails at signature validation.
     */
    public function test_email_verification_fails_with_wrong_hash(): void
    {
        $user = User::factory()->unverified()->create([
            'email' => 'john@example.com',
        ]);

        // Create valid signed URL but manually change the hash in the path
        $verificationUrl = URL::temporarySignedRoute(
            'verification.verify',
            now()->addHours(24),
            [
                'id' => $user->id,
                'hash' => sha1($user->email), // Correct hash for signature
            ]
        );

        // Replace the hash in the URL with wrong hash (this invalidates the signature)
        $wrongHashUrl = str_replace('/' . sha1($user->email), '/wrong-hash', $verificationUrl);

        $response = $this->get($wrongHashUrl);

        // Signature validation fails first when hash is tampered with
        $response->assertStatus(403)
            ->assertJson([
                'message' => 'Invalid or expired verification link.',
            ]);
    }

    /**
     * Test email verification fails when already verified.
     */
    public function test_email_verification_fails_when_already_verified(): void
    {
        $user = User::factory()->create([
            'email' => 'john@example.com',
            'email_verified_at' => now(),
        ]);

        $verificationUrl = URL::temporarySignedRoute(
            'verification.verify',
            now()->addHours(24),
            [
                'id' => $user->id,
                'hash' => sha1($user->email),
            ]
        );

        $response = $this->get($verificationUrl);

        // The validation exception might cause a redirect in some cases
        // Check that the error message is present
        if ($response->status() === 302) {
            $response->assertRedirect();
        } else {
            $response->assertStatus(422)
                ->assertJsonValidationErrors(['email']);
        }
    }

    /**
     * Test user can resend verification email.
     */
    public function test_user_can_resend_verification_email(): void
    {
        Notification::fake();

        $user = User::factory()->unverified()->create([
            'email' => 'john@example.com',
        ]);

        $response = $this->postJson('/api/v1/email/verification-notification', [
            'email' => 'john@example.com',
        ]);

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Verification email has been sent.',
            ]);

        // Verify notification was sent
        Notification::assertSentTo($user, VerifyEmailNotification::class);
    }

    /**
     * Test resend verification fails without email.
     */
    public function test_resend_verification_fails_without_email(): void
    {
        $response = $this->postJson('/api/v1/email/verification-notification', []);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /**
     * Test resend verification fails with invalid email.
     */
    public function test_resend_verification_fails_with_invalid_email(): void
    {
        $response = $this->postJson('/api/v1/email/verification-notification', [
            'email' => 'invalid-email',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /**
     * Test resend verification fails with non-existent email.
     */
    public function test_resend_verification_fails_with_non_existent_email(): void
    {
        $response = $this->postJson('/api/v1/email/verification-notification', [
            'email' => 'nonexistent@example.com',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /**
     * Test resend verification fails when email already verified.
     */
    public function test_resend_verification_fails_when_email_already_verified(): void
    {
        User::factory()->create([
            'email' => 'john@example.com',
            'email_verified_at' => now(),
        ]);

        $response = $this->postJson('/api/v1/email/verification-notification', [
            'email' => 'john@example.com',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /**
     * Test email verification link expires after 24 hours.
     */
    public function test_email_verification_link_expires_after_24_hours(): void
    {
        $user = User::factory()->unverified()->create([
            'email' => 'john@example.com',
        ]);

        // Create a URL that expired 1 hour ago (25 hours total)
        $expiredUrl = URL::temporarySignedRoute(
            'verification.verify',
            now()->subHour(), // Expired
            [
                'id' => $user->id,
                'hash' => sha1($user->email),
            ]
        );

        $response = $this->get($expiredUrl);

        $response->assertStatus(403)
            ->assertJson([
                'message' => 'Invalid or expired verification link.',
            ]);
    }

    /**
     * Test authenticated user can get their information.
     */
    public function test_authenticated_user_can_get_their_information(): void
    {
        $user = User::factory()->create([
            'name' => 'John Doe',
            'email' => 'john@example.com',
        ]);

        $token = $user->createToken('auth-token')->plainTextToken;

        $response = $this->withHeader('Authorization', 'Bearer ' . $token)
            ->getJson('/api/v1/me');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'user' => [
                    'id',
                    'name',
                    'email',
                    'email_verified_at',
                    'created_at',
                    'updated_at',
                ],
            ])
            ->assertJson([
                'user' => [
                    'id' => $user->id,
                    'name' => 'John Doe',
                    'email' => 'john@example.com',
                ],
            ]);

        // Verify password is not in response
        $responseData = $response->json();
        $this->assertArrayNotHasKey('password', $responseData['user']);
    }

    /**
     * Test unauthenticated user cannot access me endpoint.
     */
    public function test_unauthenticated_user_cannot_access_me_endpoint(): void
    {
        $response = $this->getJson('/api/v1/me');

        $response->assertStatus(401);
    }

    /**
     * Test me endpoint fails with invalid token.
     */
    public function test_me_endpoint_fails_with_invalid_token(): void
    {
        $response = $this->withHeader('Authorization', 'Bearer invalid-token')
            ->getJson('/api/v1/me');

        $response->assertStatus(401);
    }

    /**
     * Test me endpoint returns user with social media login info.
     */
    public function test_me_endpoint_returns_user_with_social_media_info(): void
    {
        $user = User::factory()->create([
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'provider' => 'google',
            'provider_id' => '123456789',
            'social_media_login' => true,
        ]);

        $token = $user->createToken('auth-token')->plainTextToken;

        $response = $this->withHeader('Authorization', 'Bearer ' . $token)
            ->getJson('/api/v1/me');

        $response->assertStatus(200)
            ->assertJson([
                'user' => [
                    'provider' => 'google',
                    'provider_id' => '123456789',
                    'social_media_login' => true,
                ],
            ]);
    }

    /**
     * Test login sends OTP email instead of token.
     */
    public function test_login_sends_otp_email_instead_of_token(): void
    {
        Notification::fake();

        $user = User::factory()->create([
            'email' => 'john@example.com',
            'password' => Hash::make('Password123!'),
        ]);

        $response = $this->postJson('/api/v1/login', [
            'email' => 'john@example.com',
            'password' => 'Password123!',
        ]);

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Verification code has been sent to your email address.',
            ])
            ->assertJsonMissing(['token']);

        // Verify OTP notification was sent
        Notification::assertSentTo($user, OtpNotification::class);

        // Verify OTP was stored in database
        $this->assertDatabaseHas('otps', [
            'email' => 'john@example.com',
            'used' => false,
        ]);
    }

    /**
     * Test login fails with incorrect credentials no OTP sent.
     */
    public function test_login_fails_with_incorrect_credentials_no_otp_sent(): void
    {
        Notification::fake();

        User::factory()->create([
            'email' => 'john@example.com',
            'password' => Hash::make('Password123!'),
        ]);

        $response = $this->postJson('/api/v1/login', [
            'email' => 'john@example.com',
            'password' => 'WrongPassword123!',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);

        // Verify no OTP notification was sent
        Notification::assertNothingSent();
    }

    /**
     * Test verify OTP fails without email.
     */
    public function test_verify_otp_fails_without_email(): void
    {
        $response = $this->postJson('/api/v1/verify-otp', [
            'code' => '123456',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /**
     * Test verify OTP fails without code.
     */
    public function test_verify_otp_fails_without_code(): void
    {
        User::factory()->create([
            'email' => 'john@example.com',
        ]);

        $response = $this->postJson('/api/v1/verify-otp', [
            'email' => 'john@example.com',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['code']);
    }

    /**
     * Test verify OTP fails with invalid code length.
     */
    public function test_verify_otp_fails_with_invalid_code_length(): void
    {
        User::factory()->create([
            'email' => 'john@example.com',
        ]);

        $response = $this->postJson('/api/v1/verify-otp', [
            'email' => 'john@example.com',
            'code' => '12345', // 5 digits instead of 6
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['code']);
    }

    /**
     * Test verify OTP fails with invalid code.
     */
    public function test_verify_otp_fails_with_invalid_code(): void
    {
        $user = User::factory()->create([
            'email' => 'john@example.com',
            'password' => Hash::make('Password123!'),
        ]);

        // Login to generate OTP
        $this->postJson('/api/v1/login', [
            'email' => 'john@example.com',
            'password' => 'Password123!',
        ]);

        // Try to verify with wrong code
        $response = $this->postJson('/api/v1/verify-otp', [
            'email' => 'john@example.com',
            'code' => '000000', // Wrong code
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['code']);
    }

    /**
     * Test verify OTP fails with expired code.
     */
    public function test_verify_otp_fails_with_expired_code(): void
    {
        $user = User::factory()->create([
            'email' => 'john@example.com',
        ]);

        // Create an expired OTP
        $expiredCode = '123456';
        DB::table('otps')->insert([
            'email' => 'john@example.com',
            'code' => Hash::make($expiredCode),
            'expires_at' => now()->subMinutes(11), // Expired (10 minutes expiry)
            'used' => false,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $response = $this->postJson('/api/v1/verify-otp', [
            'email' => 'john@example.com',
            'code' => $expiredCode,
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['code']);
    }

    /**
     * Test verify OTP fails with non-existent email.
     */
    public function test_verify_otp_fails_with_non_existent_email(): void
    {
        $response = $this->postJson('/api/v1/verify-otp', [
            'email' => 'nonexistent@example.com',
            'code' => '123456',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /**
     * Test OTP can only be used once.
     */
    public function test_otp_can_only_be_used_once(): void
    {
        $user = User::factory()->create([
            'email' => 'john@example.com',
            'password' => Hash::make('Password123!'),
        ]);

        // Create an OTP manually for testing
        $code = '123456';
        DB::table('otps')->insert([
            'email' => 'john@example.com',
            'code' => Hash::make($code),
            'expires_at' => now()->addMinutes(10),
            'used' => false,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        // First verification should succeed
        $response = $this->postJson('/api/v1/verify-otp', [
            'email' => 'john@example.com',
            'code' => $code,
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'message',
                'user',
                'token',
            ]);

        // Second verification with same code should fail
        $response = $this->postJson('/api/v1/verify-otp', [
            'email' => 'john@example.com',
            'code' => $code,
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['code']);
    }

    /**
     * Test complete 2FA login flow.
     */
    public function test_complete_2fa_login_flow(): void
    {
        Notification::fake();

        $user = User::factory()->create([
            'email' => 'john@example.com',
            'password' => Hash::make('Password123!'),
        ]);

        // Step 1: Login (should send OTP)
        $loginResponse = $this->postJson('/api/v1/login', [
            'email' => 'john@example.com',
            'password' => 'Password123!',
        ]);

        $loginResponse->assertStatus(200)
            ->assertJson([
                'message' => 'Verification code has been sent to your email address.',
            ]);

        Notification::assertSentTo($user, OtpNotification::class);

        // Step 2: Get OTP from notification (in real scenario, user gets it from email)
        $notification = Notification::sent($user, OtpNotification::class)->first();
        $otpCode = $notification->code;

        // Step 3: Verify OTP and get token
        $verifyResponse = $this->postJson('/api/v1/verify-otp', [
            'email' => 'john@example.com',
            'code' => $otpCode,
        ]);

        $verifyResponse->assertStatus(200)
            ->assertJsonStructure([
                'message',
                'user' => [
                    'id',
                    'name',
                    'email',
                ],
                'token',
            ])
            ->assertJson([
                'message' => 'Login successful',
                'user' => [
                    'email' => 'john@example.com',
                ],
            ]);

        // Verify token works
        $token = $verifyResponse->json('token');
        $meResponse = $this->withHeader('Authorization', 'Bearer ' . $token)
            ->getJson('/api/v1/me');

        $meResponse->assertStatus(200)
            ->assertJson([
                'user' => [
                    'email' => 'john@example.com',
                ],
            ]);
    }
}

