<?php

namespace Tests\Feature\Api\V1;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use App\Notifications\ResetPasswordNotification;
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
     * Test user can login with valid credentials.
     */
    public function test_user_can_login_with_valid_credentials(): void
    {
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
                'message' => 'Login successful',
                'user' => [
                    'email' => 'john@example.com',
                ],
            ]);

        // Verify token was created
        $this->assertNotNull($response->json('token'));
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
}

