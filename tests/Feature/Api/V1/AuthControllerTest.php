<?php

namespace Tests\Feature\Api\V1;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use App\Notifications\ResetPasswordNotification;
use Laravel\Sanctum\Sanctum;
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
}

