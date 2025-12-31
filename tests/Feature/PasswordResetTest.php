<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Foundation\Testing\WithFaker;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Tests\TestCase;

class PasswordResetTest extends TestCase
{
    use RefreshDatabase, WithFaker;

    /**
     * Test forgot password with valid email.
     */
    public function test_forgot_password_with_valid_email(): void
    {
        $user = User::factory()->create([
            'email' => 'test@example.com',
        ]);

        $response = $this->postJson('/api/forgot-password', [
            'email' => 'test@example.com',
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'message',
                'data' => [
                    'message',
                    'token', // For testing only
                ],
            ])
            ->assertJson([
                'success' => true,
            ]);

        // Verify token was created in database
        $this->assertDatabaseHas('password_reset_tokens', [
            'email' => 'test@example.com',
        ]);
    }

    /**
     * Test forgot password with non-existent email.
     */
    public function test_forgot_password_with_nonexistent_email(): void
    {
        $response = $this->postJson('/api/forgot-password', [
            'email' => 'nonexistent@example.com',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /**
     * Test forgot password validation - email required.
     */
    public function test_forgot_password_validation_email_required(): void
    {
        $response = $this->postJson('/api/forgot-password', []);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /**
     * Test forgot password validation - email format.
     */
    public function test_forgot_password_validation_email_format(): void
    {
        $response = $this->postJson('/api/forgot-password', [
            'email' => 'invalid-email',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /**
     * Test reset password with valid token.
     */
    public function test_reset_password_with_valid_token(): void
    {
        $user = User::factory()->create([
            'email' => 'test@example.com',
            'password' => bcrypt('oldpassword'),
        ]);

        // Generate reset token
        $token = bin2hex(random_bytes(32));
        DB::table('password_reset_tokens')->insert([
            'email' => 'test@example.com',
            'token' => Hash::make($token),
            'created_at' => now(),
        ]);

        $response = $this->postJson('/api/reset-password', [
            'email' => 'test@example.com',
            'token' => $token,
            'password' => 'newpassword123',
            'password_confirmation' => 'newpassword123',
        ]);

        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'message' => 'Password reset successfully',
            ]);

        // Verify password was updated
        $user->refresh();
        $this->assertTrue(Hash::check('newpassword123', $user->password));

        // Verify token was deleted
        $this->assertDatabaseMissing('password_reset_tokens', [
            'email' => 'test@example.com',
        ]);
    }

    /**
     * Test reset password with invalid token.
     */
    public function test_reset_password_with_invalid_token(): void
    {
        $user = User::factory()->create([
            'email' => 'test@example.com',
        ]);

        $response = $this->postJson('/api/reset-password', [
            'email' => 'test@example.com',
            'token' => 'invalid-token',
            'password' => 'newpassword123',
            'password_confirmation' => 'newpassword123',
        ]);

        $response->assertStatus(400)
            ->assertJson([
                'success' => false,
            ]);
    }

    /**
     * Test reset password with expired token.
     */
    public function test_reset_password_with_expired_token(): void
    {
        $user = User::factory()->create([
            'email' => 'test@example.com',
        ]);

        // Generate reset token that's expired (>60 minutes)
        $token = bin2hex(random_bytes(32));
        DB::table('password_reset_tokens')->insert([
            'email' => 'test@example.com',
            'token' => Hash::make($token),
            'created_at' => now()->subMinutes(61), // 61 minutes ago
        ]);

        $response = $this->postJson('/api/reset-password', [
            'email' => 'test@example.com',
            'token' => $token,
            'password' => 'newpassword123',
            'password_confirmation' => 'newpassword123',
        ]);

        $response->assertStatus(400)
            ->assertJson([
                'success' => false,
            ]);
    }

    /**
     * Test reset password with mismatched email.
     */
    public function test_reset_password_with_mismatched_email(): void
    {
        $user = User::factory()->create([
            'email' => 'test@example.com',
        ]);

        // Generate reset token for test@example.com
        $token = bin2hex(random_bytes(32));
        DB::table('password_reset_tokens')->insert([
            'email' => 'test@example.com',
            'token' => Hash::make($token),
            'created_at' => now(),
        ]);

        // Try to reset with different email
        $response = $this->postJson('/api/reset-password', [
            'email' => 'different@example.com',
            'token' => $token,
            'password' => 'newpassword123',
            'password_confirmation' => 'newpassword123',
        ]);

        $response->assertStatus(400)
            ->assertJson([
                'success' => false,
            ]);
    }

    /**
     * Test reset password validation - all fields required.
     */
    public function test_reset_password_validation_required_fields(): void
    {
        $response = $this->postJson('/api/reset-password', []);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email', 'token', 'password']);
    }

    /**
     * Test reset password validation - password minimum length.
     */
    public function test_reset_password_validation_password_min_length(): void
    {
        $response = $this->postJson('/api/reset-password', [
            'email' => 'test@example.com',
            'token' => 'some-token',
            'password' => '123',
            'password_confirmation' => '123',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['password']);
    }

    /**
     * Test reset password validation - password confirmation.
     */
    public function test_reset_password_validation_password_confirmation(): void
    {
        $response = $this->postJson('/api/reset-password', [
            'email' => 'test@example.com',
            'token' => 'some-token',
            'password' => 'newpassword123',
            'password_confirmation' => 'differentpassword',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['password']);
    }

    /**
     * Test that old tokens are deleted when requesting new reset.
     */
    public function test_forgot_password_deletes_old_tokens(): void
    {
        $user = User::factory()->create([
            'email' => 'test@example.com',
        ]);

        // Create old token
        $oldToken = bin2hex(random_bytes(32));
        DB::table('password_reset_tokens')->insert([
            'email' => 'test@example.com',
            'token' => Hash::make($oldToken),
            'created_at' => now()->subMinutes(30),
        ]);

        // Request new reset
        $response = $this->postJson('/api/forgot-password', [
            'email' => 'test@example.com',
        ]);

        $response->assertStatus(200);

        // Verify old token was replaced (only one token exists)
        $tokenCount = DB::table('password_reset_tokens')
            ->where('email', 'test@example.com')
            ->count();

        $this->assertEquals(1, $tokenCount);
    }

    /**
     * Test that all user tokens are revoked after password reset.
     */
    public function test_reset_password_revokes_all_tokens(): void
    {
        $user = User::factory()->create([
            'email' => 'test@example.com',
            'password' => bcrypt('oldpassword'),
        ]);

        // Create some auth tokens
        $user->createToken('device-1');
        $user->createToken('device-2');

        $this->assertEquals(2, $user->tokens()->count());

        // Generate reset token
        $token = bin2hex(random_bytes(32));
        DB::table('password_reset_tokens')->insert([
            'email' => 'test@example.com',
            'token' => Hash::make($token),
            'created_at' => now(),
        ]);

        // Reset password
        $response = $this->postJson('/api/reset-password', [
            'email' => 'test@example.com',
            'token' => $token,
            'password' => 'newpassword123',
            'password_confirmation' => 'newpassword123',
        ]);

        $response->assertStatus(200);

        // Verify all tokens were revoked
        $user->refresh();
        $this->assertEquals(0, $user->tokens()->count());
    }
}
