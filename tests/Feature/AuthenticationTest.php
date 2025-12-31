<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Foundation\Testing\WithFaker;
use Tests\TestCase;

class AuthenticationTest extends TestCase
{
    use RefreshDatabase, WithFaker;

    /**
     * Test successful user registration.
     */
    public function test_register_with_valid_data(): void
    {
        $userData = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password' => 'password123',
            'password_confirmation' => 'password123',
        ];

        $response = $this->postJson('/api/register', $userData);

        $response->assertStatus(201)
            ->assertJsonStructure([
                'success',
                'message',
                'data' => [
                    'user' => [
                        'id',
                        'name',
                        'email',
                        'created_at',
                        'updated_at',
                    ],
                    'token',
                ],
            ])
            ->assertJson([
                'success' => true,
                'message' => 'User registered successfully',
            ]);

        $this->assertDatabaseHas('users', [
            'email' => 'john@example.com',
            'name' => 'John Doe',
        ]);
    }

    /**
     * Test registration validation - name required.
     */
    public function test_register_validation_name_required(): void
    {
        $userData = [
            'email' => 'john@example.com',
            'password' => 'password123',
            'password_confirmation' => 'password123',
        ];

        $response = $this->postJson('/api/register', $userData);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['name']);
    }

    /**
     * Test registration validation - email required.
     */
    public function test_register_validation_email_required(): void
    {
        $userData = [
            'name' => 'John Doe',
            'password' => 'password123',
            'password_confirmation' => 'password123',
        ];

        $response = $this->postJson('/api/register', $userData);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /**
     * Test registration validation - email format.
     */
    public function test_register_validation_email_format(): void
    {
        $userData = [
            'name' => 'John Doe',
            'email' => 'invalid-email',
            'password' => 'password123',
            'password_confirmation' => 'password123',
        ];

        $response = $this->postJson('/api/register', $userData);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /**
     * Test registration validation - password required.
     */
    public function test_register_validation_password_required(): void
    {
        $userData = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
        ];

        $response = $this->postJson('/api/register', $userData);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['password']);
    }

    /**
     * Test registration validation - password minimum length.
     */
    public function test_register_validation_password_min_length(): void
    {
        $userData = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password' => '123',
            'password_confirmation' => '123',
        ];

        $response = $this->postJson('/api/register', $userData);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['password']);
    }

    /**
     * Test registration with duplicate email.
     */
    public function test_register_with_duplicate_email(): void
    {
        // Create existing user
        User::factory()->create([
            'email' => 'john@example.com',
        ]);

        $userData = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password' => 'password123',
            'password_confirmation' => 'password123',
        ];

        $response = $this->postJson('/api/register', $userData);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /**
     * Test successful login with valid credentials.
     */
    public function test_login_with_valid_credentials(): void
    {
        $user = User::factory()->create([
            'email' => 'john@example.com',
            'password' => bcrypt('password123'),
        ]);

        $loginData = [
            'email' => 'john@example.com',
            'password' => 'password123',
        ];

        $response = $this->postJson('/api/login', $loginData);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'message',
                'data' => [
                    'user' => [
                        'id',
                        'name',
                        'email',
                        'created_at',
                        'updated_at',
                    ],
                    'token',
                ],
            ])
            ->assertJson([
                'success' => true,
                'message' => 'User logged in successfully',
            ]);
    }

    /**
     * Test login with invalid email.
     */
    public function test_login_with_invalid_email(): void
    {
        User::factory()->create([
            'email' => 'john@example.com',
            'password' => bcrypt('password123'),
        ]);

        $loginData = [
            'email' => 'wrong@example.com',
            'password' => 'password123',
        ];

        $response = $this->postJson('/api/login', $loginData);

        $response->assertStatus(401)
            ->assertJson([
                'success' => false,
            ]);
    }

    /**
     * Test login with invalid password.
     */
    public function test_login_with_invalid_password(): void
    {
        User::factory()->create([
            'email' => 'john@example.com',
            'password' => bcrypt('password123'),
        ]);

        $loginData = [
            'email' => 'john@example.com',
            'password' => 'wrongpassword',
        ];

        $response = $this->postJson('/api/login', $loginData);

        $response->assertStatus(401)
            ->assertJson([
                'success' => false,
            ]);
    }

    /**
     * Test login validation - required fields.
     */
    public function test_login_validation_required_fields(): void
    {
        $response = $this->postJson('/api/login', []);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email', 'password']);
    }

    /**
     * Test successful logout.
     */
    public function test_logout_successfully(): void
    {
        $user = User::factory()->create();
        $token = $user->createToken('test-token');

        $response = $this->actingAs($user, 'sanctum')
            ->postJson('/api/logout');

        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'message' => 'User logged out successfully',
            ]);

        // Verify token is deleted
        $this->assertDatabaseMissing('personal_access_tokens', [
            'id' => $token->accessToken->id,
        ]);
    }

    /**
     * Test logout without authentication.
     */
    public function test_logout_without_authentication(): void
    {
        $response = $this->postJson('/api/logout');

        $response->assertStatus(401)
            ->assertJson([
                'message' => 'Unauthenticated.',
            ]);
    }

    /**
     * Test logout with invalid token.
     */
    public function test_logout_with_invalid_token(): void
    {
        $response = $this->withHeader('Authorization', 'Bearer invalid-token')
            ->postJson('/api/logout');

        $response->assertStatus(401)
            ->assertJson([
                'message' => 'Unauthenticated.',
            ]);
    }

    /**
     * Test refresh token successfully.
     */
    public function test_refresh_token_successfully(): void
    {
        $user = User::factory()->create();
        $token = $user->createToken('test-token');

        $response = $this->actingAs($user, 'sanctum')
            ->postJson('/api/refresh');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'message',
                'data' => [
                    'token',
                ],
            ])
            ->assertJson([
                'success' => true,
                'message' => 'Token refreshed successfully',
            ]);
    }

    /**
     * Test refresh token without authentication.
     */
    public function test_refresh_token_without_authentication(): void
    {
        $response = $this->postJson('/api/refresh');

        $response->assertStatus(401)
            ->assertJson([
                'message' => 'Unauthenticated.',
            ]);
    }

    /**
     * Test refresh token with invalid token.
     */
    public function test_refresh_token_with_invalid_token(): void
    {
        $response = $this->withHeader('Authorization', 'Bearer invalid-token')
            ->postJson('/api/refresh');

        $response->assertStatus(401)
            ->assertJson([
                'message' => 'Unauthenticated.',
            ]);
    }

    /**
     * Test get authenticated user successfully.
     */
    public function test_get_authenticated_user_successfully(): void
    {
        $user = User::factory()->create([
            'name' => 'John Doe',
            'email' => 'john@example.com',
        ]);
        $token = $user->createToken('test-token')->plainTextToken;

        $response = $this->withHeader('Authorization', 'Bearer ' . $token)
            ->getJson('/api/me');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'message',
                'data' => [
                    'user' => [
                        'id',
                        'name',
                        'email',
                        'created_at',
                        'updated_at',
                    ],
                ],
            ])
            ->assertJson([
                'success' => true,
                'message' => 'User retrieved successfully',
                'data' => [
                    'user' => [
                        'name' => 'John Doe',
                        'email' => 'john@example.com',
                    ],
                ],
            ]);
    }

    /**
     * Test get user without authentication.
     */
    public function test_get_user_without_authentication(): void
    {
        $response = $this->getJson('/api/me');

        $response->assertStatus(401)
            ->assertJson([
                'message' => 'Unauthenticated.',
            ]);
    }

    /**
     * Test get user with invalid token.
     */
    public function test_get_user_with_invalid_token(): void
    {
        $response = $this->withHeader('Authorization', 'Bearer invalid-token')
            ->getJson('/api/me');

        $response->assertStatus(401)
            ->assertJson([
                'message' => 'Unauthenticated.',
            ]);
    }
}
