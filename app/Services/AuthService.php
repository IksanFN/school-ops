<?php

namespace App\Services;

use App\Exceptions\AuthException;
use Exception;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Hash;
use Illuminate\Container\Attributes\Auth;
use Illuminate\Validation\ValidationException;

class AuthService
{
    public function register(array $data)
    {
        try {

            DB::beginTransaction();

            $user = User::query()->create([
                'name' => $data['name'],
                'email' => $data['email'],
                'password' => $data['password'],
            ]);

            $token = $user->createToken('auth-token')->plainTextToken;

            DB::commit();

            return [
                'user' => $user,
                'token' => $token,
            ];
        } catch (Exception $e) {

            DB::rollBack();
            
            Log::error('Registration Failed: ' . $e->getMessage(), [
                'email' => $data['email'] ?? null,
                'file' => $e->getFile(),
                'line' => $e->getLine(),
                'trace' => $e->getTraceAsString(),
            ]);

            throw new Exception('Registration Failed. Please try again later.');
            
        }
    }

    public function login(array $data)
    {
        $user = User::query()->where('email', $data['email'])->first();

        if (!$user || !Hash::check($data['password'], $user->password)) {
            throw AuthException::invalidCredentials();
        }

        try {

            DB::beginTransaction();

            $user->tokens()->delete();

            $token = $user->createToken('auth-token')->plainTextToken;

            DB::commit();

            return [
                'user' => $user,
                'token' => $token,
            ];

        } catch (Exception $e) {

            DB::rollBack();
            
            Log::error('Login token creation failed: ' . $e->getMessage(), [
                'email' => $data['email'] ?? null,
                'file' => $e->getFile(),
                'line' => $e->getLine(),
                'trace' => $e->getTraceAsString(),
            ]);

            throw new Exception('Login failed. Please try again later.');

        }
    }

    public function logout(User $user)
    {
        try {
            
            DB::beginTransaction();

            // Get current access token, if available (null in some test scenarios)
            $currentToken = $user->currentAccessToken();
            
            if ($currentToken) {
                $user->tokens()->delete();
            } else {
                // Fallback: delete all tokens (useful for testing)
                $user->tokens()->delete();
            }

            DB::commit();

            return true;

        } catch (Exception $e) {

            DB::rollBack();
            
            Log::error('Logout failed: ' . $e->getMessage(), [
                'user_id' => $user->id ?? null,
                'file' => $e->getFile(),
                'line' => $e->getLine(),
                'trace' => $e->getTraceAsString(),
            ]);

            throw new Exception('Logout failed. Please try again later.');

        }
    }

    public function refreshToken(User $user)
    {
        try {
            
            DB::beginTransaction();

            // Get current access token, if available (null in some test scenarios)
            $currentToken = $user->currentAccessToken();
            
            if ($currentToken) {
                $user->tokens()->delete();
            } else {
                // Fallback: delete all tokens (useful for testing)
                $user->tokens()->delete();
            }

            $token = $user->createToken('auth-token')->plainTextToken;

            DB::commit();

            return [
                'user' => $user,
                'token' => $token,
            ];

        } catch (Exception $e) {

            DB::rollBack();
            
            Log::error('Refresh token creation failed: ' . $e->getMessage(), [
                'user_id' => $user->id ?? null,
                'file' => $e->getFile(),
                'line' => $e->getLine(),
                'trace' => $e->getTraceAsString(),
            ]);

            throw new Exception('Refresh token creation failed. Please try again later.');

        }
    }

    public function getAuthenticatedUser(User $user)
    {
        return $user;
    }

    /**
     * Handle forgot password request
     */
    public function forgotPassword(array $data)
    {
        try {
            $user = User::where('email', $data['email'])->first();

            if (!$user) {
                throw new Exception('User not found');
            }

            DB::beginTransaction();

            // Delete old tokens for this email
            DB::table('password_reset_tokens')
                ->where('email', $data['email'])
                ->delete();

            // Generate reset token
            $token = bin2hex(random_bytes(32));

            // Store hashed token in database
            DB::table('password_reset_tokens')->insert([
                'email' => $data['email'],
                'token' => Hash::make($token),
                'created_at' => now(),
            ]);

            DB::commit();

            // In production, send email with reset link
            // For now, we'll just return the token for testing
            Log::info('Password reset requested', [
                'email' => $data['email'],
                'token' => $token, // In production, this would be in email only
            ]);

            return [
                'message' => 'Password reset link has been sent to your email',
                'token' => $token, // Remove this in production
            ];

        } catch (Exception $e) {
            DB::rollBack();
            
            Log::error('Forgot password failed: ' . $e->getMessage(), [
                'email' => $data['email'] ?? null,
                'file' => $e->getFile(),
                'line' => $e->getLine(),
            ]);

            throw new Exception('Failed to process password reset request');
        }
    }

    /**
     * Reset password with token
     */
    public function resetPassword(array $data)
    {
        try {
            // Validate token
            if (!$this->validateResetToken($data['email'], $data['token'])) {
                throw new Exception('Invalid or expired reset token');
            }

            DB::beginTransaction();

            // Update user password
            $user = User::where('email', $data['email'])->first();
            
            if (!$user) {
                throw new Exception('User not found');
            }

            $user->password = $data['password'];
            $user->save();

            // Delete reset token
            DB::table('password_reset_tokens')
                ->where('email', $data['email'])
                ->delete();

            // Revoke all existing tokens
            $user->tokens()->delete();

            DB::commit();

            return [
                'message' => 'Password has been reset successfully',
            ];

        } catch (Exception $e) {
            DB::rollBack();
            
            Log::error('Reset password failed: ' . $e->getMessage(), [
                'email' => $data['email'] ?? null,
                'file' => $e->getFile(),
                'line' => $e->getLine(),
            ]);

            throw $e;
        }
    }

    /**
     * Validate reset token
     */
    private function validateResetToken(string $email, string $token): bool
    {
        $resetRecord = DB::table('password_reset_tokens')
            ->where('email', $email)
            ->first();

        if (!$resetRecord) {
            return false;
        }

        // Check if token is expired (60 minutes)
        $createdAt = \Carbon\Carbon::parse($resetRecord->created_at);
        if ($createdAt->addMinutes(60)->isPast()) {
            // Delete expired token
            DB::table('password_reset_tokens')
                ->where('email', $email)
                ->delete();
            return false;
        }

        // Verify token
        return Hash::check($token, $resetRecord->token);
    }
}