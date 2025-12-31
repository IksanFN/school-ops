<?php

namespace App\Http\Controllers\Api;

use App\Exceptions\AuthException;
use App\Traits\ApiResponse;
use Illuminate\Http\Request;
use App\Services\AuthService;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use App\Http\Requests\Auth\LoginRequest;
use App\Http\Requests\Auth\RegisterRequest;
use App\Http\Requests\Auth\ForgotPasswordRequest;
use App\Http\Requests\Auth\ResetPasswordRequest;
use Exception;

class AuthController extends Controller
{
    use ApiResponse;
    protected $authService;

    public function __construct(AuthService $authService)
    {
        $this->authService = $authService;
    }

    public function register(RegisterRequest $request)
    {
        try {

            $result = $this->authService->register($request->validated());

            return $this->successResponse($result, 'User registered successfully', 201);

        } catch (Exception $e) {

            // Friendly error message
            return $this->errorResponse($e->getMessage(), 500);

        }
    }

    public function login(LoginRequest $request)
    {
        try {

            $result = $this->authService->login($request->validated());

            $user = $result['user'];
            $token = $result['token'];

            return $this->successResponse([
                'user' => $user,
                'token' => $token,
            ], 'User logged in successfully', 200);

        } catch (AuthException $e) {

            return $this->errorResponse($e->getMessage(), $e->getCode());

        } catch (Exception $e) {

            return $this->errorResponse('An error occurred during login', 500);

        }
    }

    public function logout(Request $request)
    {
        try {

            $result = $this->authService->logout($request->user());

            return $this->successResponse(null, 'User logged out successfully', 200);

        } catch (Exception $e) {

            return $this->errorResponse($e->getMessage(), $e->getCode());

        }
    }

    public function refreshToken()
    {
        try {

            $result = $this->authService->refreshToken(Auth::user());

            return $this->successResponse($result, 'Token refreshed successfully', 200);

        } catch (Exception $e) {

            return $this->errorResponse($e->getMessage(), $e->getCode());

        }
    }

    public function me(Request $request)
    {
        try {

            $result = $this->authService->getAuthenticatedUser($request->user());

            return $this->successResponse(['user' => $result], 'User retrieved successfully', 200);

        } catch (Exception $e) {

            return $this->errorResponse('Failed to retrieve user', 500);

        }
    }

    public function forgotPassword(ForgotPasswordRequest $request)
    {
        try {

            $result = $this->authService->forgotPassword($request->validated());

            return $this->successResponse($result, 'Password reset link sent successfully', 200);

        } catch (Exception $e) {

            return $this->errorResponse($e->getMessage(), 500);

        }
    }

    public function resetPassword(ResetPasswordRequest $request)
    {
        try {

            $result = $this->authService->resetPassword($request->validated());

            return $this->successResponse($result, 'Password reset successfully', 200);

        } catch (Exception $e) {

            return $this->errorResponse($e->getMessage(), 400);

        }
    }
}
