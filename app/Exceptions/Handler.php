<?php

namespace App\Exceptions;

use Throwable;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Illuminate\Foundation\Exceptions\Handler as ExceptionsHandler;

class Handler extends ExceptionsHandler
{
    protected $levels = [];

    protected $dontReport = [];

    protected $dontFlash = [
        'current_password',
        'password',
        'password_confirmation',
    ];

    public function register()
    {
        $this->reportable(function (Throwable $e) {
            //
        });

        // Handle Custom AuthException
        $this->renderable(function (AuthException $e, $request) {
            if ($request->expectsJson()) {
                return response()->json([
                    'success' => false,
                    'message' => $e->getMessage(),
                ], $e->getCode() ?? 500);
            }
        });

        $this->renderable(function (ValidationException $e, $request) {
            if ($request->expectsJson()) {
                return response()->json([
                    'success' => false,
                    'message' => 'Validation failed',
                    'errors' => $e->getErrors(),
                ], $e->getCode() ?? 422);
            }
        });

        // Handle AuthenticationException
        $this->renderable(function (AuthenticationException $e, $request) {
            if ($request->expectsJson()) {
                return response()->json([
                    'success' => false,
                    'message' => 'Unauthorized',
                ], 401);
            }
        });

        // Handle Model Not Found Exception
        $this->renderable(function (ModelNotFoundException $e, $request) {
            if ($request->expectsJson()) {
                return response()->json([
                    'success' => false,
                    'message' => 'Resource not found',
                ], 404);
            }
        });

        // Handle Route Not Found Exception
        $this->renderable(function (NotFoundHttpException $e, $request) {
            if ($request->expectsJson()) {
                return response()->json([
                    'success' => false,
                    'message' => 'Route not found',
                ], 404);
            }
        });

        $this->renderable(function (\Throwable $e, $request) {
            if ($request->expectsJson() && !config('app.debug')) {
                return response()->json([
                    'success' => false,
                    'message' => 'An error occurred. Please try again later.',
                ], 500);
            }
        });
    }
}
