<?php

namespace App\Helpers;

use Illuminate\Http\JsonResponse;

class ResponseHelper
{
    public static function success($data = null, string $message = 'Success', int $statusCode = 200): JsonResponse
    {
        return response()->json([
            'success' => true,
            'message' => $message,
            'data' => $data,
        ], $statusCode);
    }

    public static function error(string $message = 'Error', $errors = null, int $statusCode = 400): JsonResponse
    {
        $response = [
            'success' => false,
            'message' => $message,
        ];

        if (!is_null($errors)) {
            $response['errors'] = $errors;
        }

        return response()->json($response, $statusCode);
    }

    public static function validationError($errors, string $message = 'Validation Error'): JsonResponse
    {
        return response()->json([
            'success' => false,
            'message' => $message,
            'errors' => $errors
        ], 422);
    }

    public static function unauthorized(string $message = 'Unauthorized'): JsonResponse
    {
        return response()->json([
            'success' => false,
            'message' => $message
        ], 401);
    }

    public static function notFound(string $message = 'Data not found'): JsonResponse
    {
        return response()->json([
            'success' => false,
            'message' => $message
        ], 404);
    }
}