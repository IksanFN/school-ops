<?php

namespace App\Exceptions;

use Exception;

class AuthException extends Exception
{
    public static function invalidCredentials()
    {
        return new self('The provided credentials are incorrect.', 401);
    }

    public static function userNotFound()
    {
        return new self('User not found', 404);
    }

    public static function tokenExpired()
    {
        return new self('Token has expired', 401);
    }

    public static function unauthorized()
    {
        return new self('Unauthorized', 401);
    }
}