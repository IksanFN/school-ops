<?php 

namespace App\Exceptions;

use Exception;
use Illuminate\Support\Arr;

class ValidationException extends Exception
{
    protected array $errors;

    public function __construct($message = 'Validation failed', array $errors = [], $code = 422)
    {
        parent::__construct($message, $code);
        $this->errors = $errors;
    }

    public function getErrors()
    {
        return $this->errors;
    }

    public static function withErrors(array $errors)
    {
        return new self('Validation failed', $errors, 422);
    }
}