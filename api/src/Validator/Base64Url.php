<?php

declare(strict_types=1);

namespace App\Validator;

use Symfony\Component\Validator\Constraint;

#[\Attribute]
class Base64Url extends Constraint
{
    public string $message = 'The string "{{ string }}" is not valid base64 URL.';
}
