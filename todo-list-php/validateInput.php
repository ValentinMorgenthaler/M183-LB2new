<?php
function sanitizeAndvalidateInput($input) {
    // Trim whitespace, remove HTML tags, and encode special characters
    $sanitized = htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES, 'UTF-8');
    
    // Validate string length (for example, title should be between 1 and 50 characters)
    if (strlen($sanitized) < 1 || strlen($sanitized) > 50) {
        die("Input must be between 1 and 50 characters.");
    }
    
    // Validate that the string only contains allowed characters
    // This allows letters, numbers, spaces, and basic punctuation
    if (!preg_match('/^[a-zA-Z0-9\s\-\_\.]+$/', $sanitized)) {
        die("Input contains invalid characters.");
    }

    return $sanitized;
}

function validateUsername($username) {
    // Trim whitespace from the beginning and end
    $username = trim($username);

    // Ensure username length is between 3 and 30 characters
    if (strlen($username) < 3 || strlen($username) > 30) {
        die("Username must be between 3 and 30 characters.");
    }

    // Allow only letters, numbers, underscore (_), hyphen (-), and dot (.)
    if (!preg_match('/^[a-zA-Z0-9._-]+$/', $username)) {
        die("Username can only contain letters, numbers, '_', '-', or '.'");
    }

    return $username;
}

function validatePassword($password) {
    // Trim whitespace from the beginning and end
    $password = trim($password);

    // Ensure password length is between 8 and 64 characters
    if (strlen($password) < 8 || strlen($password) > 64) {
        die("Password must be between 8 and 64 characters.");
    }

    // Require at least one uppercase letter, one lowercase letter, one number, and one special character
    if (!preg_match('/[A-Z]/', $password) ||  // At least one uppercase letter
        !preg_match('/[a-z]/', $password) ||  // At least one lowercase letter
        !preg_match('/[0-9]/', $password) ||  // At least one number
        !preg_match('/[\W]/', $password)) {   // At least one special character
        die("Password must include at least one uppercase letter, one lowercase letter, one number, and one special character.");
    }

    return $password;
}
?>