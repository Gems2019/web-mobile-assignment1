<?php

function sanitize_input($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $data;
}

?>

<!-- Validate Password: Used in process-register.php -->
<?php
function validate_password($password, &$error_message) 
{
    // Check if password is not empty
    if (empty($password))
    {
        $error_message = "Password must not be empty.";
        return false;
    }

    // Min length 
    if (strlen($password) < 8)
    {
        $error_message = "Password must be atleast 8 characters long.";
        return false;
    }

    // At least one lowercase letter
    if (!preg_match('/[a-z]/', $password)) 
    {
        $error_message = "Password must contain at least one lowercase letter (a-z).";
        return false;
    }

    // At least one uppercase letter
    if (!preg_match('/[A-Z]/', $password)) 
    {
        $error_message = "Password must contain at least one uppercase letter (A-Z).";
        return false;
    }

    // At least one numeric digit
    if (!preg_match('/\d/', $password)) 
    {
        $error_message = "Password must contain at least one number (0-9).";
        return false;
    }

    // At least one special character
    if (!preg_match('/[\W_]/', $password)) 
    {
        $error_message = "Password must contain at least one special character (e.g., !@#$%^&*).";
        return false;
    }

    // Valid
    $error_message = "";
    return true;
}
?>

<!-- Validate Email: Used in process-register.php -->
<?php
function is_valid_email($email, &$error_message) 
{
    // Email is empty
    if (empty($email)) 
    {
        $error_message = "Email cannot be empty.";
        return false;
    }

    // Email format
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) 
    {
        $error_message = "Invalid email format. Please enter a valid email (e.g., name@example.com).";
        return false;
    }

    // Email is valid
    $error_message = "";
    return true;
}
?>

<?php

?>
