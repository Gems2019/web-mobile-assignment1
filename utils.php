<?php

function sanitize_input($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $data;
}

function validate_password($password, &$error_message) {
    if (empty($password)) {
        $error_message = "Password must not be empty.";
        return false;
    }

    if (strlen($password) < 8) {
        $error_message = "Password must be atleast 8 characters long.";
        return false;
    }

    if (!preg_match('/[a-z]/', $password)) {
        $error_message = "Password must contain at least one lowercase letter (a-z).";
        return false;
    }

    if (!preg_match('/[A-Z]/', $password)) {
        $error_message = "Password must contain at least one uppercase letter (A-Z).";
        return false;
    }

    if (!preg_match('/\d/', $password)) {
        $error_message = "Password must contain at least one number (0-9).";
        return false;
    }

    if (!preg_match('/[\W_]/', $password)) {
        $error_message = "Password must contain at least one special character (e.g., !@#$%^&*).";
        return false;
    }

    $error_message = "";
    return true;
}

function is_valid_email($email, &$error_message) {
    if (empty($email)) {
        $error_message = "Email cannot be empty.";
        return false;
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error_message = "Invalid email format. Please enter a valid email (e.g., name@example.com).";
        return false;
    }

    $error_message = "";
    return true;
}
?>