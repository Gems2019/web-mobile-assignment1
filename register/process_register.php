<?php
session_start();
require_once "../inc_db_params.php";
require_once "../utils.php";

if (isset($_SESSION['username'])) {
    $_SESSION['error'] = "You're already signed in, please log out first";
    header("Location: ../index.php");
    exit();
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $email = trim($_POST["email"]);
    $password = $_POST["password"];
    $first_name = trim($_POST["first_name"]);
    $last_name = trim($_POST["last_name"]);
    $error_message = "";

    if (!is_valid_email($email, $error_message)) {
        $_SESSION['error'] = $error_message;
        header("Location: register.php");
        exit();
    }

    if (!validate_password($password, $error_message)) {
        $_SESSION['error'] = $error_message;
        header("Location: register.php");
        exit();
    }

    $hashed_password = password_hash($password, PASSWORD_BCRYPT);

    try {
        $db = new PDO("sqlite:../blog3795.sqlite");
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $db->prepare("SELECT COUNT(*) FROM users WHERE username = ?");
        $stmt->execute([$email]);
        if ($stmt->fetchColumn() > 0) {
            $_SESSION['error'] = "Email is already registered.";
            header("Location: register.php");
            exit();
        }

        $stmt = $db->prepare("INSERT INTO users (username, password, firstName, lastName, registrationDate, isApproved, role) VALUES (?, ?, ?, ?, datetime('now'), 0, 'contributor')");
        $stmt->execute([$email, $hashed_password, $first_name, $last_name]);

        $_SESSION['message'] = "Registration successful! Waiting for admin approval.";
        header("Location: ../login/login.php");
        exit();
    } catch (PDOException $e) {
        $_SESSION['error'] = "Database error: " . $e->getMessage();
        header("Location: register.php");
        exit();
    }
} else {
    header("Location: register.php");
    exit();
}
?>