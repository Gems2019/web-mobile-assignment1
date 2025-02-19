<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
error_log("Session path: " . session_save_path());
error_log("Database path: " . __DIR__ . "/../blog3795.sqlite");

// Set session save path explicitly
$sessionPath = sys_get_temp_dir();
if (!is_writable($sessionPath)) {
    $sessionPath = __DIR__ . '/../temp';
    if (!file_exists($sessionPath)) {
        mkdir($sessionPath, 0777, true);
    }
}
session_save_path($sessionPath);
session_start();

require_once "../inc_db_params.php";
require_once "../utils.php";

// Prevent direct access if already logged in
if (isset($_SESSION['username'])) {
    $_SESSION['error'] = "You're already signed in, please log out first";
    header("Location: ../index.php");
    exit();
}

// Process registration form submission
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $email = trim($_POST["email"]);
    $password = $_POST["password"];
    $first_name = trim($_POST["first_name"]);
    $last_name = trim($_POST["last_name"]);
    $error_message = "";

    // Validate email and password
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

    try {
        $db = new PDO("sqlite:../blog3795.sqlite");
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if email already exists
        $stmt = $db->prepare("SELECT COUNT(*) FROM Users WHERE username = ?");
        $stmt->execute([$email]);
        if ($stmt->fetchColumn() > 0) {
            $_SESSION['error'] = "Email is already registered.";
            header("Location: register.php");
            exit();
        }

        // Insert new user
        $hashed_password = password_hash($password, PASSWORD_BCRYPT);
        $stmt = $db->prepare("INSERT INTO Users (username, password, firstName, lastName, registrationDate, isApproved, role) VALUES (?, ?, ?, ?, datetime('now'), 0, 'Contributor')");
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