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

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $email = trim($_POST["email"]);
    $password = $_POST["password"];

    try {
        $db = new PDO("sqlite:" . __DIR__ . "/../blog3795.sqlite");
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Fetch user by email - now including role and isApproved
        $stmt = $db->prepare("SELECT id, password, role, isApproved, firstName, lastName FROM Users WHERE username = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            // Check if user is admin or approved
            if (strtolower($user['role']) === 'admin' || $user['isApproved']) {
                $_SESSION['user_id']   = $user['id'];
                $_SESSION['username']  = $email;
                $_SESSION['role']      = $user['role'];
                $_SESSION['firstName'] = $user['firstName'];
                $_SESSION['lastName']  = $user['lastName'];
                header("Location: ../main.php");
                exit();
            } else {
                $_SESSION['error'] = "Your account is pending approval.";
                header("Location: /login/login.php"); // Use absolute paths
                exit();
            }
        } else {
            // Invalid credentials
            $_SESSION['error'] = "Invalid email or password.";
            header("Location: /login/login.php"); // Use absolute paths
            exit();
        }
    } catch (PDOException $e) {
        $_SESSION['error'] = "Database error: " . $e->getMessage();
        header("Location: /login/login.php"); // Use absolute paths
        exit();
    }
} else {
    header("Location: /login/login.php"); // Use absolute paths
    exit();
}
?>