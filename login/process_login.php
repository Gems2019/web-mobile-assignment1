<?php session_start(); ?>

<!-- Require Database Connection -->
<?php require_once "../inc_db_params.php"; ?>

<?php
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $email = trim($_POST["email"]);
    $password = $_POST["password"];

    try {
        $db = new PDO("sqlite:../blog3795.sqlite");
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
                header("Location: login.php");
                exit();
            }
        } else {
            // Invalid credentials
            $_SESSION['error'] = "Invalid email or password.";
            header("Location: login.php");
            exit();
        }
    } catch (PDOException $e) {
        $_SESSION['error'] = "Database error: " . $e->getMessage();
        header("Location: login.php");
        exit();
    }
} else {
    header("Location: login.php");
    exit();
}
?>