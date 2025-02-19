<?php
session_start();
require_once "../../inc_db_params.php";

if (!isset($_SESSION['username'])) {
    header("Location: ../../login/login.php");
    exit();
}

// Handle form submission
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST['create'])) {
    try {
        $db = new PDO("sqlite:" . __DIR__ . "/../../blog3795.sqlite");
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if the Articles table exists
        $table_check = $db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='Articles'")->fetch();
        if (!$table_check) {
            $_SESSION['error'] = "Error: The 'Articles' table does not exist!";
            header("Location: create.php");
            exit();
        }

        // Retrieve the logged-in contributor's username and form data
        $contributorUsername = $_SESSION['username'];
        $title = trim($_POST['Title']);
        $body = trim($_POST['Body']);
        $startDate = $_POST['StartDate'];
        $endDate = $_POST['EndDate'];

        // Prepare and execute INSERT statement
        $stmt = $db->prepare("
            INSERT INTO Articles (Title, Body, StartDate, EndDate, ContributorUsername) 
            VALUES (?, ?, ?, ?, ?)
        ");
        
        $stmt->execute([$title, $body, $startDate, $endDate, $contributorUsername]);

        $_SESSION['message'] = "Article created successfully.";
        header("Location: ../../main.php");
        exit();

    } catch (PDOException $e) {
        $_SESSION['error'] = "Database error: " . $e->getMessage();
        header("Location: create.php");
        exit();
    }
} else {
    header("Location: create.php");
    exit();
}
?>

<p>
    <a href="../../main.php" class="btn btn-primary">&lt;&lt; Back to List</a>
</p>
<br />

<?php include("../../inc_footer.php"); ?>