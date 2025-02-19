<?php
include("../../inc_header.php");
include("../../inc_db_params.php");

session_start();

// Redirect if user is not logged in
if (!isset($_SESSION['username'])) {
    header("Location: ../../login/login.php");
    exit();
}

// Check if the Articles table exists
$table_check = $db->querySingle("SELECT name FROM sqlite_master WHERE type='table' AND name='Articles'");
if (!$table_check) {
    die("<p class='alert alert-danger'>Error: The 'Articles' table does not exist! Make sure to create it first.</p>");
}

// Handle form submission
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST['create'])) {

    // Retrieve the logged-in contributor's username (email)
    $contributorUsername = $_SESSION['username'];

    // Retrieve input from the form
    // Adjust field names to match your create form
    $title     = trim($_POST['Title']);
    $body      = trim($_POST['Body']);
    $startDate = $_POST['StartDate'];
    $endDate   = $_POST['EndDate'];

    // Prepare an INSERT statement for the Articles table
    $stmt = $db->prepare("
        INSERT INTO Articles (Title, Body, StartDate, EndDate, ContributorUsername) 
        VALUES (:Title, :Body, :StartDate, :EndDate, :ContributorUsername)
    ");

    // Bind form values to the SQL statement
    $stmt->bindValue(':Title', $title, SQLITE3_TEXT);
    $stmt->bindValue(':Body', $body, SQLITE3_TEXT);
    $stmt->bindValue(':StartDate', $startDate, SQLITE3_TEXT);
    $stmt->bindValue(':EndDate', $endDate, SQLITE3_TEXT);
    $stmt->bindValue(':ContributorUsername', $contributorUsername, SQLITE3_TEXT);

    // Execute the statement
    $result = $stmt->execute();

    // Provide a success or error message
    if ($result) {
        echo "<p class='alert alert-success'>Article added successfully.</p>";
    } else {
        echo "<p class='alert alert-danger'>Error adding article: " . $db->lastErrorMsg() . "</p>";
    }

    // Close the database connection
    $db->close();
}
?>

<p>
    <a href="../../main.php" class="btn btn-primary">&lt;&lt; Back to List</a>
</p>
<br />

<?php include("../../inc_footer.php"); ?>