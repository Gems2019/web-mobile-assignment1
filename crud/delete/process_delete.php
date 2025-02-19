<?php
session_start();
include("../../inc_db_params.php"); // Include database connection

// Check if user is logged in
if (!isset($_SESSION['username'])) {
    header("Location: ../../login/login.php");
    exit();
}

// Check if article ID is provided
if (!isset($_POST['id'])) {
    echo "<p class='alert alert-danger'>Error: No article ID provided.</p>";
    exit();
}

$articleId = $_POST['id'];

// Get user role and username from session
$username = $_SESSION['username'];
$userRole = strtolower($_SESSION['role'] ?? ''); // Default to empty if undefined

// Fetch the article owner
$stmt = $db->prepare("SELECT ContributorUsername FROM Articles WHERE ArticleId = :id");
$stmt->bindValue(':id', $articleId, SQLITE3_INTEGER);
$result = $stmt->execute();
$article = $result->fetchArray(SQLITE3_ASSOC);

if (!$article) {
    echo "<p class='alert alert-danger'>Error: Article not found.</p>";
    exit();
}

$articleOwner = $article['ContributorUsername'];

// Check if the user is authorized to delete the article
if ($userRole !== 'admin' && $username !== $articleOwner) {
    echo "<p class='alert alert-danger'>Error: You do not have permission to delete this article.</p>";
    exit();
}

// Prepare the DELETE SQL statement
$stmt = $db->prepare("DELETE FROM Articles WHERE ArticleId = :id");

if ($stmt) {
    $stmt->bindValue(':id', $articleId, SQLITE3_INTEGER);
    $exec = $stmt->execute();

    if ($exec) {
        header("Location: ../../main.php?message=Article deleted successfully"); // Redirect back to main page
        exit();
    } else {
        echo "<p class='alert alert-danger'>Error deleting article: " . $db->lastErrorMsg() . "</p>";
    }
} else {
    echo "<p class='alert alert-danger'>Error preparing statement: " . $db->lastErrorMsg() . "</p>";
}

// Close the database connection
$db->close();
?>

<p>
    <a href="../../main.php" class="btn btn-primary">&lt;&lt; Back to List</a>
</p>