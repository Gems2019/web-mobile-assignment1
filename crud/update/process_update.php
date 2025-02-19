<?php
session_start();
include("../../inc_db_params.php");
include("../../utils.php"); // Optional: for sanitize_input()

// Redirect if user is not logged in
if (!isset($_SESSION['username'])) {
    header("Location: ../../login/login.php");
    exit();
}

// Extract and sanitize form data
if (isset($_POST['update'])) {
    // Retrieve form values (adjust based on your actual form fields)
    $articleId  = sanitize_input($_POST['ArticleId']);
    $title      = sanitize_input($_POST['Title']);
    $body       = sanitize_input($_POST['Body']);
    $startDate  = sanitize_input($_POST['StartDate']);
    $endDate    = sanitize_input($_POST['EndDate']);

    // Retrieve logged-in user details
    $username = $_SESSION['username'];
    $userRole = strtolower($_SESSION['role'] ?? ''); // Default to empty if undefined

    // Fetch the article's contributor email
    $stmt = $db->prepare("SELECT ContributorUsername FROM Articles WHERE ArticleId = :ArticleId");
    $stmt->bindValue(':ArticleId', $articleId, SQLITE3_INTEGER);
    $result = $stmt->execute();
    $article = $result->fetchArray(SQLITE3_ASSOC);

    if (!$article) {
        echo "<p class='alert alert-danger'>Error: Article not found.</p>";
        exit();
    }

    $articleOwner = $article['ContributorUsername'];

    // Check if the user is authorized to update the article
    if ($userRole !== 'admin' && $username !== $articleOwner) {
        echo "<p class='alert alert-danger'>Error: You do not have permission to edit this article.</p>";
        exit();
    }

    // Prepare the SQL statement for updating the article
    // Adjust columns based on your actual schema
    $sql = "UPDATE Articles
            SET Title = :Title,
                Body  = :Body,
                StartDate = :StartDate,
                EndDate   = :EndDate
            WHERE ArticleId = :ArticleId";

    $stmtUpdate = $db->prepare($sql);

    if ($stmtUpdate) {
        // Bind values securely
        $stmtUpdate->bindValue(':Title', $title, SQLITE3_TEXT);
        $stmtUpdate->bindValue(':Body', $body, SQLITE3_TEXT);
        $stmtUpdate->bindValue(':StartDate', $startDate, SQLITE3_TEXT);
        $stmtUpdate->bindValue(':EndDate', $endDate, SQLITE3_TEXT);
        $stmtUpdate->bindValue(':ArticleId', $articleId, SQLITE3_INTEGER);

        // Execute the statement
        $exec = $stmtUpdate->execute();

        // Check execution result
        if (!$exec) {
            error_log('SQLite execute() failed: ' . $db->lastErrorMsg());
            echo "<p class='alert alert-danger'>Error updating article.</p>";
        } else {
            // Redirect back to the article's display page on success
            header("Location: ../../crud/display/display.php?id=" . urlencode($articleId));
            exit();
        }
    } else {
        error_log('SQLite prepare() failed: ' . $db->lastErrorMsg());
        echo "<p class='alert alert-danger'>Error preparing statement.</p>";
    }

    // Close the database connection
    $db->close();
}
?>