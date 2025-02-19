<?php
session_start();
include("../../inc_header_display.php");
include("../../inc_db_params.php");

// Initialize variables
$articleId = $title = $body = $createDate = $authorName = "";
$loggedInUser = $_SESSION['username'] ?? null;

if (isset($_GET['id'])) {
    $id = $_GET['id'];

    // Prepare an SQL statement to fetch the article data with the author's name.
    $stmt = $db->prepare("
        SELECT 
            a.ArticleId,
            a.Title,
            a.Body,
            a.CreatDate AS CreateDate,
            a.StartDate,
            a.EndDate,
            a.ContributorUsername,
            u.firstName || ' ' || u.lastName AS authorName
        FROM Articles a
        LEFT JOIN Users u ON a.ContributorUsername = u.username
        WHERE a.ArticleId = :id
    ");

    if ($stmt) {
        $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
        $result = $stmt->execute();

        if ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $articleId         = $row['ArticleId'];
            $title             = $row['Title'];
            $body              = $row['Body'];
            $createDate        = $row['CreateDate'];
            $startDate         = $row['StartDate'];
            $endDate           = $row['EndDate'];
            $contributorUsername = $row['ContributorUsername'];
            $authorName        = $row['authorName'];
        } else {
            echo "<p class='alert alert-danger'>Article not found.</p>";
        }

        $result->finalize();
    } else {
        echo "<p class='alert alert-danger'>Error preparing statement: " . $db->lastErrorMsg() . "</p>";
    }

    $db->close();
}
?>

<div class="container">
    <div class="row justify-content-center">
        <!-- Use a wider column if needed (e.g., col-md-8) -->
        <div class="col-md-8">
            <!-- Display the article title centered -->
            <h1 class="text-center mt-5"><?php echo htmlspecialchars($title); ?></h1>

            <!-- Article Content -->
            <article class="mt-4">
                <p class="text-muted mt-3">
                    <span class="fs-2">Posted by: <?php echo htmlspecialchars($authorName); ?></span><br>
                    <span class="fs-3">Created on: <?php echo htmlspecialchars($createDate); ?></span><br>
                    <span class="fs-3">Valid from: <?php echo htmlspecialchars($startDate); ?> to <?php echo htmlspecialchars($endDate); ?></span>
                </p>
                <br>
                <!-- Render the article body (allowing HTML) -->
                <div class="fs-2">
                    <?php echo nl2br($body); ?>
                </div>
            </article>

            <!-- Edit/Delete Buttons (if permitted) -->
            <?php 
            // Only allow Edit/Delete if the user is an admin or the article contributor
            if ($loggedInUser && (strtolower($_SESSION['role']) === 'admin' || $loggedInUser === $contributorUsername)): ?>
                <div class="mt-4 text-right">
                    <a href="/crud/update/update.php?id=<?php echo urlencode($articleId); ?>" class="btn btn-warning">Edit</a>
                    <a href="/crud/delete/delete.php?id=<?php echo urlencode($articleId); ?>" class="btn btn-danger">Delete</a>
                </div>
            <?php endif; ?>

            <!-- Back Button -->
            <div class="mt-3">
                <a href="../../main.php" class="btn btn-small btn-primary">&lt;&lt; BACK</a>
            </div>
        </div>
    </div>
</div>

<?php include("../../inc_footer.php"); ?>