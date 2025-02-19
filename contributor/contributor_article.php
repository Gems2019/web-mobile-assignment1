<?php
session_start();
include("../inc_header_contributor.php");
include("../inc_db_params.php");

// Redirect if user is not logged in
if (!isset($_SESSION['username'])) {
  header("Location: ../login/login.php");
  exit();
}

// We'll use the logged-in user's email (username) to find their articles
$contributorUsername = $_SESSION['username'];

// Prepare a statement to fetch articles for the current contributor
$stmt = $db->prepare("
    SELECT 
        ArticleId AS PostId,
        Title,
        Body,
        CreatDate,
        StartDate,
        EndDate
    FROM Articles
    WHERE ContributorUsername = :contributorUsername
    ORDER BY CreatDate DESC
");
$stmt->bindValue(':contributorUsername', $contributorUsername, SQLITE3_TEXT);
$articles = $stmt->execute();
?>

<div class="container">
  <div class="row justify-content-center">
    <div class="col-md-10">
      <h1 class="text-center mt-5">My Articles</h1>

      <table class="table mt-4">
        <thead>
          <tr>
            <th>Title</th>
            <th>Created On</th>
            <th>Valid From</th>
            <th>Valid To</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <?php while ($article = $articles->fetchArray(SQLITE3_ASSOC)): ?>
            <tr>
              <td><?php echo htmlspecialchars($article['Title']); ?></td>
              <td><?php echo htmlspecialchars($article['CreatDate']); ?></td>
              <td><?php echo htmlspecialchars($article['StartDate']); ?></td>
              <td><?php echo htmlspecialchars($article['EndDate']); ?></td>
              <td>
                <!-- Replace these links as needed to match your CRUD routes -->
                <a href="/crud/display/display.php?id=<?php echo urlencode($article['PostId']); ?>" class="btn btn-info btn-sm">View</a>
                <a href="/crud/update/update.php?id=<?php echo urlencode($article['PostId']); ?>" class="btn btn-warning btn-sm">Edit</a>
                <a href="/crud/delete/delete.php?id=<?php echo urlencode($article['PostId']); ?>" class="btn btn-danger btn-sm">Delete</a>
              </td>
            </tr>
          <?php endwhile; ?>
        </tbody>
      </table>

      <div class="mt-3 text-center">
        <a href="../main.php" class="btn btn-primary">
          <i class="glyphicon glyphicon-arrow-left"></i> Back to Home
        </a>
      </div>
    </div>
  </div>
</div>

<?php include("../inc_footer.php"); ?>