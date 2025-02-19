<?php
session_start();
include("../../inc_header.php");
include("../../inc_db_params.php");

// Initialize variables for the article
$articleId = $title = $body = $startDate = $endDate = "";

// Check if 'id' is provided in the URL
if (isset($_GET['id'])) {
    $id = $_GET['id'];

    // Prepare an SQL statement to fetch the article data
    $stmt = $db->prepare("SELECT * FROM Articles WHERE ArticleId = :ArticleId");

    if ($stmt) {
        // Bind the article ID parameter as an integer
        $stmt->bindValue(':ArticleId', $id, SQLITE3_INTEGER);

        // Execute the query
        $result = $stmt->execute();

        // Fetch the article data
        if ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $articleId = $row['ArticleId'];
            $title     = $row['Title'];
            $body      = $row['Body'];
            $startDate = $row['StartDate'];
            $endDate   = $row['EndDate'];
        } else {
            echo "<p class='alert alert-danger'>Article not found.</p>";
        }

        // Finalize the result set
        $result->finalize();
    } else {
        echo "<p class='alert alert-danger'>Error preparing statement: " . $db->lastErrorMsg() . "</p>";
    }
}
?>

<!-- Main Container with landing-css styling -->
<div class="container" id="mainContainer">
  <h1 class="text-center mt-5">Update Article</h1>
  <div class="row justify-content-center">
    <div class="col-md-8">
      <form action="process_update.php" method="post" class="mt-4">
        <!-- Hidden field to carry the article ID -->
        <input type="hidden" name="ArticleId" value="<?php echo htmlspecialchars($articleId); ?>" />

        <div class="mb-3">
          <label class="form-label">Article ID</label>
          <p><?php echo htmlspecialchars($articleId); ?></p>
        </div>

        <div class="mb-3">
          <label for="Title" class="form-label">Title</label>
          <input
            type="text"
            class="form-control"
            name="Title"
            id="Title"
            value="<?php echo htmlspecialchars($title); ?>"
            required
          />
        </div>

        <div class="mb-3">
          <label for="Body" class="form-label">Body</label>
          <textarea
            class="form-control"
            name="Body"
            id="Body"
            rows="8"
            required
          ><?php echo htmlspecialchars($body); ?></textarea>
        </div>

        <!-- Optional: If you want to allow updating StartDate/EndDate -->
        <div class="mb-3">
          <label for="StartDate" class="form-label">Start Date</label>
          <input
            type="date"
            class="form-control"
            name="StartDate"
            id="StartDate"
            value="<?php echo htmlspecialchars($startDate); ?>"
          />
        </div>

        <div class="mb-3">
          <label for="EndDate" class="form-label">End Date</label>
          <input
            type="date"
            class="form-control"
            name="EndDate"
            id="EndDate"
            value="<?php echo htmlspecialchars($endDate); ?>"
          />
        </div>
        <!-- End optional fields -->

        <!-- Action Buttons -->
        <div class="mt-4 d-flex">
          <a href="../../main.php" class="btn btn-primary me-3">&lt;&lt; BACK</a>
          <input type="submit" value="Update" name="update" class="btn btn-warning" />
        </div>
      </form>
    </div>
  </div>
</div>

<?php include("../../inc_footer.php"); ?>