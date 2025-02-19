<?php
session_start();
include("../../inc_header.php");
include("../../inc_db_params.php");
?>

<!-- Main Container for landing-css styling -->
<div class="container" id="mainContainer">
  <h1 class="text-center mt-5">Delete Article</h1>
  
  <?php
  // Initialize variables
  $articleId = $title = $body = '';

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

  <div class="row justify-content-center">
    <div class="col-md-8 mt-4">
      <table class="table table-striped">
        <tr>
          <td><strong>Article ID:</strong></td>
          <td><?php echo htmlspecialchars($articleId); ?></td>
        </tr>
        <tr>
          <td><strong>Title:</strong></td>
          <td><?php echo htmlspecialchars($title); ?></td>
        </tr>
        <tr>
          <td><strong>Body:</strong></td>
          <td><?php echo nl2br(htmlspecialchars($body)); ?></td>
        </tr>
      </table>

      <form action="process_delete.php" method="post" class="mt-4">
        <!-- Pass the article ID to process_delete.php -->
        <input type="hidden" name="id" value="<?php echo htmlspecialchars($articleId); ?>" />
        <a href="../../main.php" class="btn btn-small btn-primary me-3">&lt;&lt; BACK</a>
        <input type="submit" value="Delete" class="btn btn-danger" />
      </form>
    </div>
  </div>
</div>

<?php include("../../inc_footer.php"); ?>
<?php
echo "<style>
        body {
            background-color: #d9b99b;
        }

        form {
            background-color: #faf0e6;
            padding: 10px;
            border-radius: 10px;
        }
      </style>";
?>