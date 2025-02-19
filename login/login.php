<?php session_start(); ?>

<!-- Require/Include -->
<?php require_once "../inc_db_params.php"; ?>
<?php require_once "../utils.php"; ?>
<?php require_once "../inc_header_before_login.php"; ?>

<?php 
// Check if User is already logged in
if (isset($_SESSION['username'])) {
    header("Location: ../main.php");
    exit();
}
?>

<!-- Login Page START -->
<div class="container">
  <div class="row justify-content-center">
    <div class="col-md-6">
      <h1 class="mt-5 text-center">Login</h1>

      <!-- Display Errors -->
      <?php
      if (isset($_SESSION['error'])) {
          echo '<div class="alert alert-danger">' . $_SESSION['error'] . '</div>';
          unset($_SESSION['error']);
      }
      ?>

      <!-- Form -->
      <form action="process_login.php" method="post">
          <div class="mb-3">
              <label for="email" class="form-label">Email (Username)</label>
              <input type="email" class="form-control" name="email" required>
          </div>

          <div class="mb-3">
              <label for="password" class="form-label">Password</label>
              <input type="password" class="form-control" name="password" required>
          </div>
          
          <!-- Buttons -->
          <div class="d-flex justify-content-between">
              <button type="submit" class="btn btn-primary">Login</button>
              <a href="/" class="btn btn-small btn-primary">Back</a>
          </div>
      </form>
      <!-- Form END -->

      <p class="mt-3 text-center">Don't have an account? <a href="/register/register.php">Register here</a></p>
    </div>
  </div>
</div>
<!-- Login Page END -->

<?php include("../inc_footer.php"); ?>
<!-- Styling -->
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