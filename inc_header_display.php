<!DOCTYPE html>
<html lang="en">

<head>
    <title>Students CRUD</title>
    <meta http-equiv="content-type" content="text/html; charset=iso-8859-1" />
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/js/bootstrap.min.js"></script>
    <!-- Bootstrap CSS/JS includes (if not already in your header) -->
    <link href="//netdna.bootstrapcdn.com/bootstrap/3.0.0/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
    <script src="//netdna.bootstrapcdn.com/bootstrap/3.0.0/js/bootstrap.min.js"></script>
    <script src="//code.jquery.com/jquery-1.11.1.min.js"></script>

    <!-- Font -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=DM+Serif+Text:ital@0;1&display=swap" rel="stylesheet">

    <link href="//maxcdn.bootstrapcdn.com/font-awesome/4.3.0/css/font-awesome.min.css" rel="stylesheet">
    <link href="../landing-css.css" rel="stylesheet">
    <!-- Styling for crud -->
    <link rel="stylesheet" type="text/css" href="/landing-css.css">


</head>

<body>
    <!-- Navbar START -->
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <div class="container">
            <!-- Left Section (Row with Two Columns) -->
            <div class="col text-center">
                <a class="navbar-brand" href="/main.php" id="navbar-home">Home</a>
            </div>

            <div class="row w-100">
                <div class="col d-flex align-items-center">
                    <ul class="navbar-nav">
                        <?php if (isset($_SESSION['username'])): ?>
                            <li class="nav-item">
                                <a class="nav-link" href="/main.php">Latest</a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="../create/create.php">Post</a>
                            </li>
                        <?php endif; ?>
                    </ul>
                </div>
                <!-- Left Section END -->

                <!-- Right Section (Row with Three Columns) -->
                <div class="col d-flex justify-content-end">
                    <ul class="navbar-nav">
                        <li class="nav-item">
                            <a class="nav-link" href="/logout/logout.php">Logout</a>
                        </li>
                      
                    </ul>
                </div>
                <!-- Right Section END -->
            </div>
        </div>
    </nav>
    <!-- Navbar END -->
    <!-- 
  <div class="container"> -->