<?php
// Ensure $db has been initialized via inc_db_params.php (e.g. $db = new SQLite3('./blog.sqlite');)

if ($db) {
    // Create the Users table if it doesn't exist
    $SQL_create_user_table = "CREATE TABLE IF NOT EXISTS Users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        username TEXT UNIQUE NOT NULL, -- This will be the email address 
        password TEXT NOT NULL,
        firstName TEXT NOT NULL, 
        lastName TEXT NOT NULL,
        registrationDate DATETIME DEFAULT CURRENT_TIMESTAMP,
        isApproved INTEGER NOT NULL DEFAULT 0,
        role TEXT CHECK(role IN ('Admin', 'Contributor')) DEFAULT 'Contributor'
    )";
    $db->exec($SQL_create_user_table);

    // Create the Articles table if it doesn't exist.
    $SQL_create_articles_table = "CREATE TABLE IF NOT EXISTS Articles (
        ArticleId INTEGER PRIMARY KEY AUTOINCREMENT,
        Title TEXT NOT NULL,
        Body TEXT NOT NULL,
        CreatDate DATETIME DEFAULT CURRENT_TIMESTAMP,
        StartDate DATE,
        EndDate DATE,
        ContributorUsername TEXT NOT NULL
    )";
    $db->exec($SQL_create_articles_table);

    $SQL_check_user_empty = "SELECT COUNT(*) as count FROM Users";
    $result = $db->querySingle($SQL_check_user_empty, true);

    // Always try to insert these users, skipping if they already exist
    $SQL_insert_default_users = "
    INSERT OR IGNORE INTO Users (username, password, firstName, lastName, registrationDate, isApproved, role)
    VALUES
    ('a@a.a', '" . password_hash('P@$$w0rd', PASSWORD_BCRYPT) . "', 'AdminUser', 'A', datetime('now'), 1, 'Admin'),
    ('c@c.c', '" . password_hash('P@$$w0rd', PASSWORD_BCRYPT) . "', 'ContributorUser', 'C', datetime('now'), 1, 'Contributor')
";
    $db->exec($SQL_insert_default_users);

    if ($result['count'] == 0) {
        $SQL_insert_users = "
        INSERT INTO Users (username, password, firstName, lastName, registrationDate, isApproved, role)
        VALUES 
            ('alice@test.com', '" . password_hash('secret', PASSWORD_BCRYPT) . "', 'Alice', 'Johnson', datetime('now'), 1, 'Admin'),
            ('bob@test.com', '" . password_hash('secret', PASSWORD_BCRYPT) . "', 'Bob', 'Smith', datetime('now'), 0, 'Contributor'),
            ('charlie@test.com', '" . password_hash('secret', PASSWORD_BCRYPT) . "', 'Charlie', 'Brown', datetime('now'), 0, 'Contributor'),
    ";
        $db->exec($SQL_insert_users);
    }

    // Insert default users if the Users table is empty.
    $SQL_check_user_empty = "SELECT COUNT(*) as count FROM Users";
    $result = $db->querySingle($SQL_check_user_empty, true);

    if ($result['count'] == 0) {
        $SQL_insert_users = "
            INSERT INTO Users (username, password, firstName, lastName, registrationDate, isApproved, role)
            VALUES 
                ('alice@test.com', '" . password_hash('secret', PASSWORD_BCRYPT) . "', 'Alice', 'Johnson', datetime('now'), 1, 'Admin'),
                ('bob@test.com', '" . password_hash('secret', PASSWORD_BCRYPT) . "', 'Bob', 'Smith', datetime('now'), 0, 'Contributor'),
                ('charlie@test.com', '" . password_hash('secret', PASSWORD_BCRYPT) . "', 'Charlie', 'Brown', datetime('now'), 0, 'Contributor');
        ";
        $db->exec($SQL_insert_users);
    }

    // Insert default articles if the Articles table is empty
    $SQL_check_articles_empty = "SELECT COUNT(*) as count FROM Articles";
    $result = $db->querySingle($SQL_check_articles_empty, true);

    // Fetch some user emails from Users table for seeding the ContributorUsername field.
    $users = [];
    $SQL_fetch_users = "SELECT username FROM Users ORDER BY id ASC LIMIT 3";
    $query = $db->query($SQL_fetch_users);
    while ($row = $query->fetchArray(SQLITE3_ASSOC)) {
        $users[] = $row['username'];
    }

    // Insert default articles only if there are at least 3 users.
    if ($result['count'] == 0 && count($users) >= 3) {
        // Set sample StartDate and EndDate values (adjust as needed)
        $startDate = date('Y-m-d', strtotime('+1 day'));
        $endDate = date('Y-m-d', strtotime('+7 days'));

        $SQL_insert_articles = "
            INSERT INTO Articles (ContributorUsername, Title, Body, StartDate, EndDate)
            VALUES 
                ('{$users[0]}', 'Getting Started with Blogging', 'Welcome to the blogging world! This post will guide you through the basics.', '$startDate', '$endDate'),
                ('{$users[1]}', 'My Daily Routine', 'A glimpse into my daily life and how I stay productive.', '$startDate', '$endDate'),
                ('{$users[2]}', 'Life Hacks for Efficiency', 'Here are some useful tricks to make life easier and more efficient.', '$startDate', '$endDate')
        ";
        $db->exec($SQL_insert_articles);
    }
} else {
    echo "<p class='alert alert-danger'>Error creating database.</p>";
}
