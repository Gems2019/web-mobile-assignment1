<?php
// Define the database path relative to this file's location
define('DB_PATH', __DIR__.'/blog3795.sqlite'); // Absolute path

// Connect to the SQLite database using the relative path
$db = new SQLite3(DB_PATH);

// Debugging: Check if the database file exists
if (!file_exists(DB_PATH)) 
{
    die("<p class='alert alert-danger'> Error: Database file not found at " . DB_PATH . "</p>");
} 

else 
{
    error_log("Database file found: " . DB_PATH);
}

