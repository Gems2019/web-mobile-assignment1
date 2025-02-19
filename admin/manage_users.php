<?php 
session_start();
include("../inc_header.php");
include("../inc_db_params.php");

// Update role check to handle case sensitivity
if (!isset($_SESSION['role']) || !in_array($_SESSION['role'], ['Admin', 'admin'])) {
    header("Location: ../index.php");
    exit();
}

// Handle actions (approve/change role/delete)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['user_id']) && isset($_POST['action'])) {
        $user_id = $_POST['user_id'];
        $action = $_POST['action'];
        
        if ($action === 'approve') {
            $stmt = $db->prepare("UPDATE Users SET isApproved = 1 WHERE id = :id");
            $stmt->bindValue(':id', $user_id, SQLITE3_INTEGER);
            $stmt->execute();
        } 
        elseif ($action === 'change_role') {
            $new_role = $_POST['new_role'];
            $stmt = $db->prepare("UPDATE Users SET role = :role WHERE id = :id");
            $stmt->bindValue(':role', $new_role, SQLITE3_TEXT);
            $stmt->bindValue(':id', $user_id, SQLITE3_INTEGER);
            $stmt->execute();
        }
        elseif ($action === 'delete') {
            // Start transaction
            $db->exec('BEGIN TRANSACTION');
            
            try {
                // Get user's username first
                $stmt = $db->prepare("SELECT username FROM Users WHERE id = :id");
                $stmt->bindValue(':id', $user_id, SQLITE3_INTEGER);
                $result = $stmt->execute();
                $user = $result->fetchArray(SQLITE3_ASSOC);
                
                if ($user) {
                    // Delete all articles by this user
                    $stmt = $db->prepare("DELETE FROM Articles WHERE ContributorUsername = :username");
                    $stmt->bindValue(':username', $user['username'], SQLITE3_TEXT);
                    $stmt->execute();
                    
                    // Delete the user
                    $stmt = $db->prepare("DELETE FROM Users WHERE id = :id");
                    $stmt->bindValue(':id', $user_id, SQLITE3_INTEGER);
                    $stmt->execute();
                    
                    // Commit transaction
                    $db->exec('COMMIT');
                    
                    $_SESSION['success'] = "User and all their articles have been deleted.";
                }
            } catch (Exception $e) {
                // Rollback on error
                $db->exec('ROLLBACK');
                $_SESSION['error'] = "Error deleting user: " . $e->getMessage();
            }
        }
    }
}

// Fetch users
$users = $db->query("SELECT id, username, firstName, lastName, role, isApproved FROM Users ORDER BY registrationDate DESC");
?>

<!-- Add success/error messages display -->
<?php if (isset($_SESSION['success'])): ?>
    <div class="alert alert-success"><?php echo $_SESSION['success']; unset($_SESSION['success']); ?></div>
<?php endif; ?>
<?php if (isset($_SESSION['error'])): ?>
    <div class="alert alert-danger"><?php echo $_SESSION['error']; unset($_SESSION['error']); ?></div>
<?php endif; ?>

<style>
.table {
    margin-top: 20px;
}
.btn-sm {
    margin: 2px;
}
.form-control-sm {
    display: inline-block;
    width: auto;
    margin-right: 5px;
}
.mt-3 {
    margin-top: 15px;
}
</style>

<h1>User Management</h1>

<table class="table">
    <thead>
        <tr>
            <th>Username (Email)</th>
            <th>First Name</th>
            <th>Last Name</th>
            <th>Role</th>
            <th>Status</th>
            <th>Actions</th>
        </tr>
    </thead>
    <tbody>
        <?php while ($user = $users->fetchArray(SQLITE3_ASSOC)): ?>
        <tr>
            <td><?php echo htmlspecialchars($user['username']); ?></td>
            <td><?php echo htmlspecialchars($user['firstName']); ?></td>
            <td><?php echo htmlspecialchars($user['lastName']); ?></td>
            <td><?php echo htmlspecialchars($user['role']); ?></td>
            <td><?php echo $user['isApproved'] ? 'Approved' : 'Pending'; ?></td>
            <td>
                <?php if (!$user['isApproved']): ?>
                    <form method="POST" style="display: inline;">
                        <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                        <input type="hidden" name="action" value="approve">
                        <button type="submit" class="btn btn-success btn-sm">Approve</button>
                    </form>
                <?php endif; ?>
                
                <form method="POST" style="display: inline;">
                    <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                    <input type="hidden" name="action" value="change_role">
                    <select name="new_role" class="form-control-sm">
                        <option value="Admin">Admin</option>
                        <option value="Contributor">Contributor</option>
                    </select>
                    <button type="submit" class="btn btn-primary btn-sm">Change Role</button>
                </form>

                <!-- Add Delete Button -->
                <form method="POST" style="display: inline;" onsubmit="return confirm('Are you sure you want to delete this user and all their articles?');">
                    <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                    <input type="hidden" name="action" value="delete">
                    <button type="submit" class="btn btn-danger btn-sm">Delete User</button>
                </form>
            </td>
        </tr>
        <?php endwhile; ?>
    </tbody>
</table>

<div class="mt-3">
    <a href="../main.php" class="btn btn-primary">
        <i class="glyphicon glyphicon-arrow-left"></i> Back to Home
    </a>
</div>

<?php include("../inc_footer.php"); ?>