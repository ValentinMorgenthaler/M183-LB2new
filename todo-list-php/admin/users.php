<?php

    // Ensure session is started
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }

    if (!isset($_COOKIE['username'])) {
        header("Location: ../login.php");
        exit();
    }

    require_once '../config.php';
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);

    // Check connection
    if ($conn->connect_error) {
        error_log("Connection failed: " . $conn->connect_error);
        die("Database connection error. Please contact the administrator.");
    }
    // Prepare SQL statement to retrieve user from database
    $stmtU = $conn->prepare("SELECT users.ID, users.username, users.password, roles.title FROM users inner join permissions on users.ID = permissions.userID inner join roles on permissions.roleID = roles.ID order by username");
    // Execute the statement
    $stmtU->execute();
    // Store the result
    $stmtU->store_result();
    // Bind the result variables
    $stmtU->bind_result($db_id, $db_username, $db_password, $db_title);

    require_once '../fw/header.php';
?>
<h2>User List</h2>
<form method="post" action="">
    <!-- Add hidden CSRF token field -->
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
</form>
<table>
    <tr>
        <th>ID</th>
        <th>Username</th>
        <th>Role</th>
    </tr>
    <?php
        // Fetch the result
        while ($stmtU->fetch()) {
            echo "<tr><td>" . htmlspecialchars($db_id) . "</td><td>" . htmlspecialchars($db_username) . "</td><td>" . htmlspecialchars($db_title) . "</td></tr>";
        }
    ?>
</table>

<?php
    require_once '../fw/footer.php';
?>