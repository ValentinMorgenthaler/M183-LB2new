<?php
    // Check if the user is logged in
    if (!isset($_COOKIE['userid'])) {
        header("Location: /");
        exit();
    }

    // Check if a task ID is provided
    if (!isset($_GET['id']) || empty($_GET['id'])) {
        header("Location: /");
        exit();
    }

    $taskid = $_GET['id'];
    $userid = $_COOKIE['userid'];

    require_once 'fw/db.php';
    require_once 'fw/header.php';

    // Verify that the task belongs to the current user before deleting
    $stmt = executeStatement("SELECT ID FROM tasks WHERE ID = $taskid AND userID = $userid");
    
    if ($stmt->num_rows > 0) {
        // Delete the task
        $deleteStmt = executeStatement("DELETE FROM tasks WHERE ID = $taskid");
        
        echo "<span class='info info-success'>Task successfully deleted</span>";
    } else {
        echo "<span class='info info-error'>You do not have permission to delete this task</span>";
    }

    require_once 'fw/footer.php';
?>