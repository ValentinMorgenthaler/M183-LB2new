<?php

    // Ensure session is started
    if (session_status() == PHP_SESSION_NONE) {
      session_start();
    }

    // Check if the user is logged in
    if (!isset($_COOKIE['userid'])) {
        header("Location: /");
        exit();
    }

    // CSRF token validation function
    function validateCSRFToken($token) {
      return isset($_SESSION['csrf_token']) && 
            isset($token) && 
            hash_equals($_SESSION['csrf_token'], $token);
    }

    $taskid = "";
    require_once 'fw/db.php';

    // Validate CSRF token
    if (isset($_POST['csrf_token']) && !validateCSRFToken($_POST['csrf_token'])) {
      die("CSRF token validation failed. Please submit the form from the original page.");
    }

    // see if the id exists in the database

    if (isset($_POST['id']) && strlen($_POST['id']) != 0){
        $taskid = $_POST["id"];
        $stmt = executeStatement("select ID, title, state, userID from tasks where ID = $taskid");
        // New Authorization Check
        if ($stmt->num_rows > 0) {
            $stmt->bind_result($db_id, $db_title, $db_state, $owner_id);
            $stmt->fetch();
            
            // Verify task ownership
            if ($owner_id != $_COOKIE['userid']) {
                header('HTTP/1.1 403 Forbidden');
                die("You do not have permission to modify this task");
            }
        } else {
            $taskid = "";
        }
    }
  
    require_once 'fw/header.php';
    if (isset($_POST['title']) && isset($_POST['state'])){
        $state = $_POST['state'];
        $title = $_POST['title'];
        $userid = $_COOKIE['userid'];  

        if ($taskid == ""){
            $stmt = executeStatement("insert into tasks (title, state, userID) values ('$title', '$state', '$userid')");
        }
        else {
            $stmt = executeStatement("update tasks set title = '$title', state = '$state' where ID = $taskid");
        }

        // Regenerate CSRF token after successful action
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

        echo "<span class='info info-success'>Update successfull</span>";
    }
    else {
        echo "<span class='info info-error'>No update was made</span>";
    } 

    require_once 'fw/footer.php';
?>