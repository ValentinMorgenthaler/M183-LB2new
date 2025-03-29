<?php
    // Ensure session is started
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }

    // Regenerate session ID to prevent session fixation attacks
    session_regenerate_id(true);

    unset($_COOKIE['username']); 
    setcookie('username', '', -1, '/'); 
    unset($_COOKIE['userid']); 
    setcookie('userid', '', -1, '/'); 

    // Destroy the session
    session_unset();
    session_destroy();
    
    header("Location: /");
    exit();
?>