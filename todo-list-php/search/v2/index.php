<?php

    if (!isset($_GET["userid"]) || !isset($_GET["terms"])){
        die("Not enough information to search");
    }

    $userid = $_GET["userid"];
    $terms = $_GET["terms"];

    require_once '../../fw/db.php';
    $conn = getConnection();
    $searchTerm = "%$terms%";
    $stmt = $conn->prepare("select ID, title, state from tasks where userID = ? and title like ?");
    $stmt->bind_param("is", $userid, $searchTerm);
    $stmt->execute();
    $stmt->store_result();
    $stmt->bind_result($db_id, $db_title, $db_state);
    if ($stmt->num_rows > 0) {
        while ($stmt->fetch()) {
            echo $db_title . ' (' . $db_state . ')<br />';
        }
    }
    
    // Verbindung schließen
    $stmt->close();
    $conn->close();
?>