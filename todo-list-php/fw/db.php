<?php

    function executeStatement($statement){
        $conn = getConnection();
        $stmt = $conn->prepare($statement);
        $stmt->execute();
        $stmt->store_result();
        return $stmt;
    }

    function getConnection()
    {
        $root = realpath($_SERVER["DOCUMENT_ROOT"]);
        require_once "$root/config.php";
        //require_once 'config.php';
        $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);

        // Check connection
        if ($conn->connect_error) {
            error_log("Connection failed: " . $conn->connect_error);
            die("Database connection error. Please contact the administrator.");
        }

        return $conn;
    }
?>