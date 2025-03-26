<?php
// File for hashing all user passwords

// Include database configuration
require_once 'config.php';

// Create database connection
$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);

// Check connection
if ($conn->connect_error) {
    error_log("Connection failed: " . $conn->connect_error);
    die("Database connection error. Please contact the administrator.");
}

// Get all users
$result = $conn->query("SELECT ID, username, password FROM users");

// Iterate through users and update passwords with hash
while ($row = $result->fetch_assoc()) {
    // Hash the existing password
    $hashed_password = password_hash($row['password'], PASSWORD_DEFAULT);
    
    // Prepare update statement
    $stmt = $conn->prepare("UPDATE users SET password = ? WHERE ID = ?");
    $stmt->bind_param("si", $hashed_password, $row['ID']);
    
    // Execute the update
    if ($stmt->execute()) {
        echo "Updated password for user: " . $row['username'] . "<br>";
    } else {
        echo "Error updating password for user: " . $row['username'] . "<br>";
    }
    
    $stmt->close();
}

// Close connection
$result->close();
$conn->close();

echo "Password update complete.";
?>