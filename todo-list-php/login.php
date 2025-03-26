<?php

// Ensure session is started
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

require_once 'config.php';

// CSRF token validation
function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && 
           isset($token) && 
           hash_equals($_SESSION['csrf_token'], $token);
}

// Check if the form is submitted
if ($_SERVER["REQUEST_METHOD"] == "GET" && isset($_GET['username']) && isset($_GET['password'])) {
    // Validate CSRF token first
    if (!validateCSRFToken($_GET['csrf_token'])) {
        die("CSRF token validation failed. Please submit the form from the original page.");
    }

    // Get username and password from the form
    $username = $_GET['username'];
    $password = $_GET['password'];
    
    // Connect to the database
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);

    // Check connection
    if ($conn->connect_error) {
        error_log("Connection failed: " . $conn->connect_error);
        die("Database connection error. Please contact the administrator.");
    }
    // Prepare SQL statement to retrieve user from database
    $stmt = $conn->prepare("SELECT id, username, password FROM users WHERE username=?");
    $stmt->bind_param("s", $username);

    // Execute the statement
    $stmt->execute();
    // Store the result
    $stmt->store_result();
    // Check if username exists
    if ($stmt->num_rows > 0) {
        // Bind the result variables
        $stmt->bind_result($db_id, $db_username, $db_password);
        // Fetch the result
        $stmt->fetch();
        // verification of the password
        if (password_verify($password, $db_password)) {
            // Password is correct, store username in session
            setcookie("username", $username, -1, "/", "", isset($_SERVER["HTTPS"]), true);
            setcookie("userid", $db_id, -1, "/", "", isset($_SERVER["HTTPS"]), true);
            // Regenerate CSRF token after login
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

            $ip = $_SERVER['REMOTE_ADDR'];
            $time = date('Y-m-d H:i:s');
            error_log("Successful login: User $username from IP $ip at $time");

            // Redirect to index.php
            header("Location: index.php");
            exit();
        } else {
            // Password is incorrect
            echo htmlspecialchars("Incorrect username or password", ENT_QUOTES, 'UTF-8');

            error_log("Failed login attempt: Username $username from IP $ip at $time");
        }
    } else {
        // Username does not exist
        echo htmlspecialchars("Incorrect username or password", ENT_QUOTES, 'UTF-8');

        error_log("Failed login attempt: Username $username from IP $ip at $time");
    }

    // Close statement
    $stmt->close();
}
require_once 'fw/header.php';
?>

    <h2>Login</h2>


    <form id="form" method="get" action="<?php $_SERVER["PHP_SELF"]; ?>">
    <!-- Add hidden CSRF token field -->
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
    <div class="form-group">
        <label for="username">Username</label>
        <input type="text" class="form-control size-medium" name="username" id="username">
    </div>
    <div class="form-group">
        <label for="password">Password</label>
        <input type="password" class="form-control size-medium" name="password" id="password">
    </div>
    <div class="form-group">
        <label for="submit" ></label>
        <input id="submit" type="submit" class="btn size-auto" value="Login" />
    </div>
</form>

<?php
    require_once 'fw/footer.php';
?>