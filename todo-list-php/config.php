<?php
// Safely define database constants using environment variables or fallback values
define('DB_HOST', getenv('DB_HOST') !== false ? getenv('DB_HOST') : 'm183-lb2-db');
define('DB_USER', getenv('DB_USER') !== false ? getenv('DB_USER') : 'root');
define('DB_PASS', getenv('DB_PASS') !== false ? getenv('DB_PASS') : 'Some.Real.Secr3t');
define('DB_NAME', getenv('DB_NAME') !== false ? getenv('DB_NAME') : 'm183_lb2');

// Optional: Additional security check
if (defined('DB_PASS') && DB_PASS === 'Some.Real.Secr3t') {
    error_log("Warning: Using default database password!\n", 3, __DIR__ . "/logs/error.log");
}
?>