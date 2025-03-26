# Sicherheitslücken in der M183-LB2 Anwendung

## 1. SQL Injection
**Ort**: login.php (Zeile 21)
**Problem**: Die SQL-Query verwendet direkt den eingegebenen Usernamen ohne Prepared Statements
  ```php
  $stmt = $conn->prepare("SELECT id, username, password FROM users WHERE username='$username'");
  ```
**Fix**: Prepared Statement mit korrektem Parameter-Binding verwenden
  ```php
  $stmt = $conn->prepare("SELECT id, username, password FROM users WHERE username=?");
  $stmt->bind_param("s", $username);
  ```

## 2. SQL Injection
**Ort**: edit.php (Zeile 21-22)
**Problem**: Ungefilterter Parameter wird in SQL-Query genutzt
  ```php
  $stmt = executeStatement("select ID, title, state from tasks where ID = $taskid");
  ```
**Fix**: Prepared Statement mit Parameter-Binding verwenden
  ```php
  $stmt = $conn->prepare("select ID, title, state from tasks where ID = ?");
  $stmt->bind_param("i", $taskid);
  ```

## 3. SQL Injection
**Ort**: savetask.php (Zeile 14)
**Problem**: Ungefilterter Parameter wird in SQL-Query genutzt
  ```php
  $stmt = executeStatement("select ID, title, state from tasks where ID = $taskid");
  ```
**Fix**: Prepared Statement mit Parameter-Binding verwenden

## 4. SQL Injection
**Ort**: savetask.php (Zeile 28-32)
**Problem**: Variablen werden direkt in SQL-Abfragen eingesetzt
  ```php
  $stmt = executeStatement("insert into tasks (title, state, userID) values ('$title', '$state', '$userid')");
  $stmt = executeStatement("update tasks set title = '$title', state = '$state' where ID = $taskid");
  ```
**Fix**: Prepared Statements mit Parameter-Binding verwenden

## 5. SQL Injection
**Ort**: search/v2/index.php (Zeile 14)
**Problem**: Ungefilterter Suchparameter wird in SQL verwendet
  ```php
  $stmt = executeStatement("select ID, title, state from tasks where userID = $userid and title like '%$terms%'");
  ```
**Fix**: Prepared Statement mit Parameter-Binding verwenden

## 6. SQL Injection
**Ort**: user/tasklist.php (Zeile 14)
**Problem**: Ungefilterter Parameter wird in SQL verwendet
  ```php
  $stmt = $conn->prepare("select ID, title, state from tasks where UserID = $userid");
  ```
**Fix**: Prepared Statement mit Parameter-Binding verwenden

## 7. Unsichere Passwortverarbeitung
**Ort**: login.php (Zeile 31)
**Problem**: Passwörter werden im Klartext verglichen
  ```php
  if ($password == $db_password)
  ```
**Fix**: Sichere Hash-Algorithmen (wie bcrypt, Argon2) für Passwörter verwenden und Passwörter niemals im Klartext speichern

## 8. Plaintext Passwörter in der Datenbank
**Ort**: db/m183_lb2.sql (Zeile 142-143)
**Problem**: Passwörter werden im Klartext gespeichert
  ```sql
  insert into users (ID, username, password) values (1, 'admin1', 'Awesome.Pass34');
  ```
**Fix**: Passwörter mit sicheren Hash-Funktionen hashen und dann speichern

## 9. Unsichere Cookie-Verwaltung
**Ort**: login.php (Zeile 33-34)
**Problem**: Cookies ohne httpOnly und secure Flags
  ```php
  setcookie("username", $username, -1, "/");
  ```
**Fix**: Sichere Cookie-Optionen aktivieren
  ```php
  setcookie("username", $username, -1, "/", "", true, true);
  ```

## 10. Cross-Site Scripting (XSS)
**Ort**: admin/users.php (Zeile 35)
**Problem**: Ungefilterter Output von Datenbankdaten
  ```php
  echo "<tr><td>$db_id</td><td>$db_username</td><td>$db_title</td><input type='hidden' name='password' value='$db_password' /></tr>";
  ```
**Fix**: Alle Ausgaben mit htmlspecialchars() filtern
  ```php
  echo "<tr><td>" . htmlspecialchars($db_id) . "</td><td>" . htmlspecialchars($db_username) . "</td><td>" . htmlspecialchars($db_title) . "</td></tr>";
  ```

## 11. Cross-Site Scripting (XSS)
**Ort**: user/tasklist.php (Zeile 28-31)
**Problem**: Ungefilterter Output von Datenbankdaten
**Fix**: Alle Ausgaben mit htmlspecialchars() filtern

## 12. Server-Side Request Forgery (SSRF)
**Ort**: search.php (Zeile 40)
**Problem**: Der URL-Parameter kann manipuliert werden
  ```php
  $theurl='http://localhost'.$provider.'?userid='.$userid.'&terms='.$terms;
  ```
**Fix**: Whitelist für erlaubte URLs implementieren oder interne Endpunkte fest definieren

## 13. Unsichere direkte Objekt-Referenzen
**Ort**: edit.php, savetask.php
**Problem**: Keine Überprüfung, ob der angemeldete Benutzer berechtigt ist, die angeforderte Task zu bearbeiten
**Fix**: Implementierung einer Zugriffskontrolle, z.B.
  ```php
  $stmt = $conn->prepare("select ID, title, state from tasks where ID = ? AND userID = ?");
  $stmt->bind_param("ii", $taskid, $userid);
  ```

## 14. Session Fixation
**Ort**: login.php
**Problem**: Keine Session-Rotation bei Login
**Fix**: Nach erfolgreicher Authentifizierung session_regenerate_id() aufrufen

## 15. Credential Exposure
**Ort**: admin/users.php (Zeile 35)
**Problem**: Passwörter werden im HTML-Quellcode gespeichert
  ```php
  <input type='hidden' name='password' value='$db_password' />
  ```
**Fix**: Passwörter niemals in HTML-Code einfügen, komplett entfernen

## 16. Fehlende Content Security Policy
**Ort**: Gesamte Anwendung
**Problem**: Keine Content Security Policy (CSP) Header
**Fix**: CSP-Header implementieren, um XSS-Angriffe zu reduzieren
  ```php
  header("Content-Security-Policy: default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com;");
  ```

## 17. Unsichere Password-Felder
**Ort**: login.php (Zeile 64)
**Problem**: Passwort-Feld als Textfeld anstatt Passwort-Feld
  ```php
  <input type="text" class="form-control size-medium" name="password" id="password">
  ```
**Fix**: Typ auf "password" ändern
  ```php
  <input type="password" class="form-control size-medium" name="password" id="password">
  ```

## 18. Plaintext Database Credentials
**Ort**: config.php
**Problem**: Datenbank-Anmeldedaten im Klartext im Code
  ```php
  define('DB_HOST', 'm183-lb2-db');
  define('DB_USER', 'root');
  define('DB_PASS', 'Some.Real.Secr3t');
  ```
**Fix**: Umgebungsvariablen oder eine sichere Konfigurationsverwaltung verwenden

## 19. Fehlende Input-Validierung
**Ort**: savetask.php (Zeile 22-24)
**Problem**: Keine Validierung der Eingabedaten
**Fix**: Serverseitige Validierung aller Eingaben implementieren

## 20. Cross-Site Request Forgery (CSRF)
**Ort**: Mehrere Formulare
**Problem**: Keine CSRF-Token in Formularen
**Fix**: CSRF-Token für jedes Formular hinzufügen und beim Absenden validieren
  ```php
  // Token generieren
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
  
  // Im Formular einfügen
  <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
  
  // Beim Formular-Submit überprüfen
  if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
      die('CSRF-Angriff erkannt');
  }
  ```


# Docker and PHP Commands

## Docker Execution Commands

### Execute PHP Script in Container
```bash
# If using the PHP container from your docker-compose setup
docker exec -it m183-lb2-web php /var/www/html/update_passwords.php
```

### Check PHP Version
```bash
# Or to just check PHP version
docker exec -it m183-lb2-web php -v
```

## PHP Version Output
```
PHP 8.0.30 (cli) (built: Nov 21 2023 16:13:28) ( NTS )
Copyright (c) The PHP Group
Zend Engine v4.0.30, Copyright (c) Zend Technologies
```

## `delete.php` Script

### Purpose
This script handles task deletion for the todo list application with security considerations.

### Script Implementation
```php
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
```

### Security Features
- User authentication check
- Task ownership verification
- Prevention of unauthorized task deletion
- Prepared statements to prevent SQL injection
- User feedback mechanism

## Vulnerability: Lack of Security Logging

### Description
The application lacks comprehensive logging for security-relevant events.

### Proposed Logging Improvements
```php
// Add to login.php for successful login
$ip = $_SERVER['REMOTE_ADDR'];
$time = date('Y-m-d H:i:s');
error_log("Successful login: User $username from IP $ip at $time");

// Add to login.php for failed login attempts
error_log("Failed login attempt: Username $username from IP $ip at $time");
```