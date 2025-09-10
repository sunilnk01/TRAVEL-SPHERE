<?php
// config/database.php - Secure database configuration with environment variables
class Database {
    private $host;
    private $db_name;
    private $username;
    private $password;
    private $conn;
    
    public function __construct() {
        // Use environment variables for security
        $this->host = $_ENV['DB_HOST'] ?? 'localhost';
        $this->db_name = $_ENV['DB_NAME'] ?? 'vel_sphere_db';
        $this->username = $_ENV['DB_USER'] ?? 'root';
        $this->password = $_ENV['DB_PASS'] ?? '';
    }
    
    public function getConnection() {
        $this->conn = null;
        
        try {
            // Enable SSL and set charset
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"
            ];
            
            $this->conn = new PDO(
                "mysql:host=" . $this->host . ";dbname=" . $this->db_name . ";charset=utf8mb4",
                $this->username,
                $this->password,
                $options
            );
            
        } catch(PDOException $exception) {
            error_log("Connection error: " . $exception->getMessage());
            throw new Exception("Database connection failed. Please try again later.");
        }
        
        return $this->conn;
    }
    
    public function initializeDatabase() {
        try {
            $conn = $this->getConnection();
            
            // Create users table with enhanced security
            $sql_users = "CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                full_name VARCHAR(100) NOT NULL,
                phone VARCHAR(15) NOT NULL,
                address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                failed_login_attempts INT DEFAULT 0,
                last_login_attempt TIMESTAMP NULL,
                email_verified BOOLEAN DEFAULT FALSE,
                verification_token VARCHAR(255) NULL,
                INDEX idx_username (username),
                INDEX idx_email (email)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
            
            // Create bookings table with proper relationships
            $sql_bookings = "CREATE TABLE IF NOT EXISTS bookings (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                booking_reference VARCHAR(20) UNIQUE NOT NULL,
                destination VARCHAR(50) NOT NULL,
                package_type ENUM('economic', 'semi-deluxe', 'deluxe') NOT NULL,
                guests INT NOT NULL,
                check_in DATE NOT NULL,
                check_out DATE NOT NULL,
                total_cost DECIMAL(10,2) NOT NULL,
                booking_status ENUM('pending', 'confirmed', 'cancelled', 'completed') DEFAULT 'pending',
                payment_status ENUM('pending', 'paid', 'failed', 'refunded') DEFAULT 'pending',
                payment_reference VARCHAR(100) NULL,
                special_requests TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_id (user_id),
                INDEX idx_booking_ref (booking_reference),
                INDEX idx_booking_status (booking_status)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
            
            // Create admin users table
            $sql_admins = "CREATE TABLE IF NOT EXISTS admin_users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                full_name VARCHAR(100) NOT NULL,
                role ENUM('super_admin', 'admin', 'moderator') DEFAULT 'admin',
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL,
                INDEX idx_username (username)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
            
            // Create audit log table for security
            $sql_audit = "CREATE TABLE IF NOT EXISTS audit_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_type ENUM('user', 'admin') NOT NULL,
                user_id INT NULL,
                action VARCHAR(100) NOT NULL,
                table_name VARCHAR(50) NULL,
                record_id INT NULL,
                old_values JSON NULL,
                new_values JSON NULL,
                ip_address VARCHAR(45) NOT NULL,
                user_agent TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user_type_id (user_type, user_id),
                INDEX idx_action (action),
                INDEX idx_created_at (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
            
            // Create sessions table for secure session management
            $sql_sessions = "CREATE TABLE IF NOT EXISTS user_sessions (
                id VARCHAR(128) PRIMARY KEY,
                user_id INT NOT NULL,
                user_type ENUM('user', 'admin') NOT NULL,
                ip_address VARCHAR(45) NOT NULL,
                user_agent TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_id (user_id),
                INDEX idx_expires (expires_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
            
            // Execute all table creation statements
            $conn->exec($sql_users);
            $conn->exec($sql_bookings);
            $conn->exec($sql_admins);
            $conn->exec($sql_audit);
            $conn->exec($sql_sessions);
            
            // Create default admin user if not exists
            $this->createDefaultAdmin($conn);
            
            return true;
            
        } catch(PDOException $e) {
            error_log("Database initialization error: " . $e->getMessage());
            return false;
        }
    }
    
    private function createDefaultAdmin($conn) {
        try {
            // Check if default admin exists
            $stmt = $conn->prepare("SELECT id FROM admin_users WHERE username = ?");
            $stmt->execute(['admin@123']);
            
            if ($stmt->rowCount() == 0) {
                // Create default admin
                $password_hash = password_hash('iamadmin', PASSWORD_DEFAULT);
                $stmt = $conn->prepare("
                    INSERT INTO admin_users (username, password_hash, email, full_name, role) 
                    VALUES (?, ?, ?, ?, ?)
                ");
                $stmt->execute([
                    'admin@123',
                    $password_hash,
                    'admin@velsphere.com',
                    'System Administrator',
                    'super_admin'
                ]);
            }
        } catch(PDOException $e) {
            error_log("Error creating default admin: " . $e->getMessage());
        }
    }
}

// classes/SecurityManager.php - Enhanced security utilities
class SecurityManager {
    private static $maxLoginAttempts = 5;
    private static $lockoutTime = 900; // 15 minutes
    
    public static function hashPassword($password) {
        return password_hash($password, PASSWORD_DEFAULT);
    }
    
    public static function verifyPassword($password, $hash) {
        return password_verify($password, $hash);
    }
    
    public static function generateToken($length = 32) {
        return bin2hex(random_bytes($length));
    }
    
    public static function sanitizeInput($input) {
        return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
    }
    
    public static function validateEmail($email) {
        return filter_var($email, FILTER_VALIDATE_EMAIL);
    }
    
    public static function validatePassword($password) {
        // At least 8 characters, one uppercase, one lowercase, one number
        return preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/', $password);
    }
    
    public static function checkRateLimit($pdo, $ip, $action, $maxAttempts = 5, $timeWindow = 300) {
        try {
            $stmt = $pdo->prepare("
                SELECT COUNT(*) as attempts 
                FROM audit_logs 
                WHERE ip_address = ? AND action = ? AND created_at > DATE_SUB(NOW(), INTERVAL ? SECOND)
            ");
            $stmt->execute([$ip, $action, $timeWindow]);
            $result = $stmt->fetch();
            
            return $result['attempts'] < $maxAttempts;
        } catch(PDOException $e) {
            error_log("Rate limit check error: " . $e->getMessage());
            return false;
        }
    }
    
    public static function logActivity($pdo, $userType, $userId, $action, $tableName = null, $recordId = null, $oldValues = null, $newValues = null) {
        try {
            $stmt = $pdo->prepare("
                INSERT INTO audit_logs (user_type, user_id, action, table_name, record_id, old_values, new_values, ip_address, user_agent) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ");
            
            $stmt->execute([
                $userType,
                $userId,
                $action,
                $tableName,
                $recordId,
                $oldValues ? json_encode($oldValues) : null,
                $newValues ? json_encode($newValues) : null,
                $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
            ]);
        } catch(PDOException $e) {
            error_log("Activity logging error: " . $e->getMessage());
        }
    }
    
    public static function generateBookingReference() {
        return 'VEL' . strtoupper(substr(md5(uniqid()), 0, 8));
    }
    
    public static function isValidCSRFToken($token) {
        return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
    }
    
    public static function generateCSRFToken() {
        if (!isset($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = self::generateToken();
        }
        return $_SESSION['csrf_token'];
    }
}

// classes/SessionManager.php - Secure session handling
class SessionManager {
    private $pdo;
    
    public function __construct($pdo) {
        $this->pdo = $pdo;
        $this->configureSession();
    }
    
    private function configureSession() {
        // Secure session configuration
        ini_set('session.cookie_httponly', 1);
        ini_set('session.cookie_secure', isset($_SERVER['HTTPS']));
        ini_set('session.cookie_samesite', 'Strict');
        ini_set('session.use_only_cookies', 1);
        ini_set('session.gc_maxlifetime', 3600); // 1 hour
        
        session_start();
    }
    
    public function createSession($userId, $userType = 'user') {
        try {
            $sessionId = session_id();
            $expiresAt = date('Y-m-d H:i:s', time() + 3600);
            
            // Clean up old sessions
            $this->cleanupExpiredSessions();
            
            // Create new session record
            $stmt = $this->pdo->prepare("
                INSERT INTO user_sessions (id, user_id, user_type, ip_address, user_agent, expires_at) 
                VALUES (?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE 
                expires_at = VALUES(expires_at), 
                is_active = TRUE
            ");
            
            $stmt->execute([
                $sessionId,
                $userId,
                $userType,
                $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
                $expiresAt
            ]);
            
            $_SESSION['user_id'] = $userId;
            $_SESSION['user_type'] = $userType;
            $_SESSION['login_time'] = time();
            
            return true;
        } catch(PDOException $e) {
            error_log("Session creation error: " . $e->getMessage());
            return false;
        }
    }
    
    public function validateSession() {
        if (!isset($_SESSION['user_id']) || !isset($_SESSION['user_type'])) {
            return false;
        }
        
        try {
            $stmt = $this->pdo->