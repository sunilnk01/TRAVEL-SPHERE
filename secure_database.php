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
            $stmt = $this->pdo->prepare("
                SELECT user_id, user_type, expires_at 
                FROM user_sessions 
                WHERE id = ? AND is_active = TRUE AND expires_at > NOW()
            ");
            $stmt->execute([session_id()]);
            $session = $stmt->fetch();
            
            if (!$session || $session['user_id'] != $_SESSION['user_id']) {
                $this->destroySession();
                return false;
            }
            
            // Extend session if valid
            $this->extendSession();
            return true;
            
        } catch(PDOException $e) {
            error_log("Session validation error: " . $e->getMessage());
            return false;
        }
    }
    
    public function extendSession() {
        try {
            $stmt = $this->pdo->prepare("
                UPDATE user_sessions 
                SET expires_at = DATE_ADD(NOW(), INTERVAL 1 HOUR) 
                WHERE id = ?
            ");
            $stmt->execute([session_id()]);
        } catch(PDOException $e) {
            error_log("Session extension error: " . $e->getMessage());
        }
    }
    
    public function destroySession() {
        try {
            if (session_id()) {
                $stmt = $this->pdo->prepare("UPDATE user_sessions SET is_active = FALSE WHERE id = ?");
                $stmt->execute([session_id()]);
            }
            
            $_SESSION = array();
            if (isset($_COOKIE[session_name()])) {
                setcookie(session_name(), '', time()-42000, '/');
            }
            session_destroy();
            
        } catch(PDOException $e) {
            error_log("Session destruction error: " . $e->getMessage());
        }
    }
    
    private function cleanupExpiredSessions() {
        try {
            $stmt = $this->pdo->prepare("DELETE FROM user_sessions WHERE expires_at < NOW()");
            $stmt->execute();
        } catch(PDOException $e) {
            error_log("Session cleanup error: " . $e->getMessage());
        }
    }
}

// classes/UserManager.php - User management with enhanced security
class UserManager {
    private $pdo;
    private $securityManager;
    
    public function __construct($pdo) {
        $this->pdo = $pdo;
        $this->securityManager = new SecurityManager();
    }
    
    public function registerUser($data) {
        try {
            // Validate input
            $errors = $this->validateUserData($data);
            if (!empty($errors)) {
                return ['success' => false, 'errors' => $errors];
            }
            
            // Check if user already exists
            if ($this->userExists($data['username'], $data['email'])) {
                return ['success' => false, 'errors' => ['User already exists with this username or email']];
            }
            
            // Hash password
            $passwordHash = SecurityManager::hashPassword($data['password']);
            $verificationToken = SecurityManager::generateToken();
            
            $stmt = $this->pdo->prepare("
                INSERT INTO users (username, password_hash, email, full_name, phone, address, verification_token) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ");
            
            $stmt->execute([
                SecurityManager::sanitizeInput($data['username']),
                $passwordHash,
                strtolower(trim($data['email'])),
                SecurityManager::sanitizeInput($data['full_name']),
                SecurityManager::sanitizeInput($data['phone']),
                SecurityManager::sanitizeInput($data['address']),
                $verificationToken
            ]);
            
            $userId = $this->pdo->lastInsertId();
            
            SecurityManager::logActivity($this->pdo, 'user', $userId, 'user_registered', 'users', $userId);
            
            return ['success' => true, 'user_id' => $userId, 'verification_token' => $verificationToken];
            
        } catch(PDOException $e) {
            error_log("User registration error: " . $e->getMessage());
            return ['success' => false, 'errors' => ['Registration failed. Please try again.']];
        }
    }
    
    public function authenticateUser($username, $password) {
        try {
            $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            
            // Rate limiting
            if (!SecurityManager::checkRateLimit($this->pdo, $ip, 'login_attempt', 5, 300)) {
                return ['success' => false, 'message' => 'Too many login attempts. Please try again later.'];
            }
            
            $stmt = $this->pdo->prepare("
                SELECT id, username, password_hash, email, full_name, is_active, failed_login_attempts, last_login_attempt 
                FROM users 
                WHERE (username = ? OR email = ?) AND is_active = TRUE
            ");
            $stmt->execute([$username, $username]);
            $user = $stmt->fetch();
            
            // Log login attempt
            SecurityManager::logActivity($this->pdo, 'user', $user['id'] ?? null, 'login_attempt');
            
            if (!$user) {
                return ['success' => false, 'message' => 'Invalid credentials'];
            }
            
            // Check account lockout
            if ($user['failed_login_attempts'] >= 5 && 
                strtotime($user['last_login_attempt']) > (time() - 900)) {
                return ['success' => false, 'message' => 'Account temporarily locked. Please try again later.'];
            }
            
            if (SecurityManager::verifyPassword($password, $user['password_hash'])) {
                // Reset failed attempts on successful login
                $this->resetFailedAttempts($user['id']);
                
                SecurityManager::logActivity($this->pdo, 'user', $user['id'], 'login_success');
                
                return [
                    'success' => true,
                    'user' => [
                        'id' => $user['id'],
                        'username' => $user['username'],
                        'email' => $user['email'],
                        'full_name' => $user['full_name']
                    ]
                ];
            } else {
                $this->incrementFailedAttempts($user['id']);
                return ['success' => false, 'message' => 'Invalid credentials'];
            }
            
        } catch(PDOException $e) {
            error_log("Authentication error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Authentication failed. Please try again.'];
        }
    }
    
    private function validateUserData($data) {
        $errors = [];
        
        if (empty($data['username']) || strlen($data['username']) < 3) {
            $errors[] = 'Username must be at least 3 characters long';
        }
        
        if (!SecurityManager::validateEmail($data['email'])) {
            $errors[] = 'Please enter a valid email address';
        }
        
        if (!SecurityManager::validatePassword($data['password'])) {
            $errors[] = 'Password must be at least 8 characters with uppercase, lowercase, and number';
        }
        
        if (empty($data['full_name'])) {
            $errors[] = 'Full name is required';
        }
        
        if (empty($data['phone']) || !preg_match('/^\+?[\d\s\-\(\)]{10,}$/', $data['phone'])) {
            $errors[] = 'Please enter a valid phone number';
        }
        
        return $errors;
    }
    
    private function userExists($username, $email) {
        $stmt = $this->pdo->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
        $stmt->execute([$username, strtolower(trim($email))]);
        return $stmt->rowCount() > 0;
    }
    
    private function incrementFailedAttempts($userId) {
        $stmt = $this->pdo->prepare("
            UPDATE users 
            SET failed_login_attempts = failed_login_attempts + 1, last_login_attempt = NOW() 
            WHERE id = ?
        ");
        $stmt->execute([$userId]);
    }
    
    private function resetFailedAttempts($userId) {
        $stmt = $this->pdo->prepare("
            UPDATE users 
            SET failed_login_attempts = 0, last_login_attempt = NULL 
            WHERE id = ?
        ");
        $stmt->execute([$userId]);
    }
    
    public function getUserById($userId) {
        try {
            $stmt = $this->pdo->prepare("
                SELECT id, username, email, full_name, phone, address, created_at 
                FROM users 
                WHERE id = ? AND is_active = TRUE
            ");
            $stmt->execute([$userId]);
            return $stmt->fetch();
        } catch(PDOException $e) {
            error_log("Get user error: " . $e->getMessage());
            return false;
        }
    }
}

// classes/BookingManager.php - Enhanced booking management
class BookingManager {
    private $pdo;
    
    public function __construct($pdo) {
        $this->pdo = $pdo;
    }
    
    public function createBooking($data) {
        try {
            $this->pdo->beginTransaction();
            
            // Validate booking data
            $errors = $this->validateBookingData($data);
            if (!empty($errors)) {
                return ['success' => false, 'errors' => $errors];
            }
            
            // Calculate total cost
            $totalCost = $this->calculateCost($data);
            $bookingReference = SecurityManager::generateBookingReference();
            
            $stmt = $this->pdo->prepare("
                INSERT INTO bookings (
                    user_id, booking_reference, destination, package_type, 
                    guests, check_in, check_out, total_cost, special_requests
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ");
            
            $stmt->execute([
                $data['user_id'],
                $bookingReference,
                SecurityManager::sanitizeInput($data['destination']),
                $data['package_type'],
                (int)$data['guests'],
                $data['check_in'],
                $data['check_out'],
                $totalCost,
                SecurityManager::sanitizeInput($data['special_requests'] ?? '')
            ]);
            
            $bookingId = $this->pdo->lastInsertId();
            
            SecurityManager::logActivity(
                $this->pdo, 
                'user', 
                $data['user_id'], 
                'booking_created', 
                'bookings', 
                $bookingId, 
                null, 
                $data
            );
            
            $this->pdo->commit();
            
            return [
                'success' => true,
                'booking_id' => $bookingId,
                'booking_reference' => $bookingReference,
                'total_cost' => $totalCost
            ];
            
        } catch(PDOException $e) {
            $this->pdo->rollback();
            error_log("Booking creation error: " . $e->getMessage());
            return ['success' => false, 'errors' => ['Booking failed. Please try again.']];
        }
    }
    
    private function calculateCost($data) {
        $baseRates = [
            'city1' => 2000,
            'city2' => 3000,
            'city3' => 4000,
            'city4' => 2500,
            'city5' => 5000,
            'city6' => 3500
        ];
        
        $packageMultipliers = [
            'economic' => 1.0,
            'semi-deluxe' => 1.8,
            'deluxe' => 3.0
        ];
        
        $baseRate = $baseRates[$data['destination']] ?? 2000;
        $multiplier = $packageMultipliers[$data['package_type']] ?? 1.0;
        $guests = (int)$data['guests'];
        
        $checkIn = new DateTime($data['check_in']);
        $checkOut = new DateTime($data['check_out']);
        $days = $checkIn->diff($checkOut)->days;
        
        return $baseRate * $multiplier * $guests * max(1, $days);
    }
    
    private function validateBookingData($data) {
        $errors = [];
        
        if (empty($data['destination'])) {
            $errors[] = 'Please select a destination';
        }
        
        if (!in_array($data['package_type'], ['economic', 'semi-deluxe', 'deluxe'])) {
            $errors[] = 'Please select a valid package type';
        }
        
        if (empty($data['guests']) || $data['guests'] < 1 || $data['guests'] > 20) {
            $errors[] = 'Number of guests must be between 1 and 20';
        }
        
        if (empty($data['check_in']) || empty($data['check_out'])) {
            $errors[] = 'Please select check-in and check-out dates';
        } else {
            $checkIn = new DateTime($data['check_in']);
            $checkOut = new DateTime($data['check_out']);
            $today = new DateTime();
            
            if ($checkIn < $today) {
                $errors[] = 'Check-in date must be in the future';
            }
            
            if ($checkOut <= $checkIn) {
                $errors[] = 'Check-out date must be after check-in date';
            }
        }
        
        return $errors;
    }
    
    public function getUserBookings($userId) {
        try {
            $stmt = $this->pdo->prepare("
                SELECT * FROM bookings 
                WHERE user_id = ? 
                ORDER BY created_at DESC
            ");
            $stmt->execute([$userId]);
            return $stmt->fetchAll();
        } catch(PDOException $e) {
            error_log("Get user bookings error: " . $e->getMessage());
            return [];
        }
    }
    
    public function updateBookingStatus($bookingId, $status, $userId = null) {
        try {
            $sql = "UPDATE bookings SET booking_status = ?, updated_at = NOW() WHERE id = ?";
            $params = [$status, $bookingId];
            
            if ($userId) {
                $sql .= " AND user_id = ?";
                $params[] = $userId;
            }
            
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute($params);
            
            return $stmt->rowCount() > 0;
        } catch(PDOException $e) {
            error_log("Update booking status error: " . $e->getMessage());
            return false;
        }
    }
}