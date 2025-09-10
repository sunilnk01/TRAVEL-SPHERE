<?php
// .env.example - Environment variables template
?>
# Database Configuration
DB_HOST=localhost
DB_NAME=vel_sphere_db
DB_USER=root
DB_PASS=
DB_CHARSET=utf8mb4

# Application Settings
APP_NAME="VEL SPHERE"
APP_ENV=development
APP_DEBUG=true
APP_URL=http://localhost:8000

# Security Keys (Generate new ones for production)
APP_KEY=base64:your-32-character-secret-key-here
CSRF_SECRET=your-csrf-secret-key-here

# Mail Configuration
MAIL_MAILER=smtp
MAIL_HOST=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_ENCRYPTION=tls
MAIL_FROM_ADDRESS=noreply@velsphere.com
MAIL_FROM_NAME="${APP_NAME}"

# Payment Gateway (for future implementation)
STRIPE_KEY=your-stripe-publishable-key
STRIPE_SECRET=your-stripe-secret-key
RAZORPAY_KEY=your-razorpay-key
RAZORPAY_SECRET=your-razorpay-secret

<?php
// composer.json - PHP dependencies
?>
{
    "name": "velsphere/travel-booking",
    "description": "Modern travel booking platform with enhanced security",
    "type": "project",
    "license": "MIT",
    "require": {
        "php": ">=8.0",
        "ext-pdo": "*",
        "ext-json": "*",
        "ext-openssl": "*",
        "vlucas/phpdotenv": "^5.4",
        "phpmailer/phpmailer": "^6.6",
        "league/csv": "^9.8",
        "monolog/monolog": "^2.8"
    },
    "require-dev": {
        "phpunit/phpunit": "^9.5",
        "phpstan/phpstan": "^1.8",
        "squizlabs/php_codesniffer": "^3.7"
    },
    "autoload": {
        "psr-4": {
            "VelSphere\\": "src/",
            "VelSphere\\Config\\": "config/",
            "VelSphere\\Classes\\": "classes/"
        }
    },
    "scripts": {
        "test": "phpunit",
        "lint": "phpcs --standard=PSR12 src/",
        "analyse": "phpstan analyse src/",
        "install-db": "php scripts/install-database.php",
        "serve": "php -S localhost:8000 -t public/"
    }
}

<?php
// scripts/install-database.php - Database setup script
require_once __DIR__ . '/../vendor/autoload.php';

use Dotenv\Dotenv;

// Load environment variables
$dotenv = Dotenv::createImmutable(__DIR__ . '/..');
$dotenv->load();

echo "VEL SPHERE Database Installation\n";
echo "================================\n\n";

try {
    // Connect to MySQL server (without database)
    $pdo = new PDO(
        "mysql:host=" . $_ENV['DB_HOST'],
        $_ENV['DB_USER'],
        $_ENV['DB_PASS'],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
    
    echo "✓ Connected to MySQL server\n";
    
    // Create database
    $dbName = $_ENV['DB_NAME'];
    $pdo->exec("CREATE DATABASE IF NOT EXISTS `$dbName` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
    echo "✓ Database '$dbName' created/verified\n";
    
    // Connect to the specific database
    $pdo = new PDO(
        "mysql:host=" . $_ENV['DB_HOST'] . ";dbname=" . $_ENV['DB_NAME'] . ";charset=utf8mb4",
        $_ENV['DB_USER'],
        $_ENV['DB_PASS'],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
    
    // Read and execute SQL file
    $sqlFile = __DIR__ . '/database-schema.sql';
    if (file_exists($sqlFile)) {
        $sql = file_get_contents($sqlFile);
        $statements = array_filter(array_map('trim', explode(';', $sql)));
        
        foreach ($statements as $statement) {
            if (!empty($statement)) {
                $pdo->exec($statement);
            }
        }
        echo "✓ Database schema installed\n";
    }
    
    // Create default admin user
    $adminUsername = 'admin@123';
    $adminPassword = password_hash('iamadmin', PASSWORD_DEFAULT);
    
    $stmt = $pdo->prepare("
        INSERT IGNORE INTO admin_users (username, password_hash, email, full_name, role) 
        VALUES (?, ?, ?, ?, ?)
    ");
    
    $stmt->execute([
        $adminUsername,
        $adminPassword,
        'admin@velsphere.com',
        'System Administrator',
        'super_admin'
    ]);
    
    echo "✓ Default admin user created (admin@123 / iamadmin)\n";
    echo "\n🎉 Installation completed successfully!\n";
    echo "You can now access the application at: " . $_ENV['APP_URL'] . "\n";
    
} catch (PDOException $e) {
    echo "❌ Database error: " . $e->getMessage() . "\n";
    exit(1);
} catch (Exception $e) {
    echo "❌ Installation error: " . $e->getMessage() . "\n";
    exit(1);
}

<?php
// scripts/database-schema.sql - Complete database schema
?>
-- VEL SPHERE Database Schema
-- Generated for enhanced travel booking platform

SET FOREIGN_KEY_CHECKS = 0;

-- Users table with enhanced security
CREATE TABLE IF NOT EXISTS `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(50) UNIQUE NOT NULL,
    `password_hash` VARCHAR(255) NOT NULL,
    `email` VARCHAR(100) UNIQUE NOT NULL,
    `full_name` VARCHAR(100) NOT NULL,
    `phone` VARCHAR(15) NOT NULL,
    `address` TEXT,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    `is_active` BOOLEAN DEFAULT TRUE,
    `failed_login_attempts` INT DEFAULT 0,
    `last_login_attempt` TIMESTAMP NULL,
    `email_verified` BOOLEAN DEFAULT FALSE,
    `verification_token` VARCHAR(255) NULL,
    `last_login` TIMESTAMP NULL,
    INDEX `idx_username` (`username`),
    INDEX `idx_email` (`email`),
    INDEX `idx_is_active` (`is_active`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Bookings table with comprehensive tracking
CREATE TABLE IF NOT EXISTS `bookings` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `booking_reference` VARCHAR(20) UNIQUE NOT NULL,
    `destination` VARCHAR(50) NOT NULL,
    `package_type` ENUM('economic', 'semi-deluxe', 'deluxe') NOT NULL,
    `guests` INT NOT NULL,
    `check_in` DATE NOT NULL,
    `check_out` DATE NOT NULL,
    `total_cost` DECIMAL(10,2) NOT NULL,
    `booking_status` ENUM('pending', 'confirmed', 'cancelled', 'completed') DEFAULT 'pending',
    `payment_status` ENUM('pending', 'paid', 'failed', 'refunded') DEFAULT 'pending',
    `payment_reference` VARCHAR(100) NULL,
    `special_requests` TEXT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    INDEX `idx_user_id` (`user_id`),
    INDEX `idx_booking_ref` (`booking_reference`),
    INDEX `idx_booking_status` (`booking_status`),
    INDEX `idx_dates` (`check_in`, `check_out`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Admin users table
CREATE TABLE IF NOT EXISTS `admin_users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(50) UNIQUE NOT NULL,
    `password_hash` VARCHAR(255) NOT NULL,
    `email` VARCHAR(100) UNIQUE NOT NULL,
    `full_name` VARCHAR(100) NOT NULL,
    `role` ENUM('super_admin', 'admin', 'moderator') DEFAULT 'admin',
    `is_active` BOOLEAN DEFAULT TRUE,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `last_login` TIMESTAMP NULL,
    `permissions` JSON NULL,
    INDEX `idx_username` (`username`),
    INDEX `idx_role` (`role`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Audit logs for security tracking
CREATE TABLE IF NOT EXISTS `audit_logs` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_type` ENUM('user', 'admin', 'system') NOT NULL,
    `user_id` INT NULL,
    `action` VARCHAR(100) NOT NULL,
    `table_name` VARCHAR(50) NULL,
    `record_id` INT NULL,
    `old_values` JSON NULL,
    `new_values` JSON NULL,
    `ip_address` VARCHAR(45) NOT NULL,
    `user_agent` TEXT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_user_type_id` (`user_type`, `user_id`),
    INDEX `idx_action` (`action`),
    INDEX `idx_created_at` (`created_at`),
    INDEX `idx_ip_address` (`ip_address`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- User sessions for secure session management
CREATE TABLE IF NOT EXISTS `user_sessions` (
    `id` VARCHAR(128) PRIMARY KEY,
    `user_id` INT NOT NULL,
    `user_type` ENUM('user', 'admin') NOT NULL,
    `ip_address` VARCHAR(45) NOT NULL,
    `user_agent` TEXT NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `expires_at` TIMESTAMP NOT NULL,
    `is_active` BOOLEAN DEFAULT TRUE,
    `last_activity` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_user_id` (`user_id`),
    INDEX `idx_expires` (`expires_at`),
    INDEX `idx_is_active` (`is_active`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Destinations table for package management
CREATE TABLE IF NOT EXISTS `destinations` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `code` VARCHAR(20) UNIQUE NOT NULL,
    `name` VARCHAR(100) NOT NULL,
    `description` TEXT,
    `image_url` VARCHAR(255),
    `base_price` DECIMAL(10,2) NOT NULL,
    `is_active` BOOLEAN DEFAULT TRUE,
    `meta_title` VARCHAR(200),
    `meta_description` TEXT,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_code` (`code`),
    INDEX `idx_is_active` (`is_active`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Package types configuration
CREATE TABLE IF NOT EXISTS `package_types` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `code` VARCHAR(20) UNIQUE NOT NULL,
    `name` VARCHAR(50) NOT NULL,
    `description` TEXT,
    `price_multiplier` DECIMAL(3,2) NOT NULL DEFAULT 1.00,
    `features` JSON,
    `is_active` BOOLEAN DEFAULT TRUE,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_code` (`code`),
    INDEX `idx_is_active` (`is_active`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Email templates
CREATE TABLE IF NOT EXISTS `email_templates` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `code` VARCHAR(50) UNIQUE NOT NULL,
    `subject` VARCHAR(200) NOT NULL,
    `body` TEXT NOT NULL,
    `variables` JSON,
    `is_active` BOOLEAN DEFAULT TRUE,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_code` (`code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- System settings
CREATE TABLE IF NOT EXISTS `system_settings` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `key` VARCHAR(100) UNIQUE NOT NULL,
    `value` TEXT,
    `type` ENUM('string', 'number', 'boolean', 'json') DEFAULT 'string',
    `description` TEXT,
    `is_public` BOOLEAN DEFAULT FALSE,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_key` (`key`),
    INDEX `idx_is_public` (`is_public`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET FOREIGN_KEY_CHECKS = 1;

-- Insert default data
INSERT IGNORE INTO `destinations` (`code`, `name`, `description`, `base_price`, `meta_title`, `meta_description`) VALUES
('city1', 'Paradise City', 'Experience the beauty of pristine beaches and crystal-clear waters in this tropical paradise.', 2000.00, 'Paradise City - Tropical Beach Destination', 'Book your tropical getaway to Paradise City with pristine beaches and crystal waters.'),
('city2', 'Mountain Retreat', 'Escape to the serene mountains with breathtaking views and peaceful surroundings.', 3000.00, 'Mountain Retreat - Scenic Mountain Escape', 'Discover peace and tranquility in our mountain retreat destination.'),
('city3', 'Cultural Heritage', 'Immerse yourself in rich cultural heritage and historical landmarks.', 4000.00, 'Cultural Heritage Tours - Historical Destinations', 'Explore rich cultural heritage and ancient historical landmarks.'),
('city4', 'Adventure Hub', 'Thrilling adventures and exciting activities in a vibrant urban setting.', 2500.00, 'Adventure Hub - Thrilling Urban Adventures', 'Experience thrilling adventures and exciting activities in our adventure hub.'),
('city5', 'Luxury Resort', 'Ultimate luxury experience with world-class amenities and service.', 5000.00, 'Luxury Resort Experience - Premium Travel', 'Indulge in ultimate luxury with world-class amenities and premium service.'),
('city6', 'Coastal Paradise', 'Beautiful coastal views with perfect beaches and water sports.', 3500.00, 'Coastal Paradise - Beach and Water Sports', 'Enjoy beautiful coastal views with perfect beaches and exciting water sports.');

INSERT IGNORE INTO `package_types` (`code`, `name`, `description`, `price_multiplier`, `features`) VALUES
('economic', 'Economic Package', 'Budget-friendly package with essential amenities', 1.00, '["Standard accommodation", "Basic meals", "Local transportation", "Standard guide"]'),
('semi-deluxe', 'Semi-Deluxe Package', 'Mid-range package with enhanced comfort', 1.80, '["Premium accommodation", "All meals included", "AC transportation", "Expert guide", "Welcome drink"]'),
('deluxe', 'Deluxe Package', 'Luxury package with premium services', 3.00, '["Luxury accommodation", "Fine dining", "Private transportation", "Personal guide", "Spa services", "Airport transfer"]');

INSERT IGNORE INTO `system_settings` (`key`, `value`, `type`, `description`, `is_public`) VALUES
('site_name', 'VEL SPHERE', 'string', 'Website name', TRUE),
('site_tagline', 'Your Gateway to Amazing Destinations', 'string', 'Website tagline', TRUE),
('contact_email', 'info@velsphere.com', 'string', 'Contact email address', TRUE),
('contact_phone', '+91 123-456-7890', 'string', 'Contact phone number', TRUE),
('booking_cancellation_hours', '24', 'number', 'Hours before check-in to allow free cancellation', FALSE),
('max_guests_per_booking', '20', 'number', 'Maximum guests allowed per booking', FALSE),
('email_verification_required', '1', 'boolean', 'Require email verification for new users', FALSE);

INSERT IGNORE INTO `email_templates` (`code`, `subject`, `body`, `variables`) VALUES
('welcome', 'Welcome to VEL SPHERE!', 'Dear {{full_name}},\n\nWelcome to VEL SPHERE! Your account has been successfully created.\n\nYour login details:\nUsername: {{username}}\nEmail: {{email}}\n\nStart exploring our amazing destinations and book your next adventure!\n\nBest regards,\nVEL SPHERE Team', '["full_name", "username", "email"]'),
('booking_confirmation', 'Booking Confirmed - {{booking_reference}}', 'Dear {{full_name}},\n\nYour booking has been confirmed!\n\nBooking Reference: {{booking_reference}}\nDestination: {{destination}}\nPackage: {{package_type}}\nGuests: {{guests}}\nCheck-in: {{check_in}}\nCheck-out: {{check_out}}\nTotal Cost: ₹{{total_cost}}\n\nWe look forward to providing you with an amazing travel experience!\n\nBest regards,\nVEL SPHERE Team', '["full_name", "booking_reference", "destination", "package_type", "guests", "check_in", "check_out", "total_cost"]');

<?php
// .gitignore - Version control ignore file
?>
# Environment files
.env
.env.local
.env.production

# Composer
/vendor/
composer.lock

# Logs
/logs/
*.log

# Cache
/cache/
/tmp/

# IDE files
.vscode/
.idea/
*.swp
*.swo
*~

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Uploads
/public/uploads/
!/public/uploads/.gitkeep

# Node modules (if using frontend build tools)
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Build files
/public/build/
/public/hot

# Testing
/coverage/
.phpunit.result.cache

# Security
private.key
public.key
*.pem

<?php
// public/.htaccess - Apache configuration
?>
RewriteEngine On

# Handle Angular and Laravel / Symfony routes
RewriteCond %{REQUEST_FILENAME} !-d
RewriteCond %{REQUEST_FILENAME} !-f
RewriteRule ^(.*)$ index.php?route=$1 [QSA,L]

# Security Headers
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"  
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"

# HSTS (HTTP Strict Transport Security)
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

# Prevent access to sensitive files
<Files "*.env*">
    Order allow,deny
    Deny from all
</Files>

<Files "composer.*">
    Order allow,deny  
    Deny from all
</Files>

<Files "*.md">
    Order allow,deny
    Deny from all
</Files>

# Enable compression
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/plain
    AddOutputFilterByType DEFLATE text/html
    AddOutputFilterByType DEFLATE text/xml
    AddOutputFilterByType DEFLATE text/css
    AddOutputFilterByType DEFLATE application/xml
    AddOutputFilterByType DEFLATE application/xhtml+xml
    AddOutputFilterByType DEFLATE application/rss+xml
    AddOutputFilterByType DEFLATE application/javascript
    AddOutputFilterByType DEFLATE application/x-javascript
</IfModule>

# Browser caching
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
    ExpiresByType image/png "access plus 1 year"
    ExpiresByType image/jpg "access plus 1 year"
    ExpiresByType image/jpeg "access plus 1 year"
    ExpiresByType image/gif "access plus 1 year"
    ExpiresByType image/svg+xml "access plus 1 year"
</IfModule>