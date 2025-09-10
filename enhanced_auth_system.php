<?php
// auth/login.php - Enhanced login with rate limiting and CSRF protection
session_start();
require_once '../config/database.php';
require_once '../classes/SecurityManager.php';
require_once '../classes/SessionManager.php';
require_once '../classes/UserManager.php';

header('Content-Type: application/json');

try {
    // Initialize database and managers
    $database = new Database();
    $pdo = $database->getConnection();
    $sessionManager = new SessionManager($pdo);
    $userManager = new UserManager($pdo);
    
    // Check request method
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception('Invalid request method');
    }
    
    // Validate CSRF token
    if (!SecurityManager::isValidCSRFToken($_POST['csrf_token'] ?? '')) {
        throw new Exception('Invalid security token');
    }
    
    // Get and validate input
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    
    if (empty($username) || empty($password)) {
        throw new Exception('Username and password are required');
    }
    
    // Attempt authentication
    $result = $userManager->authenticateUser($username, $password);
    
    if ($result['success']) {
        // Create secure session
        $sessionCreated = $sessionManager->createSession($result['user']['id'], 'user');
        
        if ($sessionCreated) {
            // Store user data in session
            $_SESSION['user_data'] = $result['user'];
            
            echo json_encode([
                'success' => true,
                'message' => 'Login successful',
                'redirect' => '/dashboard.php'
            ]);
        } else {
            throw new Exception('Session creation failed');
        }
    } else {
        echo json_encode([
            'success' => false,
            'message' => $result['message']
        ]);
    }
    
} catch (Exception $e) {
    error_log("Login error: " . $e->getMessage());
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ]);
}

// auth/register.php - Enhanced registration with email verification
session_start();
require_once '../config/database.php';
require_once '../classes/SecurityManager.php';
require_once '../classes/UserManager.php';

header('Content-Type: application/json');

try {
    $database = new Database();
    $pdo = $database->getConnection();
    $userManager = new UserManager($pdo);
    
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception('Invalid request method');
    }
    
    // Validate CSRF token
    if (!SecurityManager::isValidCSRFToken($_POST['csrf_token'] ?? '')) {
        throw new Exception('Invalid security token');
    }
    
    // Collect and sanitize form data
    $userData = [
        'username' => SecurityManager::sanitizeInput($_POST['username'] ?? ''),
        'email' => strtolower(trim($_POST['email'] ?? '')),
        'password' => $_POST['password'] ?? '',
        'full_name' => SecurityManager::sanitizeInput($_POST['full_name'] ?? ''),
        'phone' => SecurityManager::sanitizeInput($_POST['phone'] ?? ''),
        'address' => SecurityManager::sanitizeInput($_POST['address'] ?? '')
    ];
    
    // Attempt registration
    $result = $userManager->registerUser($userData);
    
    if ($result['success']) {
        // Send verification email (placeholder)
        // $this->sendVerificationEmail($userData['email'], $result['verification_token']);
        
        echo json_encode([
            'success' => true,
            'message' => 'Registration successful. Please check your email for verification.',
            'redirect' => '/login.php'
        ]);
    } else {
        echo json_encode([
            'success' => false,
            'errors' => $result['errors']
        ]);
    }
    
} catch (Exception $e) {
    error_log("Registration error: " . $e->getMessage());
    echo json_encode([
        'success' => false,
        'message' => 'Registration failed. Please try again.'
    ]);
}

// dashboard.php - User dashboard with booking management
session_start();
require_once 'config/database.php';
require_once 'classes/SessionManager.php';
require_once 'classes/BookingManager.php';
require_once 'classes/SecurityManager.php';

$database = new Database();
$pdo = $database->getConnection();
$sessionManager = new SessionManager($pdo);

// Validate session
if (!$sessionManager->validateSession()) {
    header('Location: /login.php');
    exit;
}

$bookingManager = new BookingManager($pdo);
$userBookings = $bookingManager->getUserBookings($_SESSION['user_id']);
$csrfToken = SecurityManager::generateCSRFToken();

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - VEL SPHERE</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary-color: #2c5aa0;
            --secondary-color: #f39c12;
            --success-color: #27ae60;
            --warning-color: #f39c12;
            --danger-color: #e74c3c;
        }

        .dashboard-nav {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 1rem 0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            margin-bottom: 2rem;
            transition: transform 0.2s ease;
        }

        .card:hover {
            transform: translateY(-5px);
        }

        .booking-card {
            border-left: 4px solid var(--primary-color);
        }

        .booking-card.pending {
            border-left-color: var(--warning-color);
        }

        .booking-card.confirmed {
            border-left-color: var(--success-color);
        }

        .booking-card.cancelled {
            border-left-color: var(--danger-color);
        }

        .stats-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }

        .btn-modern {
            border-radius: 25px;
            padding: 0.5rem 1.5rem;
            font-weight: 600;
            border: none;
            transition: all 0.3s ease;
        }

        .btn-primary {
            background: var(--primary-color);
        }

        .btn-primary:hover {
            background: #1e4080;
            transform: translateY(-2px);
        }

        .alert {
            border-radius: 15px;
            border: none;
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="dashboard-nav">
        <div class="container">
            <div class="d-flex justify-content-between align-items-center text-white">
                <div>
                    <h4 class="mb-0">Welcome, <?php echo htmlspecialchars($_SESSION['user_data']['full_name']); ?>!</h4>
                    <small>VEL SPHERE Dashboard</small>
                </div>
                <div>
                    <a href="/packages.php" class="btn btn-outline-light btn-modern me-2">Browse Packages</a>
                    <a href="/profile.php" class="btn btn-outline-light btn-modern me-2">Profile</a>
                    <a href="/auth/logout.php" class="btn btn-light btn-modern">Logout</a>
                </div>
            </div>
        </div>
    </nav>

    <div class="container py-5">
        <div class="row">
            <!-- Statistics Cards -->
            <div class="col-md-3">
                <div class="card stats-card">
                    <div class="card-body text-center">
                        <i class="fas fa-calendar-check fa-2x mb-3"></i>
                        <h3><?php echo count($userBookings); ?></h3>
                        <p class="mb-0">Total Bookings</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stats-card">
                    <div class="card-body text-center">
                        <i class="fas fa-clock fa-2x mb-3"></i>
                        <h3><?php echo count(array_filter($userBookings, fn($b) => $b['booking_status'] === 'pending')); ?></h3>
                        <p class="mb-0">Pending</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stats-card">
                    <div class="card-body text-center">
                        <i class="fas fa-check-circle fa-2x mb-3"></i>
                        <h3><?php echo count(array_filter($userBookings, fn($b) => $b['booking_status'] === 'confirmed')); ?></h3>
                        <p class="mb-0">Confirmed</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stats-card">
                    <div class="card-body text-center">
                        <i class="fas fa-map-marker-alt fa-2x mb-3"></i>
                        <h3><?php echo count(array_unique(array_column($userBookings, 'destination'))); ?></h3>
                        <p class="mb-0">Destinations</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Quick Actions -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Quick Actions</h5>
                        <div class="d-flex flex-wrap gap-3">
                            <button class="btn btn-primary btn-modern" onclick="showBookingModal()">
                                <i class="fas fa-plus me-2"></i>New Booking
                            </button>
                            <a href="/packages.php" class="btn btn-outline-primary btn-modern">
                                <i class="fas fa-search me-2"></i>Browse Packages
                            </a>
                            <a href="/profile.php" class="btn btn-outline-secondary btn-modern">
                                <i class="fas fa-user me-2"></i>Update Profile
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Recent Bookings -->
        <div class="row">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Your Bookings</h5>
                    </div>
                    <div class="card-body">
                        <?php if (empty($userBookings)): ?>
                            <div class="text-center py-5">
                                <i class="fas fa-calendar-times fa-3x text-muted mb-3"></i>
                                <h5>No bookings yet</h5>
                                <p class="text-muted">Start planning your next adventure!</p>
                                <button class="btn btn-primary btn-modern" onclick="showBookingModal()">Book Your First Trip</button>
                            </div>
                        <?php else: ?>
                            <div class="row">
                                <?php foreach ($userBookings as $booking): ?>
                                    <div class="col-md-6 col-lg-4">
                                        <div class="card booking-card <?php echo $booking['booking_status']; ?>">
                                            <div class="card-body">
                                                <div class="d-flex justify-content-between align-items-start mb-3">
                                                    <h6 class="text-uppercase fw-bold"><?php echo htmlspecialchars($booking['destination']); ?></h6>
                                                    <span class="badge bg-<?php echo $booking['booking_status'] === 'confirmed' ? 'success' : ($booking['booking_status'] === 'pending' ? 'warning' : 'danger'); ?>">
                                                        <?php echo ucfirst($booking['booking_status']); ?>
                                                    </span>
                                                </div>
                                                <p class="mb-1"><strong>Reference:</strong> <?php echo htmlspecialchars($booking['booking_reference']); ?></p>
                                                <p class="mb-1"><strong>Package:</strong> <?php echo ucwords(str_replace('-', ' ', $booking['package_type'])); ?></p>
                                                <p class="mb-1"><strong>Guests:</strong> <?php echo $booking['guests']; ?></p>
                                                <p class="mb-1"><strong>Dates:</strong> <?php echo date('M d, Y', strtotime($booking['check_in'])); ?> - <?php echo date('M d, Y', strtotime($booking['check_out'])); ?></p>
                                                <p class="mb-3"><strong>Total:</strong> ₹<?php echo number_format($booking['total_cost']); ?></p>
                                                
                                                <div class="d-flex gap-2">
                                                    <button class="btn btn-outline-primary btn-sm btn-modern" onclick="viewBooking('<?php echo $booking['id']; ?>')">
                                                        <i class="fas fa-eye me-1"></i>View
                                                    </button>
                                                    <?php if ($booking['booking_status'] === 'pending'): ?>
                                                        <button class="btn btn-outline-danger btn-sm btn-modern" onclick="cancelBooking('<?php echo $booking['id']; ?>')">
                                                            <i class="fas fa-times me-1"></i>Cancel
                                                        </button>
                                                    <?php endif; ?>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Booking Modal -->
    <div class="modal fade" id="bookingModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Create New Booking</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="bookingForm">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                