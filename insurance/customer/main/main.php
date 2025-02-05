<?php
session_start();

// Security: Add CSRF protection
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if (!isset($_SESSION['customerEmail'])) {
    header("Location: ../login/login.php");
    exit();
}

$currentUserEmail = $_SESSION['customerEmail'];

require_once('dp.php');

// Consolidated database queries using functions
function getUserInfo($conn, $email) {
    $sql = "SELECT customerEmail FROM customer WHERE customerEmail = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    $userInfo = $result->fetch_assoc();
    $stmt->close();
    return $userInfo;
}

function getPolicyInfo($conn, $email) {
    $sql = "SELECT policyNumber, amountDue, coverageDetails, expiryDate FROM policy WHERE customerEmail = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    $policyInfo = $result->fetch_assoc();
    $stmt->close();
    return $policyInfo;
}

function getClaims($conn, $email) {
    $sql = "SELECT claimId, status, submissionDate, claimDetails FROM claims WHERE customerEmail = ? ORDER BY submissionDate DESC";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    $claims = $result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
    return $claims;
}

// Fetch all user data
$userInfo = getUserInfo($conn, $currentUserEmail);
$policyInfo = getPolicyInfo($conn, $currentUserEmail);
$claims = getClaims($conn, $currentUserEmail);

// Handle form submissions with CSRF protection
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('CSRF token validation failed');
    }

    if (isset($_POST['make_payment'])) {
        // Validate payment data
        $policyNumber = filter_input(INPUT_POST, 'policyNumber', FILTER_SANITIZE_STRING);
        $amountDue = filter_input(INPUT_POST, 'amountDue', FILTER_VALIDATE_FLOAT);
        
        if ($policyNumber && $amountDue) {
            // Add payment processing logic here
            $sql = "UPDATE policy SET amountDue = 0, lastPaymentDate = NOW() WHERE policyNumber = ? AND customerEmail = ?";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("ss", $policyNumber, $currentUserEmail);
            $stmt->execute();
            $stmt->close();
            
            $_SESSION['message'] = "Payment successful!";
        }
    } elseif (isset($_POST['request_policy_change'])) {
        $policyNumber = filter_input(INPUT_POST, 'policyNumber', FILTER_SANITIZE_STRING);
        $changeDetails = filter_input(INPUT_POST, 'change_details', FILTER_SANITIZE_STRING);
        
        if ($policyNumber && $changeDetails) {
            $sql = "INSERT INTO policy_change_requests (policyNumber, customerEmail, changeDetails, requestDate) VALUES (?, ?, ?, NOW())";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("sss", $policyNumber, $currentUserEmail, $changeDetails);
            $stmt->execute();
            $stmt->close();
            
            $_SESSION['message'] = "Policy change request submitted successfully!";
        }
    } elseif (isset($_POST['submit_claim'])) {
        $policyNumber = filter_input(INPUT_POST, 'policyNumber', FILTER_SANITIZE_STRING);
        $claimDetails = filter_input(INPUT_POST, 'claim_details', FILTER_SANITIZE_STRING);
        
        if ($policyNumber && $claimDetails) {
            $sql = "INSERT INTO claims (policyNumber, customerEmail, claimDetails, status, submissionDate) VALUES (?, ?, ?, 'Pending', NOW())";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("sss", $policyNumber, $currentUserEmail, $claimDetails);
            $stmt->execute();
            $stmt->close();
            
            $_SESSION['message'] = "Claim submitted successfully!";
        }
    }
    
    // Redirect after POST to prevent form resubmission
    header("Location: main.php");
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Customer Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        body { background-color: #f4f6f9; }
        .sidebar {
            min-height: 100vh;
            background-color: #2c3e50;
            color: white;
            padding-top: 20px;
        }
        .sidebar a {
            color: rgba(255,255,255,0.7);
            text-decoration: none;
            padding: 10px 15px;
            display: block;
            transition: all 0.3s ease;
        }
        .sidebar a:hover {
            color: white;
            background-color: rgba(255,255,255,0.1);
        }
        .content-area { padding: 20px; }
        .profile-card {
            background-color: white;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            padding: 30px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar Navigation -->
            <div class="col-md-2 sidebar">
                <div class="text-center mb-4">
                    <h4 class="text-white">Customer Portal</h4>
                </div>
                <nav class="nav nav-pills flex-column">
                    <a class="nav-link" href="#profile">
                        <i class="bi bi-person me-2"></i>Profile
                    </a>
                    <a class="nav-link" href="#policies">
                        <i class="bi bi-file-earmark-text me-2"></i>Policies
                    </a>
                    <a class="nav-link" href="#payment">
                        <i class="bi bi-credit-card me-2"></i>Payments
                    </a>
                    <a class="nav-link" href="#claims">
                        <i class="bi bi-clipboard-check me-2"></i>Claims
                    </a>
                    <a class="nav-link text-danger" href="logout.php">
                        <i class="bi bi-box-arrow-right me-2"></i>Log Out
                    </a>
                </nav>
            </div>

            <!-- Main Content Area -->
            <div class="col-md-10 content-area">
                <?php if (isset($_SESSION['message'])): ?>
                    <div class="alert alert-success alert-dismissible fade show" role="alert">
                        <?php 
                        echo htmlspecialchars($_SESSION['message']);
                        unset($_SESSION['message']);
                        ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                <?php endif; ?>

                <!-- Profile Section -->
                <div class="profile-card" id="profile">
                    <h3>Welcome, <?php echo htmlspecialchars($userInfo['customerEmail']); ?></h3>
                    <p class="text-muted">Manage your insurance policies and claims</p>
                </div>

                <!-- Policies Section -->
                <div class="profile-card" id="policies">
                    <h4>Your Policies</h4>
                    <?php if ($policyInfo): ?>
                        <div class="table-responsive">
                            <table class="table">
                                <tr>
                                    <th>Policy Number</th>
                                    <td><?php echo htmlspecialchars($policyInfo['policyNumber']); ?></td>
                                </tr>
                                <tr>
                                    <th>Coverage Details</th>
                                    <td><?php echo htmlspecialchars($policyInfo['coverageDetails']); ?></td>
                                </tr>
                                <tr>
                                    <th>Amount Due</th>
                                    <td>$<?php echo htmlspecialchars($policyInfo['amountDue']); ?></td>
                                </tr>
                                <tr>
                                    <th>Expiry Date</th>
                                    <td><?php echo htmlspecialchars($policyInfo['expiryDate']); ?></td>
                                </tr>
                            </table>
                        </div>
                    <?php else: ?>
                        <p>No active policies found.</p>
                    <?php endif; ?>
                </div>

                <!-- Payment Section -->
                <?php if ($policyInfo && $policyInfo['amountDue'] > 0): ?>
                    <div class="profile-card" id="payment">
                        <h4>Make Payment</h4>
                        <form action="main.php" method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                            <input type="hidden" name="policyNumber" value="<?php echo htmlspecialchars($policyInfo['policyNumber']); ?>">
                            <input type="hidden" name="amountDue" value="<?php echo htmlspecialchars($policyInfo['amountDue']); ?>">
                            <button type="submit" name="make_payment" class="btn btn-primary">
                                Pay $<?php echo htmlspecialchars($policyInfo['amountDue']); ?>
                            </button>
                        </form>
                    </div>
                <?php endif; ?>

                <!-- Claims Section -->
                <div class="profile-card" id="claims">
                    <h4>Claims Management</h4>
                    <form action="main.php" method="POST" class="mb-4">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <input type="hidden" name="policyNumber" value="<?php echo htmlspecialchars($policyInfo['policyNumber']); ?>">
                        <div class="mb-3">
                            <label for="claim_details" class="form-label">New Claim Details</label>
                            <textarea class="form-control" id="claim_details" name="claim_details" rows="3" required></textarea>
                        </div>
                        <button type="submit" name="submit_claim" class="btn btn-primary">Submit Claim</button>
                    </form>

                    <?php if ($claims): ?>
                        <h5>Claim History</h5>
                        <div class="table-responsive">
                            <table class="table">
                                <thead>
                                    <tr>
                                        <th>Claim ID</th>
                                        <th>Submission Date</th>
                                        <th>Details</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($claims as $claim): ?>
                                        <tr>
                                            <td><?php echo htmlspecialchars($claim['claimId']); ?></td>
                                            <td><?php echo htmlspecialchars($claim['submissionDate']); ?></td>
                                            <td><?php echo htmlspecialchars($claim['claimDetails']); ?></td>
                                            <td>
                                                <span class="badge bg-<?php echo $claim['status'] === 'Pending' ? 'warning' : 'success'; ?>">
                                                    <?php echo htmlspecialchars($claim['status']); ?>
                                                </span>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php else: ?>
                        <p>No claims history found.</p>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>

<?php $conn->close(); ?>
