<?php
// Database connection
$host = 'localhost'; // Hostname
$dbname = 'techsiksha'; // Your database name
$username = 'pma'; // Database username (default in XAMPP)
$password = ''; // Database password (empty by default)

// Create a connection
$conn = new mysqli($host, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Process the form submission
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Collect form data and sanitize input
    $name = htmlspecialchars($_POST['name']);
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $role = $_POST['role'];
    $password = $_POST['password'];
    $hashedPassword = password_hash($password, PASSWORD_BCRYPT); // Hash the password
    
    // Validate role: Ensure the role is either 'Student' or 'Expert'
    if ($role == '1') {
        $role = 'Student';
    } elseif ($role == '2') {
        $role = 'Expert';
    } else {
        die("Invalid role selected.");
    }

    // Handle file upload if the user uploads a resume (for experts only)
    $resume = '';
    if ($role == 'Expert' && isset($_FILES['resume']['name']) && $_FILES['resume']['name'] != '') {
        // Create an 'uploads' directory if not exists
        if (!file_exists('uploads')) {
            mkdir('uploads', 0777, true);
        }

        $targetDir = 'uploads/';
        $resume = $targetDir . basename($_FILES['resume']['name']);
        
        // Check file type and size (optional security)
        $fileType = strtolower(pathinfo($resume, PATHINFO_EXTENSION));
        if ($fileType != "pdf" && $fileType != "doc" && $fileType != "docx") {
            die("Only PDF, DOC, or DOCX files are allowed.");
        }
        
        if ($_FILES['resume']['size'] > 5000000) { // 5MB file size limit
            die("File is too large.");
        }
        
        // Move the file to the target directory
        if (!move_uploaded_file($_FILES['resume']['tmp_name'], $resume)) {
            die("Failed to upload resume.");
        }
    }

    // Insert the data using a prepared statement to prevent SQL injection
    $stmt = $conn->prepare("INSERT INTO users (name, email, role, password, resume) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param("sssss", $name, $email, $role, $hashedPassword, $resume);

    if ($stmt->execute()) {
        echo "Registration successful!";
    } else {
        echo "Error: " . $stmt->error;
    }

    // Close the statement
    $stmt->close();
}

// Close the connection
$conn->close();
?>
