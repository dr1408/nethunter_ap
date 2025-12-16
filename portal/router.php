<?php
// ========== FLASK PROXY HANDLER ==========
if ($_SERVER['REQUEST_URI'] === '/pass' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get the posted data
    $input = file_get_contents('php://input');
    
    // Create HTTP context for file_get_contents (no curl needed)
    $options = [
        'http' => [
            'header'  => "Content-Type: application/x-www-form-urlencoded\r\n",
            'method'  => 'POST',
            'content' => $input,
            'timeout' => 3
        ]
    ];
    
    $context = stream_context_create($options);
    
    // Forward to Flask using file_get_contents
    $result = @file_get_contents('http://127.0.0.1:5000/pass', false, $context);
    
    if ($result === FALSE) {
        // Flask not responding
        header('Content-Type: application/json');
        echo '{"status":"error","message":"Verification server unavailable"}';
    } else {
        // Return Flask's response
        header('Content-Type: application/json');
        echo $result;
    }
    exit;
}
// ========== END FLASK PROXY ==========

// Captive Portal Router - Serve all portal pages and static files
$request = $_SERVER['REQUEST_URI'];
$file_path = __DIR__ . $request;

// List of valid portal pages
$portal_pages = ['/', '/index.html', '/upgrading.html', '/loading.html'];

// Serve static files if they exist
if ($request !== '/' && file_exists($file_path) && !is_dir($file_path)) {
    $mime_types = [
        '.css' => 'text/css',
        '.js' => 'application/javascript',
        '.png' => 'image/png',
        '.jpg' => 'image/jpeg',
        '.jpeg' => 'image/jpeg',
        '.gif' => 'image/gif',
        '.ico' => 'image/x-icon',
        '.html' => 'text/html'
    ];
    
    $ext = strtolower(strrchr($request, '.'));
    if (isset($mime_types[$ext])) {
        header('Content-Type: ' . $mime_types[$ext]);
    }
    
    readfile($file_path);
    exit;
}

// Serve specific portal pages
if (in_array($request, $portal_pages)) {
    if ($request === '/upgrading.html') {
        include 'upgrading.html';
    } elseif ($request === '/loading.html') {
        include 'loading.html';
    } else {
        include 'index.html';
    }
    exit;
}

// Redirect everything else to main portal
header('Location: /');
exit;
?>