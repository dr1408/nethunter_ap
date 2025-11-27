<?php
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