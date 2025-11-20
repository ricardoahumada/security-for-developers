# Secure File Upload Implementation Examples

**Author:** MiniMax Agent  
**Module Reference:** Module 3 - File Management Vulnerabilities  
**Last Updated:** 2025-11-15  

## Overview
This file contains comprehensive code examples demonstrating secure file upload implementations, including validation, storage security, virus scanning, processing controls, and access management across different programming languages and frameworks.

---

## 1. File Validation and Sanitization

### 1.1 PHP File Upload Security
```php
<?php
class SecureFileUpload {
    private $allowedTypes = [
        'image/jpeg' => ['.jpg', '.jpeg'],
        'image/png' => ['.png'],
        'image/gif' => ['.gif'],
        'application/pdf' => ['.pdf'],
        'application/msword' => ['.doc'],
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => ['.docx'],
        'application/vnd.ms-excel' => ['.xls'],
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' => ['.xlsx'],
        'text/plain' => ['.txt'],
        'text/csv' => ['.csv']
    ];
    
    private $maxFileSize = 5242880; // 5MB
    private $uploadPath;
    private $quarantinePath;
    private $tempPath;
    
    public function __construct($uploadPath = null, $quarantinePath = null, $tempPath = null) {
        $this->uploadPath = $uploadPath ?: sys_get_temp_dir() . '/uploads/';
        $this->quarantinePath = $quarantinePath ?: sys_get_temp_dir() . '/quarantine/';
        $this->tempPath = $tempPath ?: sys_get_temp_dir() . '/temp/';
        
        $this->ensureDirectoriesExist();
    }
    
    private function ensureDirectoriesExist() {
        $directories = [$this->uploadPath, $this->quarantinePath, $this->tempPath];
        
        foreach ($directories as $dir) {
            if (!is_dir($dir)) {
                if (!mkdir($dir, 0755, true)) {
                    throw new Exception("Failed to create directory: $dir");
                }
            }
        }
    }
    
    /**
     * Validate uploaded file
     */
    public function validateFile($file) {
        $errors = [];
        
        // Check if file was uploaded
        if (!isset($file['error']) || is_array($file['error'])) {
            throw new RuntimeException('Invalid file upload');
        }
        
        // Check file upload error
        switch ($file['error']) {
            case UPLOAD_ERR_OK:
                break;
            case UPLOAD_ERR_NO_FILE:
                throw new RuntimeException('No file sent');
            case UPLOAD_ERR_INI_SIZE:
            case UPLOAD_ERR_FORM_SIZE:
                throw new RuntimeException('File exceeds size limit');
            default:
                throw new RuntimeException('Unknown upload error');
        }
        
        // Validate file size
        if ($file['size'] > $this->maxFileSize) {
            $errors[] = 'File size exceeds maximum allowed size';
        }
        
        if ($file['size'] <= 0) {
            $errors[] = 'File size is zero or negative';
        }
        
        // Check MIME type
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mimeType = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);
        
        if (!array_key_exists($mimeType, $this->allowedTypes)) {
            $errors[] = "File type not allowed. Detected: $mimeType";
        }
        
        // Validate file extension
        $originalName = $file['name'];
        $extension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
        
        if (empty($extension)) {
            $errors[] = 'File must have an extension';
        }
        
        if (isset($this->allowedTypes[$mimeType])) {
            $allowedExtensions = $this->allowedTypes[$mimeType];
            if (!in_array('.' . $extension, $allowedExtensions)) {
                $errors[] = 'File extension does not match MIME type';
            }
        }
        
        // Check for double extensions
        if (substr_count($originalName, '.') > 1) {
            $errors[] = 'Multiple file extensions detected';
        }
        
        // Validate filename
        if (!$this->isValidFilename($originalName)) {
            $errors[] = 'Invalid filename format';
        }
        
        // Check file signature (magic bytes)
        if (!$this->validateFileSignature($file['tmp_name'], $mimeType)) {
            $errors[] = 'File signature does not match declared type';
        }
        
        return [
            'valid' => empty($errors),
            'errors' => $errors,
            'mimeType' => $mimeType,
            'extension' => $extension,
            'size' => $file['size']
        ];
    }
    
    /**
     * Validate filename for security
     */
    private function isValidFilename($filename) {
        // Check for path traversal
        if (strpos($filename, '..') !== false || strpos($filename, '/') !== false || strpos($filename, '\\') !== false) {
            return false;
        }
        
        // Check for null bytes
        if (strpos($filename, "\0") !== false) {
            return false;
        }
        
        // Check for dangerous characters
        if (preg_match('/[<>:"/\\|?*\x00-\x1f]/', $filename)) {
            return false;
        }
        
        // Check length
        if (strlen($filename) > 255) {
            return false;
        }
        
        return true;
    }
    
    /**
     * Validate file signature (magic bytes)
     */
    private function validateFileSignature($filePath, $expectedMimeType) {
        $handle = fopen($filePath, 'rb');
        if (!$handle) {
            return false;
        }
        
        $header = fread($handle, 8);
        fclose($handle);
        
        $signatures = [
            'image/jpeg' => "\xFF\xD8\xFF",
            'image/png' => "\x89PNG\r\n\x1a\n",
            'image/gif' => "GIF87a",
            'application/pdf' => "%PDF",
            'application/msword' => "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => "PK\x03\x04",
            'application/vnd.ms-excel' => "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' => "PK\x03\x04"
        ];
        
        if (isset($signatures[$expectedMimeType])) {
            return strpos($header, $signatures[$expectedMimeType]) === 0;
        }
        
        return true; // Allow files without known signatures
    }
    
    /**
     * Generate secure filename
     */
    public function generateSecureFilename($originalName, $userId = null) {
        $extension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
        $timestamp = time();
        $randomBytes = bin2hex(random_bytes(16));
        
        // Create directory structure
        $datePath = date('Y/m/d');
        $userPath = $userId ? $userId . '/' : '';
        
        return [
            'filename' => $timestamp . '_' . $randomBytes . '.' . $extension,
            'path' => $datePath . '/' . $userPath,
            'fullPath' => $datePath . '/' . $userPath . $timestamp . '_' . $randomBytes . '.' . $extension
        ];
    }
    
    /**
     * Upload file to secure location
     */
    public function uploadFile($file, $userId = null, $moveToQuarantine = false) {
        // Validate file
        $validation = $this->validateFile($file);
        
        if (!$validation['valid']) {
            throw new InvalidArgumentException('File validation failed: ' . implode(', ', $validation['errors']));
        }
        
        // Generate secure filename
        $secureName = $this->generateSecureFilename($file['name'], $userId);
        
        // Create destination path
        $uploadDir = $this->uploadPath . $secureName['path'];
        if (!is_dir($uploadDir)) {
            mkdir($uploadDir, 0755, true);
        }
        
        $destination = $uploadDir . $secureName['filename'];
        
        // Move file to destination or quarantine
        if ($moveToQuarantine) {
            $finalPath = $this->quarantinePath . $secureName['fullPath'];
        } else {
            $finalPath = $destination;
        }
        
        if (!move_uploaded_file($file['tmp_name'], $finalPath)) {
            throw new RuntimeException('Failed to move uploaded file');
        }
        
        // Set proper permissions
        chmod($finalPath, 0644);
        
        // Log upload
        $this->logFileUpload($userId, $file['name'], $secureName['filename'], $validation);
        
        return [
            'success' => true,
            'originalName' => $file['name'],
            'storedName' => $secureName['filename'],
            'path' => $secureName['fullPath'],
            'mimeType' => $validation['mimeType'],
            'size' => $validation['size'],
            'quarantine' => $moveToQuarantine
        ];
    }
    
    /**
     * Scan file for malware
     */
    public function scanFileForMalware($filePath) {
        // Basic file scanning - in production, integrate with antivirus engines
        $handle = fopen($filePath, 'rb');
        if (!$handle) {
            return ['infected' => false, 'threats' => []];
        }
        
        $content = fread($handle, 10240); // Read first 10KB
        fclose($handle);
        
        $threats = [];
        
        // Check for executable signatures
        $executableSignatures = [
            "MZ", // Windows PE executable
            "\x7fELF", // Linux ELF executable
            "#!/bin/sh", // Shell script
            "#!/usr/bin/env python", // Python script
            "<script", // JavaScript in files
            "eval(", // Potential code injection
            "base64_decode", // Potential obfuscated code
            "system(", // System command execution
            "exec(", // Command execution
            "shell_exec" // Shell execution
        ];
        
        foreach ($executableSignatures as $signature) {
            if (strpos($content, $signature) !== false) {
                $threats[] = "Detected executable signature: $signature";
            }
        }
        
        // Check file extensions against content
        $extensionThreats = $this->checkExtensionThreats($filePath);
        $threats = array_merge($threats, $extensionThreats);
        
        return [
            'infected' => !empty($threats),
            'threats' => $threats,
            'scanTime' => date('Y-m-d H:i:s')
        ];
    }
    
    private function checkExtensionThreats($filePath) {
        $threats = [];
        $extension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
        $handle = fopen($filePath, 'rb');
        
        if (!$handle) {
            return $threats;
        }
        
        $content = fread($handle, 1024);
        fclose($handle);
        
        // Check for macro threats in Office documents
        if (in_array($extension, ['doc', 'docx', 'xls', 'xlsx'])) {
            if (strpos($content, 'AutoOpen') !== false || 
                strpos($content, 'Document_Open') !== false) {
                $threats[] = 'Potential macro virus detected';
            }
        }
        
        // Check for script content in documents
        if (in_array($extension, ['pdf'])) {
            if (strpos($content, '/JavaScript') !== false || 
                strpos($content, '/OpenAction') !== false) {
                $threats[] = 'PDF contains potentially malicious JavaScript';
            }
        }
        
        return $threats;
    }
    
    /**
     * Process uploaded file
     */
    public function processFile($filePath, $options = []) {
        $extension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
        $results = [];
        
        switch ($extension) {
            case 'jpg':
            case 'jpeg':
            case 'png':
            case 'gif':
                $results = $this->processImage($filePath, $options);
                break;
                
            case 'pdf':
                $results = $this->processPDF($filePath, $options);
                break;
                
            case 'txt':
            case 'csv':
                $results = $this->processText($filePath, $options);
                break;
                
            case 'doc':
            case 'docx':
                $results = $this->processDocument($filePath, $options);
                break;
                
            default:
                $results = ['processed' => true, 'message' => 'File type not processed'];
        }
        
        return $results;
    }
    
    private function processImage($filePath, $options) {
        $results = [];
        
        // Get image dimensions
        $imageInfo = getimagesize($filePath);
        if ($imageInfo) {
            $results['dimensions'] = [
                'width' => $imageInfo[0],
                'height' => $imageInfo[1],
                'type' => image_type_to_mime_type($imageInfo[2])
            ];
        }
        
        // Resize if required
        if (isset($options['maxWidth']) || isset($options['maxHeight'])) {
            $resizedPath = $this->resizeImage($filePath, $options);
            $results['resized'] = true;
            $results['resizedPath'] = $resizedPath;
        }
        
        // Remove EXIF data if required
        if (isset($options['removeExif']) && $options['removeExif']) {
            $cleanedPath = $this->removeExifData($filePath);
            $results['exifRemoved'] = true;
            $results['cleanedPath'] = $cleanedPath;
        }
        
        $results['processed'] = true;
        return $results;
    }
    
    private function processPDF($filePath, $options) {
        $results = [];
        
        // Check PDF metadata
        $pdfInfo = $this->extractPDFMetadata($filePath);
        $results['metadata'] = $pdfInfo;
        
        // Check for JavaScript
        $hasJavaScript = $this->checkPDFJavaScript($filePath);
        $results['hasJavaScript'] = $hasJavaScript;
        
        if ($hasJavaScript && isset($options['removeJavaScript']) && $options['removeJavaScript']) {
            $cleanedPath = $this->removePDFJavaScript($filePath);
            $results['javascriptRemoved'] = true;
            $results['cleanedPath'] = $cleanedPath;
        }
        
        $results['processed'] = true;
        return $results;
    }
    
    private function processText($filePath, $options) {
        $results = [];
        
        $content = file_get_contents($filePath);
        $results['size'] = filesize($filePath);
        $results['lineCount'] = substr_count($content, "\n") + 1;
        
        // Check for suspicious content
        $suspiciousPatterns = [
            'eval(',
            'base64_decode(',
            'system(',
            'exec(',
            'shell_exec(',
            'passthru(',
            'file_get_contents(',
            'file_put_contents(',
            'fopen(',
            'curl_exec('
        ];
        
        $foundPatterns = [];
        foreach ($suspiciousPatterns as $pattern) {
            if (strpos($content, $pattern) !== false) {
                $foundPatterns[] = $pattern;
            }
        }
        
        $results['suspiciousPatterns'] = $foundPatterns;
        $results['processed'] = true;
        return $results;
    }
    
    private function processDocument($filePath, $options) {
        // Document processing would require additional libraries
        $results = ['processed' => false, 'message' => 'Document processing not implemented'];
        return $results;
    }
    
    private function logFileUpload($userId, $originalName, $storedName, $validation) {
        $logEntry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'userId' => $userId,
            'originalName' => $originalName,
            'storedName' => $storedName,
            'mimeType' => $validation['mimeType'],
            'size' => $validation['size'],
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'userAgent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
        ];
        
        // Log to file or database
        error_log('FILE_UPLOAD: ' . json_encode($logEntry));
    }
    
    private function resizeImage($filePath, $options) {
        // Image resizing implementation
        return $filePath; // Placeholder
    }
    
    private function removeExifData($filePath) {
        // EXIF removal implementation
        return $filePath; // Placeholder
    }
    
    private function extractPDFMetadata($filePath) {
        // PDF metadata extraction
        return []; // Placeholder
    }
    
    private function checkPDFJavaScript($filePath) {
        // Check for JavaScript in PDF
        return false; // Placeholder
    }
    
    private function removePDFJavaScript($filePath) {
        // Remove JavaScript from PDF
        return $filePath; // Placeholder
    }
}

// Usage example
try {
    $uploader = new SecureFileUpload('/var/uploads/', '/var/quarantine/');
    
    if ($_FILES['upload']['error'] === UPLOAD_ERR_OK) {
        // Upload to quarantine for scanning
        $result = $uploader->uploadFile($_FILES['upload'], $userId, true);
        
        if ($result['success']) {
            // Scan for malware
            $scanResult = $uploader->scanFileForMalware($this->quarantinePath . $result['path']);
            
            if (!$scanResult['infected']) {
                // Move from quarantine to final location
                $finalResult = $uploader->uploadFile($_FILES['upload'], $userId, false);
                echo json_encode(['success' => true, 'file' => $finalResult]);
            } else {
                echo json_encode(['success' => false, 'error' => 'Malware detected', 'threats' => $scanResult['threats']]);
            }
        }
    }
} catch (Exception $e) {
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}
?>
```

### 1.2 Node.js File Upload Security
```javascript
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs').promises;
const sharp = require('sharp');
const { createWorker } = require('tesseract.js');

class SecureFileUpload {
    constructor(config = {}) {
        this.config = {
            uploadPath: config.uploadPath || './uploads/',
            quarantinePath: config.quarantinePath || './quarantine/',
            tempPath: config.tempPath || './temp/',
            maxFileSize: config.maxFileSize || 5 * 1024 * 1024, // 5MB
            allowedMimeTypes: config.allowedMimeTypes || [
                'image/jpeg',
                'image/png',
                'image/gif',
                'application/pdf',
                'text/plain',
                'text/csv'
            ],
            allowedExtensions: config.allowedExtensions || [
                '.jpg', '.jpeg', '.png', '.gif', '.pdf', '.txt', '.csv'
            ],
            antivirusEnabled: config.antivirusEnabled || false,
            quarantineEnabled: config.quarantineEnabled || true
        };
        
        this.initializeDirectories();
    }
    
    async initializeDirectories() {
        const dirs = [this.config.uploadPath, this.config.quarantinePath, this.config.tempPath];
        
        for (const dir of dirs) {
            try {
                await fs.access(dir);
            } catch {
                await fs.mkdir(dir, { recursive: true });
            }
        }
    }
    
    /**
     * Create multer storage with security checks
     */
    createSecureMulterStorage() {
        return multer.diskStorage({
            destination: (req, file, cb) => {
                cb(null, this.config.tempPath);
            },
            
            filename: (req, file, cb) => {
                const secureName = this.generateSecureFilename(file.originalname);
                cb(null, secureName.filename);
            },
            
            fileFilter: (req, file, cb) => {
                try {
                    const validation = this.validateFile(file);
                    if (validation.valid) {
                        cb(null, true);
                    } else {
                        cb(new Error(`File validation failed: ${validation.errors.join(', ')}`));
                    }
                } catch (error) {
                    cb(error);
                }
            }
        });
    }
    
    /**
     * Create multer middleware
     */
    createMulterMiddleware() {
        return multer({
            storage: this.createSecureMulterStorage(),
            limits: {
                fileSize: this.config.maxFileSize,
                files: 1
            },
            fileFilter: (req, file, cb) => {
                try {
                    const validation = this.validateFile(file);
                    if (validation.valid) {
                        cb(null, true);
                    } else {
                        cb(new Error(`File validation failed: ${validation.errors.join(', ')}`));
                    }
                } catch (error) {
                    cb(error);
                }
            }
        });
    }
    
    /**
     * Validate file
     */
    validateFile(file) {
        const errors = [];
        
        // Check file size
        if (file.size > this.config.maxFileSize) {
            errors.push(`File size exceeds maximum allowed size (${this.config.maxFileSize} bytes)`);
        }
        
        if (file.size === 0) {
            errors.push('File size is zero');
        }
        
        // Check MIME type
        if (!this.config.allowedMimeTypes.includes(file.mimetype)) {
            errors.push(`File type not allowed. Detected: ${file.mimetype}`);
        }
        
        // Check extension
        const extension = path.extname(file.originalname).toLowerCase();
        if (!this.config.allowedExtensions.includes(extension)) {
            errors.push(`File extension not allowed: ${extension}`);
        }
        
        // Check for double extensions
        const parts = file.originalname.split('.');
        if (parts.length > 2) {
            errors.push('Multiple file extensions detected');
        }
        
        // Validate filename
        if (!this.isValidFilename(file.originalname)) {
            errors.push('Invalid filename format');
        }
        
        // Validate file signature
        if (!this.validateFileSignature(file)) {
            errors.push('File signature does not match declared type');
        }
        
        return {
            valid: errors.length === 0,
            errors: errors,
            extension: extension,
            size: file.size,
            mimetype: file.mimetype
        };
    }
    
    /**
     * Validate filename
     */
    isValidFilename(filename) {
        // Check for path traversal
        if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
            return false;
        }
        
        // Check for null bytes
        if (filename.includes('\0')) {
            return false;
        }
        
        // Check for dangerous characters
        if (/[<>:"/\\|?*\x00-\x1f]/.test(filename)) {
            return false;
        }
        
        // Check length
        if (filename.length > 255) {
            return false;
        }
        
        return true;
    }
    
    /**
     * Validate file signature
     */
    async validateFileSignature(file) {
        try {
            const buffer = await fs.readFile(file.path);
            const header = buffer.slice(0, 8).toString('hex');
            
            const signatures = {
                'image/jpeg': 'ffd8ffe',
                'image/png': '89504e470d0a1a0a',
                'image/gif': '47494638',
                'application/pdf': '25504446',
                'text/plain': '', // Text files don't have consistent signatures
                'text/csv': '' // CSV files don't have consistent signatures
            };
            
            const expectedSignature = signatures[file.mimetype];
            if (expectedSignature) {
                return header.startsWith(expectedSignature);
            }
            
            return true; // Allow files without known signatures
        } catch (error) {
            console.error('Error validating file signature:', error);
            return false;
        }
    }
    
    /**
     * Generate secure filename
     */
    generateSecureFilename(originalName, userId = null) {
        const extension = path.extname(originalName).toLowerCase();
        const timestamp = Date.now();
        const randomBytes = crypto.randomBytes(16).toString('hex');
        
        const datePath = new Date().toISOString().split('T')[0].replace(/-/g, '/');
        const userPath = userId ? `${userId}/` : '';
        
        return {
            filename: `${timestamp}_${randomBytes}${extension}`,
            path: `${datePath}/${userPath}`,
            fullPath: `${datePath}/${userPath}${timestamp}_${randomBytes}${extension}`
        };
    }
    
    /**
     * Scan file for malware
     */
    async scanFileForMalware(filePath) {
        const threats = [];
        
        try {
            const buffer = await fs.readFile(filePath);
            
            // Check for executable signatures
            const executableSignatures = [
                '4d5a', // Windows PE
                '7f454c46', // Linux ELF
                '2321', // Shebang
                '233d', // Python shebang
                '3c736372697074', // <script
                '6576616c28', // eval(
                '6261736536345f6465636f6465', // base64_decode
                '73797374656d28', // system(
                '6578656328' // exec(
            ];
            
            const hexString = buffer.toString('hex');
            
            for (const signature of executableSignatures) {
                if (hexString.includes(signature)) {
                    threats.push(`Detected executable signature: ${signature}`);
                }
            }
            
            // Check for macro threats in Office documents
            const extension = path.extname(filePath).toLowerCase();
            if (['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'].includes(extension)) {
                const content = buffer.toString('utf8').toLowerCase();
                const macroPatterns = ['autoopen', 'document_open', 'auto_close'];
                
                for (const pattern of macroPatterns) {
                    if (content.includes(pattern)) {
                        threats.push(`Potential macro virus detected: ${pattern}`);
                    }
                }
            }
            
        } catch (error) {
            console.error('Error scanning file for malware:', error);
            threats.push('Scan error: ' + error.message);
        }
        
        return {
            infected: threats.length > 0,
            threats: threats,
            scanTime: new Date().toISOString()
        };
    }
    
    /**
     * Process uploaded file
     */
    async processFile(filePath, options = {}) {
        const extension = path.extname(filePath).toLowerCase();
        const results = {};
        
        try {
            switch (extension) {
                case '.jpg':
                case '.jpeg':
                case '.png':
                case '.gif':
                    results.image = await this.processImage(filePath, options);
                    break;
                    
                case '.pdf':
                    results.pdf = await this.processPDF(filePath, options);
                    break;
                    
                case '.txt':
                case '.csv':
                    results.text = await this.processText(filePath, options);
                    break;
                    
                default:
                    results.message = 'File type not processed';
            }
            
            results.processed = true;
        } catch (error) {
            results.error = error.message;
            results.processed = false;
        }
        
        return results;
    }
    
    /**
     * Process image file
     */
    async processImage(filePath, options = {}) {
        const results = {};
        
        try {
            // Get image metadata
            const metadata = await sharp(filePath).metadata();
            results.metadata = {
                width: metadata.width,
                height: metadata.height,
                format: metadata.format,
                size: metadata.size,
                channels: metadata.channels,
                hasAlpha: metadata.hasAlpha
            };
            
            // Resize image if required
            if (options.maxWidth || options.maxHeight) {
                const resizedPath = filePath.replace(path.extname(filePath), '_resized' + path.extname(filePath));
                
                let sharpInstance = sharp(filePath);
                
                if (options.maxWidth && options.maxHeight) {
                    sharpInstance = sharpInstance.resize(options.maxWidth, options.maxHeight, {
                        fit: 'inside',
                        withoutEnlargement: true
                    });
                } else if (options.maxWidth) {
                    sharpInstance = sharpInstance.resize(options.maxWidth, null, {
                        fit: 'inside',
                        withoutEnlargement: true
                    });
                } else if (options.maxHeight) {
                    sharpInstance = sharpInstance.resize(null, options.maxHeight, {
                        fit: 'inside',
                        withoutEnlargement: true
                    });
                }
                
                await sharpInstance.toFile(resizedPath);
                results.resized = true;
                results.resizedPath = resizedPath;
            }
            
            // Remove metadata if requested
            if (options.removeMetadata) {
                const cleanedPath = filePath.replace(path.extname(filePath), '_cleaned' + path.extname(filePath));
                await sharp(filePath)
                    .withMetadata({}) // Remove all metadata
                    .toFile(cleanedPath);
                results.metadataRemoved = true;
                results.cleanedPath = cleanedPath;
            }
            
            // Generate thumbnail
            if (options.generateThumbnail) {
                const thumbnailPath = filePath.replace(path.extname(filePath), '_thumb' + path.extname(filePath));
                await sharp(filePath)
                    .resize(200, 200, { fit: 'cover' })
                    .toFile(thumbnailPath);
                results.thumbnail = true;
                results.thumbnailPath = thumbnailPath;
            }
            
        } catch (error) {
            results.error = error.message;
        }
        
        return results;
    }
    
    /**
     * Process PDF file
     */
    async processPDF(filePath, options = {}) {
        const results = {};
        
        try {
            // Basic PDF processing - in production, use PDF libraries
            const stats = await fs.stat(filePath);
            results.size = stats.size;
            results.pageCount = await this.countPDFPages(filePath); // Placeholder
            
            // Check for JavaScript
            const buffer = await fs.readFile(filePath);
            const content = buffer.toString('latin1');
            
            const hasJavaScript = content.includes('/JavaScript') || content.includes('/OpenAction');
            results.hasJavaScript = hasJavaScript;
            
            if (hasJavaScript && options.removeJavaScript) {
                // PDF JavaScript removal would require specialized libraries
                results.message = 'JavaScript removal not implemented';
            }
            
        } catch (error) {
            results.error = error.message;
        }
        
        return results;
    }
    
    /**
     * Process text file
     */
    async processText(filePath, options = {}) {
        const results = {};
        
        try {
            const content = await fs.readFile(filePath, 'utf8');
            const lines = content.split('\n');
            
            results.size = content.length;
            results.lineCount = lines.length;
            results.wordCount = content.split(/\s+/).length;
            
            // Check for suspicious patterns
            const suspiciousPatterns = [
                'eval(',
                'base64_decode(',
                'system(',
                'exec(',
                'shell_exec(',
                'passthru(',
                'file_get_contents(',
                'file_put_contents(',
                'fopen(',
                'curl_exec('
            ];
            
            const foundPatterns = [];
            for (const pattern of suspiciousPatterns) {
                if (content.includes(pattern)) {
                    foundPatterns.push(pattern);
                }
            }
            
            results.suspiciousPatterns = foundPatterns;
            results.hasSuspiciousContent = foundPatterns.length > 0;
            
        } catch (error) {
            results.error = error.message;
        }
        
        return results;
    }
    
    /**
     * Move file to secure location
     */
    async moveToSecureLocation(sourcePath, destinationPath, quarantine = false) {
        try {
            const targetPath = quarantine 
                ? path.join(this.config.quarantinePath, destinationPath)
                : path.join(this.config.uploadPath, destinationPath);
            
            // Create directory structure
            const dir = path.dirname(targetPath);
            await fs.mkdir(dir, { recursive: true });
            
            // Move file
            await fs.rename(sourcePath, targetPath);
            
            // Set secure permissions
            await fs.chmod(targetPath, 0o644);
            
            return {
                success: true,
                path: targetPath,
                url: this.generateFileUrl(targetPath, quarantine)
            };
        } catch (error) {
            throw new Error(`Failed to move file: ${error.message}`);
        }
    }
    
    /**
     * Generate file URL
     */
    generateFileUrl(filePath, isQuarantine = false) {
        const basePath = isQuarantine ? '/files/quarantine/' : '/files/';
        const relativePath = filePath
            .replace(this.config.uploadPath, '')
            .replace(this.config.quarantinePath, '');
        
        return basePath + relativePath;
    }
    
    /**
     * Cleanup temporary files
     */
    async cleanupTempFiles(maxAge = 3600000) { // 1 hour
        try {
            const files = await fs.readdir(this.config.tempPath);
            const now = Date.now();
            
            for (const file of files) {
                const filePath = path.join(this.config.tempPath, file);
                const stats = await fs.stat(filePath);
                
                if (now - stats.mtime.getTime() > maxAge) {
                    await fs.unlink(filePath);
                }
            }
        } catch (error) {
            console.error('Error cleaning up temp files:', error);
        }
    }
    
    // Placeholder methods
    async countPDFPages(filePath) {
        // PDF page counting would require PDF libraries
        return 0;
    }
}

// Express.js middleware
const createSecureUploadMiddleware = (config = {}) => {
    const uploader = new SecureFileUpload(config);
    
    return {
        single: (fieldName) => [
            uploader.createMulterMiddleware().single(fieldName),
            async (req, res, next) => {
                try {
                    if (!req.file) {
                        return res.status(400).json({ error: 'No file uploaded' });
                    }
                    
                    const filePath = req.file.path;
                    const validation = uploader.validateFile(req.file);
                    
                    if (!validation.valid) {
                        await fs.unlink(filePath);
                        return res.status(400).json({ 
                            error: 'File validation failed', 
                            details: validation.errors 
                        });
                    }
                    
                    // Scan for malware if enabled
                    if (config.antivirusEnabled) {
                        const scanResult = await uploader.scanFileForMalware(filePath);
                        
                        if (scanResult.infected) {
                            await fs.unlink(filePath);
                            return res.status(400).json({ 
                                error: 'Malware detected', 
                                threats: scanResult.threats 
                            });
                        }
                    }
                    
                    req.secureFile = req.file;
                    req.uploader = uploader;
                    next();
                } catch (error) {
                    console.error('Upload middleware error:', error);
                    res.status(500).json({ error: 'Upload processing failed' });
                }
            }
        ]
    };
};

// Example Express app
const express = require('express');
const app = express();

const uploadMiddleware = createSecureUploadMiddleware({
    maxFileSize: 10 * 1024 * 1024, // 10MB
    allowedMimeTypes: ['image/jpeg', 'image/png', 'application/pdf'],
    quarantineEnabled: true,
    antivirusEnabled: true
});

app.post('/upload', uploadMiddleware.single('file'), async (req, res) => {
    try {
        const uploader = req.uploader;
        const file = req.secureFile;
        
        // Generate secure filename
        const secureName = uploader.generateSecureFilename(file.originalname, req.user?.id);
        
        // Process file if needed
        const processOptions = {
            maxWidth: 800,
            maxHeight: 600,
            removeMetadata: true,
            generateThumbnail: true
        };
        
        const processingResult = await uploader.processFile(file.path, processOptions);
        
        // Move to secure location
        const moveResult = await uploader.moveToSecureLocation(
            file.path, 
            secureName.fullPath,
            false // Move directly to upload path (not quarantine)
        );
        
        // Log upload
        console.log('File uploaded:', {
            userId: req.user?.id,
            originalName: file.originalname,
            storedName: secureName.filename,
            size: file.size,
            mimeType: file.mimetype
        });
        
        res.json({
            success: true,
            file: {
                originalName: file.originalname,
                storedName: secureName.filename,
                url: moveResult.url,
                size: file.size,
                mimeType: file.mimetype,
                processing: processingResult
            }
        });
        
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Cleanup endpoint (admin only)
app.post('/admin/cleanup-temp', async (req, res) => {
    try {
        const uploader = new SecureFileUpload();
        await uploader.cleanupTempFiles();
        res.json({ success: true, message: 'Cleanup completed' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = { SecureFileUpload, createSecureUploadMiddleware };
```

---

## 2. File Access Control and Permissions

### 2.1 PHP File Access Control
```php
<?php
class FileAccessControl {
    private $db;
    private $baseUploadPath;
    private $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx'];
    
    public function __construct($database, $baseUploadPath) {
        $this->db = $database;
        $this->baseUploadPath = rtrim($baseUploadPath, '/') . '/';
    }
    
    /**
     * Check if user can access file
     */
    public function canUserAccessFile($userId, $fileId) {
        $sql = "SELECT f.*, fp.permission_level 
                FROM files f
                LEFT JOIN file_permissions fp ON f.id = fp.file_id
                WHERE f.id = ? AND (fp.user_id = ? OR f.owner_id = ? OR fp.permission_level = 'public')";
        
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("iii", $fileId, $userId, $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        
        return $result->fetch_assoc();
    }
    
    /**
     * Check if user can upload file
     */
    public function canUserUploadFile($userId, $fileType, $fileSize) {
        // Check user's file upload quota
        $quotaCheck = $this->checkUserQuota($userId, $fileSize);
        if (!$quotaCheck['allowed']) {
            return $quotaCheck;
        }
        
        // Check file type permissions
        if (!$this->isFileTypeAllowed($userId, $fileType)) {
            return [
                'allowed' => false,
                'reason' => 'File type not allowed for user'
            ];
        }
        
        return ['allowed' => true];
    }
    
    /**
     * Check user's storage quota
     */
    private function checkUserQuota($userId, $newFileSize) {
        $sql = "SELECT 
                    u.storage_quota,
                    COALESCE(SUM(f.file_size), 0) as used_storage
                FROM users u
                LEFT JOIN files f ON u.id = f.owner_id
                WHERE u.id = ?";
        
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        
        $quota = $row['storage_quota'] ?? 104857600; // Default 100MB
        $used = $row['used_storage'] ?? 0;
        $available = $quota - $used;
        
        if ($newFileSize > $available) {
            return [
                'allowed' => false,
                'reason' => 'Insufficient storage quota',
                'quota' => $quota,
                'used' => $used,
                'required' => $newFileSize,
                'available' => $available
            ];
        }
        
        return [
            'allowed' => true,
            'quota' => $quota,
            'used' => $used,
            'remaining' => $available - $newFileSize
        ];
    }
    
    /**
     * Check if file type is allowed for user
     */
    private function isFileTypeAllowed($userId, $fileType) {
        $sql = "SELECT permission_type 
                FROM user_file_permissions 
                WHERE user_id = ? AND file_type = ?";
        
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("is", $userId, $fileType);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($row = $result->fetch_assoc()) {
            return $row['permission_type'] !== 'denied';
        }
        
        // Default allow for common file types
        return in_array(strtolower($fileType), $this->allowedExtensions);
    }
    
    /**
     * Create file record in database
     */
    public function createFileRecord($fileData) {
        $sql = "INSERT INTO files (
                    owner_id, original_name, stored_name, file_path, 
                    file_size, mime_type, file_type, permission_level,
                    upload_date, is_active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), 1)";
        
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param(
            "issssiss", 
            $fileData['owner_id'],
            $fileData['original_name'],
            $fileData['stored_name'],
            $fileData['file_path'],
            $fileData['file_size'],
            $fileData['mime_type'],
            $fileData['file_type'],
            $fileData['permission_level']
        );
        
        if ($stmt->execute()) {
            return $this->db->insert_id;
        }
        
        throw new Exception('Failed to create file record');
    }
    
    /**
     * Get secure file path (prevent directory traversal)
     */
    public function getSecureFilePath($userId, $storedName) {
        // Sanitize filename
        $sanitizedName = basename($storedName);
        
        // Create user directory structure
        $userDir = $this->baseUploadPath . $userId . '/';
        if (!is_dir($userDir)) {
            mkdir($userDir, 0755, true);
        }
        
        $filePath = $userDir . $sanitizedName;
        
        // Ensure file is within allowed directory
        $realPath = realpath($userDir);
        $targetPath = realpath($filePath);
        
        if ($targetPath === false || strpos($targetPath, $realPath) !== 0) {
            throw new Exception('Invalid file path');
        }
        
        return $targetPath;
    }
    
    /**
     * Set file permissions
     */
    public function setFilePermissions($fileId, $userId, $permissionLevel) {
        $sql = "INSERT INTO file_permissions (file_id, user_id, permission_level) 
                VALUES (?, ?, ?) 
                ON DUPLICATE KEY UPDATE permission_level = VALUES(permission_level)";
        
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("iis", $fileId, $userId, $permissionLevel);
        $stmt->execute();
    }
    
    /**
     * Get user's files with pagination
     */
    public function getUserFiles($userId, $page = 1, $limit = 20, $filters = []) {
        $offset = ($page - 1) * $limit;
        
        $sql = "SELECT f.*, 
                       fp.permission_level,
                       CASE WHEN f.owner_id = ? THEN 'owner' ELSE 'shared' END as access_type
                FROM files f
                LEFT JOIN file_permissions fp ON f.id = fp.file_id AND fp.user_id = ?
                WHERE f.is_active = 1 AND (f.owner_id = ? OR fp.user_id IS NOT NULL)";
        
        $params = [$userId, $userId, $userId];
        
        // Add filters
        if (!empty($filters['file_type'])) {
            $sql .= " AND f.file_type = ?";
            $params[] = $filters['file_type'];
        }
        
        if (!empty($filters['date_from'])) {
            $sql .= " AND DATE(f.upload_date) >= ?";
            $params[] = $filters['date_from'];
        }
        
        if (!empty($filters['date_to'])) {
            $sql .= " AND DATE(f.upload_date) <= ?";
            $params[] = $filters['date_to'];
        }
        
        $sql .= " ORDER BY f.upload_date DESC LIMIT ? OFFSET ?";
        $params[] = $limit;
        $params[] = $offset;
        
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param(str_repeat('s', count($params)), ...$params);
        $stmt->execute();
        $result = $stmt->get_result();
        
        return $result->fetch_all(MYSQLI_ASSOC);
    }
    
    /**
     * Log file access
     */
    public function logFileAccess($userId, $fileId, $action, $ipAddress, $userAgent) {
        $sql = "INSERT INTO file_access_log (user_id, file_id, action, ip_address, user_agent, access_time) 
                VALUES (?, ?, ?, ?, ?, NOW())";
        
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("iisss", $userId, $fileId, $action, $ipAddress, $userAgent);
        $stmt->execute();
    }
    
    /**
     * Delete file (soft delete)
     */
    public function deleteFile($userId, $fileId) {
        // Check if user owns the file
        $sql = "SELECT id FROM files WHERE id = ? AND owner_id = ?";
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("ii", $fileId, $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if (!$result->fetch_assoc()) {
            throw new Exception('File not found or access denied');
        }
        
        // Soft delete
        $sql = "UPDATE files SET is_active = 0, deleted_at = NOW() WHERE id = ?";
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("i", $fileId);
        $stmt->execute();
        
        // Log the deletion
        $this->logFileAccess($userId, $fileId, 'delete', $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
        
        return true;
    }
}

// File download handler
class SecureFileDownloader {
    private $fileAccessControl;
    
    public function __construct($fileAccessControl) {
        $this->fileAccessControl = $fileAccessControl;
    }
    
    /**
     * Download file with security checks
     */
    public function downloadFile($userId, $fileId) {
        try {
            // Check access permissions
            $fileInfo = $this->fileAccessControl->canUserAccessFile($userId, $fileId);
            
            if (!$fileInfo) {
                throw new Exception('File not found or access denied');
            }
            
            // Check if file exists and is accessible
            $filePath = $this->fileAccessControl->getSecureFilePath($userId, $fileInfo['stored_name']);
            
            if (!file_exists($filePath)) {
                throw new Exception('File not found on server');
            }
            
            // Log access
            $this->fileAccessControl->logFileAccess(
                $userId, 
                $fileId, 
                'download', 
                $_SERVER['REMOTE_ADDR'] ?? '', 
                $_SERVER['HTTP_USER_AGENT'] ?? ''
            );
            
            // Set headers for file download
            header('Content-Type: ' . $fileInfo['mime_type']);
            header('Content-Length: ' . filesize($filePath));
            header('Content-Disposition: attachment; filename="' . $fileInfo['original_name'] . '"');
            header('Cache-Control: private, must-revalidate');
            header('Pragma: public');
            
            // Prevent execution of uploaded files
            if (strpos($fileInfo['mime_type'], 'image/') === false && 
                strpos($fileInfo['mime_type'], 'application/pdf') === false) {
                header('X-Content-Type-Options: nosniff');
            }
            
            // Output file
            readfile($filePath);
            exit;
            
        } catch (Exception $e) {
            http_response_code(403);
            echo json_encode(['error' => $e->getMessage()]);
        }
    }
}

// Usage example
try {
    $database = new mysqli('localhost', 'username', 'password', 'database');
    $fileAccessControl = new FileAccessControl($database, '/var/uploads/');
    
    // Check if user can upload
    $canUpload = $fileAccessControl->canUserUploadFile(123, 'image/jpeg', 1024000);
    
    if ($canUpload['allowed']) {
        // Process file upload...
        echo "Upload allowed";
    } else {
        echo "Upload denied: " . $canUpload['reason'];
    }
    
} catch (Exception $e) {
    echo "Error: " . $e->getMessage();
}
?>
```

---

## 3. Virus Scanning and File Processing

### 3.1 ClamAV Integration
```php
<?php
class AntivirusScanner {
    private $clamavPath;
    private $quarantinePath;
    private $scanTimeout = 300; // 5 minutes
    
    public function __construct($clamavPath = '/usr/bin/clamscan', $quarantinePath = '/var/quarantine/') {
        $this->clamavPath = $clamavPath;
        $this->quarantinePath = rtrim($quarantinePath, '/') . '/';
        
        // Ensure quarantine directory exists
        if (!is_dir($this->quarantinePath)) {
            mkdir($this->quarantinePath, 0755, true);
        }
        
        // Check if ClamAV is available
        if (!$this->isClamAVAvailable()) {
            throw new Exception('ClamAV not available at specified path');
        }
    }
    
    /**
     * Check if ClamAV is available
     */
    private function isClamAVAvailable() {
        return file_exists($this->clamavPath) && is_executable($this->clamavPath);
    }
    
    /**
     * Scan single file
     */
    public function scanFile($filePath) {
        $command = sprintf(
            '%s --no-summary --infected --recursive --timeout=%d %s 2>&1',
            escapeshellcmd($this->clamavPath),
            $this->scanTimeout,
            escapeshellarg($filePath)
        );
        
        $output = [];
        $returnCode = 0;
        exec($command, $output, $returnCode);
        
        $result = [
            'clean' => false,
            'infected' => false,
            'error' => false,
            'threats' => [],
            'scanTime' => time(),
            'command' => $command,
            'output' => implode("\n", $output)
        ];
        
        // Parse ClamAV output
        foreach ($output as $line) {
            if (strpos($line, 'FOUND') !== false) {
                $result['infected'] = true;
                $result['clean'] = false;
                
                // Extract threat name
                if (preg_match('/: (.+) FOUND/', $line, $matches)) {
                    $result['threats'][] = trim($matches[1]);
                }
            } elseif (strpos($line, 'OK') !== false) {
                $result['clean'] = true;
            } elseif (strpos($line, 'ERROR') !== false) {
                $result['error'] = true;
                $result['errorMessage'] = $line;
            }
        }
        
        // Handle return codes
        switch ($returnCode) {
            case 0:
                $result['clean'] = true;
                break;
            case 1:
                $result['infected'] = true;
                break;
            case 2:
                $result['error'] = true;
                $result['errorMessage'] = 'Scan error occurred';
                break;
            default:
                $result['error'] = true;
                $result['errorMessage'] = 'Unknown scan error';
        }
        
        return $result;
    }
    
    /**
     * Scan multiple files
     */
    public function scanFiles($filePaths) {
        $results = [];
        $overallClean = true;
        
        foreach ($filePaths as $filePath) {
            if (!file_exists($filePath)) {
                $results[$filePath] = [
                    'error' => true,
                    'errorMessage' => 'File not found'
                ];
                continue;
            }
            
            $scanResult = $this->scanFile($filePath);
            $results[$filePath] = $scanResult;
            
            if ($scanResult['infected'] || $scanResult['error']) {
                $overallClean = false;
            }
        }
        
        return [
            'overallClean' => $overallClean,
            'results' => $results,
            'totalFiles' => count($filePaths),
            'infectedCount' => count(array_filter($results, function($r) { return $r['infected']; })),
            'errorCount' => count(array_filter($results, function($r) { return $r['error']; }))
        ];
    }
    
    /**
     * Quarantine infected file
     */
    public function quarantineFile($filePath, $threatName) {
        if (!file_exists($filePath)) {
            throw new Exception('File not found for quarantine');
        }
        
        $quarantineFileName = basename($filePath) . '_quarantined_' . time();
        $quarantinePath = $this->quarantinePath . $quarantineFileName;
        
        if (!copy($filePath, $quarantinePath)) {
            throw new Exception('Failed to copy file to quarantine');
        }
        
        // Create quarantine metadata
        $metadata = [
            'originalPath' => $filePath,
            'quarantinePath' => $quarantinePath,
            'threatName' => $threatName,
            'quarantineTime' => date('Y-m-d H:i:s'),
            'fileSize' => filesize($quarantinePath),
            'originalMD5' => md5_file($filePath),
            'quarantineMD5' => md5_file($quarantinePath)
        ];
        
        // Save metadata
        $metadataPath = $this->quarantinePath . $quarantineFileName . '.meta';
        file_put_contents($metadataPath, json_encode($metadata, JSON_PRETTY_PRINT));
        
        // Remove original file
        unlink($filePath);
        
        return [
            'quarantined' => true,
            'quarantinePath' => $quarantinePath,
            'metadata' => $metadata
        ];
    }
    
    /**
     * Update ClamAV virus definitions
     */
    public function updateDefinitions() {
        $command = sprintf('%s --update 2>&1', escapeshellcmd($this->clamavPath));
        
        $output = [];
        $returnCode = 0;
        exec($command, $output, $returnCode);
        
        return [
            'success' => $returnCode === 0,
            'output' => implode("\n", $output),
            'returnCode' => $returnCode
        ];
    }
    
    /**
     * Get ClamAV version information
     */
    public function getVersionInfo() {
        $command = sprintf('%s --version 2>&1', escapeshellcmd($this->clamavPath));
        
        $output = [];
        $returnCode = 0;
        exec($command, $output, $returnCode);
        
        return [
            'version' => implode("\n", $output),
            'returnCode' => $returnCode
        ];
    }
}

// Advanced file processing pipeline
class FileProcessingPipeline {
    private $antivirusScanner;
    private $secureFileUpload;
    private $fileAccessControl;
    
    public function __construct($antivirusScanner, $secureFileUpload, $fileAccessControl) {
        $this->antivirusScanner = $antivirusScanner;
        $this->secureFileUpload = $secureFileUpload;
        $this->fileAccessControl = $fileAccessControl;
    }
    
    /**
     * Process uploaded file through security pipeline
     */
    public function processUploadedFile($userId, $uploadedFile, $options = []) {
        $pipelineResults = [
            'validation' => null,
            'virusScan' => null,
            'processing' => null,
            'storage' => null,
            'database' => null
        ];
        
        try {
            // Step 1: Validate file
            $pipelineResults['validation'] = $this->secureFileUpload->validateFile($uploadedFile);
            
            if (!$pipelineResults['validation']['valid']) {
                throw new Exception('File validation failed: ' . implode(', ', $pipelineResults['validation']['errors']));
            }
            
            // Step 2: Store in temporary location
            $tempPath = $this->secureFileUpload->getTempUploadPath($uploadedFile);
            $uploadResult = $this->secureFileUpload->uploadFile($uploadedFile, $userId, true); // Upload to temp first
            
            // Step 3: Virus scan
            $pipelineResults['virusScan'] = $this->antivirusScanner->scanFile($tempPath);
            
            if ($pipelineResults['virusScan']['infected']) {
                // Quarantine infected file
                $this->antivirusScanner->quarantineFile($tempPath, implode(', ', $pipelineResults['virusScan']['threats']));
                
                throw new Exception('Infected file detected and quarantined: ' . implode(', ', $pipelineResults['virusScan']['threats']));
            }
            
            if ($pipelineResults['virusScan']['error']) {
                throw new Exception('Virus scan error: ' . $pipelineResults['virusScan']['errorMessage']);
            }
            
            // Step 4: Process file (resize, optimize, etc.)
            if (isset($options['processFile']) && $options['processFile']) {
                $pipelineResults['processing'] = $this->secureFileUpload->processFile($tempPath, $options['processingOptions']);
            }
            
            // Step 5: Move to final secure location
            $securePath = $this->fileAccessControl->getSecureFilePath($userId, $uploadResult['storedName']);
            rename($tempPath, $securePath);
            $pipelineResults['storage'] = ['moved' => true, 'path' => $securePath];
            
            // Step 6: Create database record
            $fileRecord = [
                'owner_id' => $userId,
                'original_name' => $uploadedFile['name'],
                'stored_name' => $uploadResult['storedName'],
                'file_path' => $securePath,
                'file_size' => $uploadedFile['size'],
                'mime_type' => $pipelineResults['validation']['mimeType'],
                'file_type' => $pipelineResults['validation']['extension'],
                'permission_level' => $options['permissionLevel'] ?? 'private'
            ];
            
            $fileId = $this->fileAccessControl->createFileRecord($fileRecord);
            $pipelineResults['database'] = ['fileId' => $fileId];
            
            return [
                'success' => true,
                'fileId' => $fileId,
                'pipelineResults' => $pipelineResults,
                'fileInfo' => [
                    'originalName' => $uploadedFile['name'],
                    'storedName' => $uploadResult['storedName'],
                    'filePath' => $securePath,
                    'fileSize' => $uploadedFile['size'],
                    'mimeType' => $pipelineResults['validation']['mimeType']
                ]
            ];
            
        } catch (Exception $e) {
            // Cleanup on failure
            if (isset($tempPath) && file_exists($tempPath)) {
                unlink($tempPath);
            }
            
            return [
                'success' => false,
                'error' => $e->getMessage(),
                'pipelineResults' => $pipelineResults
            ];
        }
    }
}

// Usage example
try {
    $antivirus = new AntivirusScanner();
    $secureUpload = new SecureFileUpload();
    $fileAccess = new FileAccessControl($database, '/var/uploads/');
    
    $pipeline = new FileProcessingPipeline($antivirus, $secureUpload, $fileAccess);
    
    $result = $pipeline->processUploadedFile($userId, $_FILES['upload'], [
        'processFile' => true,
        'processingOptions' => [
            'maxWidth' => 800,
            'maxHeight' => 600,
            'removeMetadata' => true,
            'generateThumbnail' => true
        ],
        'permissionLevel' => 'private'
    ]);
    
    if ($result['success']) {
        echo json_encode([
            'success' => true,
            'fileId' => $result['fileId'],
            'fileInfo' => $result['fileInfo']
        ]);
    } else {
        echo json_encode(['success' => false, 'error' => $result['error']]);
    }
    
} catch (Exception $e) {
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}
?>
```

---

## 4. File Processing and Image Security

### 4.1 Image Security Processing
```php
<?php
class ImageSecurityProcessor {
    private $allowedFormats = ['jpeg', 'jpg', 'png', 'gif'];
    private $maxDimensions = ['width' => 2000, 'height' => 2000];
    private $maxFileSize = 5242880; // 5MB
    
    /**
     * Process image with security measures
     */
    public function processImage($sourcePath, $options = []) {
        $results = [];
        
        try {
            // Get image information
            $imageInfo = $this->validateImage($sourcePath);
            $results['validation'] = $imageInfo;
            
            if (!$imageInfo['valid']) {
                throw new Exception('Invalid image: ' . implode(', ', $imageInfo['errors']));
            }
            
            // Remove metadata
            if (isset($options['removeMetadata']) && $options['removeMetadata']) {
                $this->removeImageMetadata($sourcePath);
                $results['metadataRemoved'] = true;
            }
            
            // Resize image if needed
            if (isset($options['resize']) && $options['resize']) {
                $resizeResult = $this->resizeImage($sourcePath, $options);
                $results['resized'] = $resizeResult;
            }
            
            // Generate thumbnail
            if (isset($options['generateThumbnail']) && $options['generateThumbnail']) {
                $thumbnailResult = $this->generateThumbnail($sourcePath, $options);
                $results['thumbnail'] = $thumbnailResult;
            }
            
            // Strip comments and text chunks
            if (isset($options['stripTextChunks']) && $options['stripTextChunks']) {
                $this->stripImageTextChunks($sourcePath);
                $results['textChunksRemoved'] = true;
            }
            
            // Validate image integrity
            $integrityResult = $this->validateImageIntegrity($sourcePath);
            $results['integrity'] = $integrityResult;
            
            if (!$integrityResult['valid']) {
                throw new Exception('Image integrity check failed');
            }
            
            $results['processed'] = true;
            
        } catch (Exception $e) {
            $results['error'] = $e->getMessage();
            $results['processed'] = false;
        }
        
        return $results;
    }
    
    /**
     * Validate image
     */
    private function validateImage($filePath) {
        $errors = [];
        
        if (!file_exists($filePath)) {
            $errors[] = 'File not found';
            return ['valid' => false, 'errors' => $errors];
        }
        
        if (filesize($filePath) > $this->maxFileSize) {
            $errors[] = 'File size exceeds limit';
        }
        
        $imageInfo = getimagesize($filePath);
        if (!$imageInfo) {
            $errors[] = 'Not a valid image file';
            return ['valid' => false, 'errors' => $errors];
        }
        
        $mimeType = $imageInfo['mime'];
        $width = $imageInfo[0];
        $height = $imageInfo[1];
        
        // Validate format
        $format = $this->getImageFormat($filePath);
        if (!in_array($format, $this->allowedFormats)) {
            $errors[] = 'Image format not allowed: ' . $format;
        }
        
        // Validate dimensions
        if ($width > $this->maxDimensions['width']) {
            $errors[] = 'Image width exceeds limit';
        }
        
        if ($height > $this->maxDimensions['height']) {
            $errors[] = 'Image height exceeds limit';
        }
        
        // Check for very small or very large aspect ratios (potential steganography)
        $aspectRatio = $width / $height;
        if ($aspectRatio > 10 || $aspectRatio < 0.1) {
            $errors[] = 'Suspicious image dimensions';
        }
        
        return [
            'valid' => empty($errors),
            'errors' => $errors,
            'width' => $width,
            'height' => $height,
            'mimeType' => $mimeType,
            'format' => $format,
            'size' => filesize($filePath)
        ];
    }
    
    /**
     * Get image format
     */
    private function getImageFormat($filePath) {
        $info = getimagesize($filePath);
        if (!$info) return false;
        
        switch ($info[2]) {
            case IMAGETYPE_JPEG:
                return 'jpeg';
            case IMAGETYPE_PNG:
                return 'png';
            case IMAGETYPE_GIF:
                return 'gif';
            default:
                return 'unknown';
        }
    }
    
    /**
     * Remove image metadata
     */
    private function removeImageMetadata($filePath) {
        $imageInfo = getimagesize($filePath);
        $format = $this->getImageFormat($filePath);
        
        switch ($format) {
            case 'jpeg':
                return $this->removeJPEGMetadata($filePath);
            case 'png':
                return $this->removePNGMetadata($filePath);
            case 'gif':
                return $this->removeGIFMetadata($filePath);
            default:
                return false;
        }
    }
    
    /**
     * Remove JPEG metadata
     */
    private function removeJPEGMetadata($filePath) {
        $source = imagecreatefromjpeg($filePath);
        if (!$source) {
            throw new Exception('Failed to load JPEG image');
        }
        
        $tempPath = $filePath . '.tmp';
        
        // Save without metadata
        $quality = 90;
        if (!imagejpeg($source, $tempPath, $quality)) {
            throw new Exception('Failed to save JPEG image');
        }
        
        imagedestroy($source);
        
        // Replace original
        rename($tempPath, $filePath);
        
        return true;
    }
    
    /**
     * Remove PNG metadata
     */
    private function removePNGMetadata($filePath) {
        $source = imagecreatefrompng($filePath);
        if (!$source) {
            throw new Exception('Failed to load PNG image');
        }
        
        // Remove alpha channel info
        imagealphablending($source, false);
        imagesavealpha($source, true);
        
        $tempPath = $filePath . '.tmp';
        
        if (!imagepng($source, $tempPath)) {
            throw new Exception('Failed to save PNG image');
        }
        
        imagedestroy($source);
        
        rename($tempPath, $filePath);
        
        return true;
    }
    
    /**
     * Remove GIF metadata
     */
    private function removeGIFMetadata($filePath) {
        // GIF metadata removal is more complex
        // For simplicity, we'll re-create the GIF without metadata
        $source = imagecreatefromgif($filePath);
        if (!$source) {
            throw new Exception('Failed to load GIF image');
        }
        
        $width = imagesx($source);
        $height = imagesy($source);
        
        $dest = imagecreatetruecolor($width, $height);
        
        // Copy image data
        imagecopy($dest, $source, 0, 0, 0, 0, $width, $height);
        
        $tempPath = $filePath . '.tmp';
        
        if (!imagegif($dest, $tempPath)) {
            throw new Exception('Failed to save GIF image');
        }
        
        imagedestroy($source);
        imagedestroy($dest);
        
        rename($tempPath, $filePath);
        
        return true;
    }
    
    /**
     * Resize image
     */
    private function resizeImage($filePath, $options) {
        $maxWidth = $options['maxWidth'] ?? 800;
        $maxHeight = $options['maxHeight'] ?? 600;
        $quality = $options['quality'] ?? 90;
        
        $imageInfo = getimagesize($filePath);
        $width = $imageInfo[0];
        $height = $imageInfo[1];
        
        // Calculate new dimensions
        $newDimensions = $this->calculateResizeDimensions($width, $height, $maxWidth, $maxHeight);
        
        $source = imagecreatefromstring(file_get_contents($filePath));
        if (!$source) {
            throw new Exception('Failed to load image for resizing');
        }
        
        $resized = imagecreatetruecolor($newDimensions['width'], $newDimensions['height']);
        
        // Preserve transparency
        imagealphablending($resized, false);
        imagesavealpha($resized, true);
        
        // Resize
        imagecopyresampled(
            $resized, $source,
            0, 0, 0, 0,
            $newDimensions['width'], $newDimensions['height'],
            $width, $height
        );
        
        $format = $this->getImageFormat($filePath);
        $tempPath = $filePath . '_resized';
        
        $success = false;
        switch ($format) {
            case 'jpeg':
                $success = imagejpeg($resized, $tempPath, $quality);
                break;
            case 'png':
                $success = imagepng($resized, $tempPath);
                break;
            case 'gif':
                $success = imagegif($resized, $tempPath);
                break;
        }
        
        imagedestroy($source);
        imagedestroy($resized);
        
        if (!$success) {
            throw new Exception('Failed to save resized image');
        }
        
        return [
            'resized' => true,
            'originalDimensions' => ['width' => $width, 'height' => $height],
            'newDimensions' => $newDimensions,
            'path' => $tempPath
        ];
    }
    
    /**
     * Calculate resize dimensions
     */
    private function calculateResizeDimensions($width, $height, $maxWidth, $maxHeight) {
        $ratio = min($maxWidth / $width, $maxHeight / $height);
        
        if ($ratio >= 1) {
            // No resize needed
            return ['width' => $width, 'height' => $height];
        }
        
        return [
            'width' => round($width * $ratio),
            'height' => round($height * $ratio)
        ];
    }
    
    /**
     * Generate thumbnail
     */
    private function generateThumbnail($filePath, $options) {
        $thumbWidth = $options['thumbWidth'] ?? 150;
        $thumbHeight = $options['thumbHeight'] ?? 150;
        
        $source = imagecreatefromstring(file_get_contents($filePath));
        if (!$source) {
            throw new Exception('Failed to load image for thumbnail');
        }
        
        $width = imagesx($source);
        $height = imagesy($source);
        
        // Create thumbnail with cropped square aspect ratio
        $thumbnail = imagecreatetruecolor($thumbWidth, $thumbHeight);
        
        // Handle transparency
        imagealphablending($thumbnail, false);
        imagesavealpha($thumbnail, true);
        $transparent = imagecolorallocatealpha($thumbnail, 255, 255, 255, 127);
        imagefill($thumbnail, 0, 0, $transparent);
        
        // Calculate crop dimensions to maintain aspect ratio
        $sourceRatio = $width / $height;
        $targetRatio = $thumbWidth / $thumbHeight;
        
        if ($sourceRatio > $targetRatio) {
            // Source is wider, crop width
            $newWidth = $height * $targetRatio;
            $sourceX = ($width - $newWidth) / 2;
            $sourceY = 0;
            $sourceW = $newWidth;
            $sourceH = $height;
        } else {
            // Source is taller, crop height
            $newHeight = $width / $targetRatio;
            $sourceX = 0;
            $sourceY = ($height - $newHeight) / 2;
            $sourceW = $width;
            $sourceH = $newHeight;
        }
        
        imagecopyresampled(
            $thumbnail, $source,
            0, 0, $sourceX, $sourceY,
            $thumbWidth, $thumbHeight,
            $sourceW, $sourceH
        );
        
        $thumbPath = $filePath . '_thumb';
        $format = $this->getImageFormat($filePath);
        
        $success = false;
        switch ($format) {
            case 'jpeg':
                $success = imagejpeg($thumbnail, $thumbPath, 80);
                break;
            case 'png':
                $success = imagepng($thumbnail, $thumbPath);
                break;
            case 'gif':
                $success = imagegif($thumbnail, $thumbPath);
                break;
        }
        
        imagedestroy($source);
        imagedestroy($thumbnail);
        
        if (!$success) {
            throw new Exception('Failed to save thumbnail');
        }
        
        return [
            'thumbnail' => true,
            'dimensions' => ['width' => $thumbWidth, 'height' => $thumbHeight],
            'path' => $thumbPath
        ];
    }
    
    /**
     * Strip text chunks from image
     */
    private function stripImageTextChunks($filePath) {
        // Remove text chunks that might contain malicious content
        $format = $this->getImageFormat($filePath);
        
        switch ($format) {
            case 'png':
                return $this->stripPNGTextChunks($filePath);
            case 'jpeg':
                return $this->stripJPEGTextChunks($filePath);
            default:
                return false;
        }
    }
    
    /**
     * Strip PNG text chunks
     */
    private function stripPNGTextChunks($filePath) {
        $content = file_get_contents($filePath);
        
        // PNG signature
        $pngSignature = pack('H*', '89504E470D0A1A0A');
        
        if (substr($content, 0, 8) !== $pngSignature) {
            return false;
        }
        
        // Remove text chunks (tEXt, zTXt, iTXt)
        $content = preg_replace('/tEXt.{0,}?\x00\x00/', '', $content);
        $content = preg_replace('/zTXt.{0,}?\x00\x00/', '', $content);
        $content = preg_replace('/iTXt.{0,}?\x00\x00/', '', $content);
        
        // Update CRC and length
        $content = $this->updatePNGChunks($content);
        
        file_put_contents($filePath, $content);
        return true;
    }
    
    /**
     * Strip JPEG comments and APP segments
     */
    private function stripJPEGTextChunks($filePath) {
        $content = file_get_contents($filePath);
        
        // JPEG signature
        $jpegSignature = pack('H*', 'FFD8FF');
        
        if (substr($content, 0, 3) !== $jpegSignature) {
            return false;
        }
        
        // Remove JPEG comments (0xFFFE)
        $content = preg_replace('/\xFF\xFE.{2,}/s', '', $content);
        
        // Remove certain APP segments that contain text
        $content = preg_replace('/\xFF\xE0.{2,}/s', '', $content); // APP0
        $content = preg_replace('/\xFF\xE2.{2,}/s', '', $content); // APP2
        
        file_put_contents($filePath, $content);
        return true;
    }
    
    /**
     * Update PNG chunk CRC and length
     */
    private function updatePNGChunks($content) {
        // This is a simplified version - full implementation would recalculate all CRCs
        return $content;
    }
    
    /**
     * Validate image integrity
     */
    private function validateImageIntegrity($filePath) {
        $format = $this->getImageFormat($filePath);
        
        switch ($format) {
            case 'jpeg':
                return $this->validateJPEGIntegrity($filePath);
            case 'png':
                return $this->validatePNGIntegrity($filePath);
            case 'gif':
                return $this->validateGIFIntegrity($filePath);
            default:
                return ['valid' => false, 'error' => 'Unknown format'];
        }
    }
    
    /**
     * Validate JPEG integrity
     */
    private function validateJPEGIntegrity($filePath) {
        $handle = fopen($filePath, 'rb');
        if (!$handle) {
            return ['valid' => false, 'error' => 'Cannot open file'];
        }
        
        // Check JPEG signature
        $signature = fread($handle, 2);
        fclose($handle);
        
        if ($signature !== pack('H*', 'FFD8')) {
            return ['valid' => false, 'error' => 'Invalid JPEG signature'];
        }
        
        // Try to load image
        $image = @imagecreatefromjpeg($filePath);
        if (!$image) {
            return ['valid' => false, 'error' => 'Corrupted JPEG data'];
        }
        
        imagedestroy($image);
        return ['valid' => true];
    }
    
    /**
     * Validate PNG integrity
     */
    private function validatePNGIntegrity($filePath) {
        $handle = fopen($filePath, 'rb');
        if (!$handle) {
            return ['valid' => false, 'error' => 'Cannot open file'];
        }
        
        // Check PNG signature
        $signature = fread($handle, 8);
        fclose($handle);
        
        $expectedSignature = pack('H*', '89504E470D0A1A0A');
        if ($signature !== $expectedSignature) {
            return ['valid' => false, 'error' => 'Invalid PNG signature'];
        }
        
        // Try to load image
        $image = @imagecreatefrompng($filePath);
        if (!$image) {
            return ['valid' => false, 'error' => 'Corrupted PNG data'];
        }
        
        imagedestroy($image);
        return ['valid' => true];
    }
    
    /**
     * Validate GIF integrity
     */
    private function validateGIFIntegrity($filePath) {
        $handle = fopen($filePath, 'rb');
        if (!$handle) {
            return ['valid' => false, 'error' => 'Cannot open file'];
        }
        
        // Check GIF signature
        $signature = fread($handle, 6);
        fclose($handle);
        
        $expectedSignatures = ['GIF87a', 'GIF89a'];
        if (!in_array($signature, $expectedSignatures)) {
            return ['valid' => false, 'error' => 'Invalid GIF signature'];
        }
        
        // Try to load image
        $image = @imagecreatefromgif($filePath);
        if (!$image) {
            return ['valid' => false, 'error' => 'Corrupted GIF data'];
        }
        
        imagedestroy($image);
        return ['valid' => true];
    }
}

// Usage example
$processor = new ImageSecurityProcessor();

try {
    $result = $processor->processImage('/path/to/image.jpg', [
        'removeMetadata' => true,
        'resize' => true,
        'maxWidth' => 800,
        'maxHeight' => 600,
        'generateThumbnail' => true,
        'thumbWidth' => 150,
        'thumbHeight' => 150,
        'stripTextChunks' => true
    ]);
    
    echo json_encode($result);
    
} catch (Exception $e) {
    echo json_encode(['error' => $e->getMessage()]);
}
?>
```

---

## 5. File Upload Security Checklist and Testing

### 5.1 Security Test Suite
```javascript
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

class FileUploadSecurityTester {
    constructor() {
        this.testResults = [];
        this.testFiles = {
            // Malicious test files
            malicious: {
                php: Buffer.from('<?php system($_GET["cmd"]); ?>'),
                script: Buffer.from('#!/bin/sh\necho "Malicious script"'),
                executable: Buffer.from('\x4d\x5a'), // MZ header for Windows executable
                largeFile: Buffer.alloc(10 * 1024 * 1024), // 10MB file
                emptyFile: Buffer.alloc(0),
                doubleExt: Buffer.from('fake.jpg.php'),
                pathTraversal: Buffer.from('../../../etc/passwd'),
                nullByte: Buffer.from('image.jpg\x00.php'),
                svgScript: Buffer.from('<svg onload="alert(1)"/>')
            },
            
            // Valid test files (simplified)
            valid: {
                jpeg: Buffer.from('\xff\xd8\xff\xe0\x00\x10JFIF'), // JPEG header
                png: Buffer.from('\x89PNG\r\n\x1a\n'), // PNG header
                gif: Buffer.from('GIF87a'), // GIF header
                pdf: Buffer.from('%PDF-1.4'), // PDF header
                text: Buffer.from('This is a valid text file')
            }
        };
    }
    
    async runAllTests() {
        console.log('Running File Upload Security Tests...\n');
        
        await this.testFileValidation();
        await this.testMalwareDetection();
        await this.testFileProcessing();
        await this.testAccessControl();
        await this.testStorageSecurity();
        
        return this.generateReport();
    }
    
    async testFileValidation() {
        console.log('Testing File Validation...');
        
        const validationTests = [
            {
                name: 'Valid JPEG file',
                file: this.testFiles.valid.jpeg,
                expected: 'valid',
                check: (result) => result.valid === true
            },
            {
                name: 'Invalid executable file',
                file: this.testFiles.malicious.executable,
                expected: 'invalid',
                check: (result) => result.valid === false
            },
            {
                name: 'Empty file',
                file: this.testFiles.malicious.emptyFile,
                expected: 'invalid',
                check: (result) => result.valid === false
            },
            {
                name: 'Double extension file',
                file: this.testFiles.malicious.doubleExt,
                expected: 'invalid',
                check: (result) => result.valid === false
            },
            {
                name: 'Path traversal attempt',
                file: this.testFiles.malicious.pathTraversal,
                expected: 'invalid',
                check: (result) => result.valid === false
            }
        ];
        
        for (const test of validationTests) {
            try {
                const result = await this.validateFile(test.file);
                const passed = test.check(result);
                
                this.testResults.push({
                    category: 'File Validation',
                    test: test.name,
                    expected: test.expected,
                    actual: result.valid ? 'valid' : 'invalid',
                    passed: passed,
                    details: result
                });
                
                console.log(`  ${test.name}: ${passed ? '✓' : '✗'}`);
                
            } catch (error) {
                this.testResults.push({
                    category: 'File Validation',
                    test: test.name,
                    expected: test.expected,
                    actual: 'error',
                    passed: false,
                    error: error.message
                });
                
                console.log(`  ${test.name}: ✗ (${error.message})`);
            }
        }
    }
    
    async testMalwareDetection() {
        console.log('\nTesting Malware Detection...');
        
        const malwareTests = [
            {
                name: 'PHP script detection',
                file: this.testFiles.malicious.php,
                expected: 'infected',
                check: (result) => result.infected === true
            },
            {
                name: 'Shell script detection',
                file: this.testFiles.malicious.script,
                expected: 'infected',
                check: (result) => result.infected === true
            },
            {
                name: 'SVG with script',
                file: this.testFiles.malicious.svgScript,
                expected: 'infected',
                check: (result) => result.infected === true
            },
            {
                name: 'Valid JPEG file',
                file: this.testFiles.valid.jpeg,
                expected: 'clean',
                check: (result) => result.infected === false
            }
        ];
        
        for (const test of malwareTests) {
            try {
                const result = await this.scanFileForMalware(test.file);
                const passed = test.check(result);
                
                this.testResults.push({
                    category: 'Malware Detection',
                    test: test.name,
                    expected: test.expected,
                    actual: result.infected ? 'infected' : 'clean',
                    passed: passed,
                    details: result
                });
                
                console.log(`  ${test.name}: ${passed ? '✓' : '✗'}`);
                
            } catch (error) {
                this.testResults.push({
                    category: 'Malware Detection',
                    test: test.name,
                    expected: test.expected,
                    actual: 'error',
                    passed: false,
                    error: error.message
                });
                
                console.log(`  ${test.name}: ✗ (${error.message})`);
            }
        }
    }
    
    async testFileProcessing() {
        console.log('\nTesting File Processing...');
        
        // Test image processing
        try {
            const imageResult = await this.processImage(this.testFiles.valid.jpeg, {
                resize: true,
                maxWidth: 800,
                maxHeight: 600,
                removeMetadata: true
            });
            
            const imagePassed = imageResult.processed && !imageResult.error;
            
            this.testResults.push({
                category: 'File Processing',
                test: 'Image processing',
                expected: 'processed',
                actual: imageResult.processed ? 'processed' : 'failed',
                passed: imagePassed,
                details: imageResult
            });
            
            console.log(`  Image processing: ${imagePassed ? '✓' : '✗'}`);
            
        } catch (error) {
            this.testResults.push({
                category: 'File Processing',
                test: 'Image processing',
                expected: 'processed',
                actual: 'error',
                passed: false,
                error: error.message
            });
            
            console.log(`  Image processing: ✗ (${error.message})`);
        }
    }
    
    async testAccessControl() {
        console.log('\nTesting Access Control...');
        
        const accessTests = [
            {
                name: 'User can access own file',
                userId: 1,
                fileId: 1,
                expected: 'allowed',
                check: (result) => result.allowed === true
            },
            {
                name: 'User cannot access others private file',
                userId: 2,
                fileId: 1,
                expected: 'denied',
                check: (result) => result.allowed === false
            },
            {
                name: 'User can access public file',
                userId: 2,
                fileId: 2,
                expected: 'allowed',
                check: (result) => result.allowed === true
            }
        ];
        
        for (const test of accessTests) {
            try {
                const result = await this.checkFileAccess(test.userId, test.fileId);
                const passed = test.check(result);
                
                this.testResults.push({
                    category: 'Access Control',
                    test: test.name,
                    expected: test.expected,
                    actual: result.allowed ? 'allowed' : 'denied',
                    passed: passed,
                    details: result
                });
                
                console.log(`  ${test.name}: ${passed ? '✓' : '✗'}`);
                
            } catch (error) {
                this.testResults.push({
                    category: 'Access Control',
                    test: test.name,
                    expected: test.expected,
                    actual: 'error',
                    passed: false,
                    error: error.message
                });
                
                console.log(`  ${test.name}: ✗ (${error.message})`);
            }
        }
    }
    
    async testStorageSecurity() {
        console.log('\nTesting Storage Security...');
        
        const storageTests = [
            {
                name: 'Secure filename generation',
                check: () => {
                    const filename = this.generateSecureFilename('test.jpg', 1);
                    return filename.length > 0 && !filename.includes('..') && !filename.includes('/');
                }
            },
            {
                name: 'File permissions setting',
                check: async () => {
                    const testFile = await this.createTestFile();
                    await this.setSecureFilePermissions(testFile);
                    const stats = await fs.stat(testFile);
                    const permissions = (stats.mode & 0o777).toString(8);
                    await fs.unlink(testFile);
                    return permissions === '644';
                }
            }
        ];
        
        for (const test of storageTests) {
            try {
                const result = await test.check();
                
                this.testResults.push({
                    category: 'Storage Security',
                    test: test.name,
                    expected: 'secure',
                    actual: result ? 'secure' : 'insecure',
                    passed: result
                });
                
                console.log(`  ${test.name}: ${result ? '✓' : '✗'}`);
                
            } catch (error) {
                this.testResults.push({
                    category: 'Storage Security',
                    test: test.name,
                    expected: 'secure',
                    actual: 'error',
                    passed: false,
                    error: error.message
                });
                
                console.log(`  ${test.name}: ✗ (${error.message})`);
            }
        }
    }
    
    // Mock methods for testing (implement based on your actual file upload system)
    async validateFile(fileBuffer) {
        const validation = {
            valid: true,
            errors: [],
            size: fileBuffer.length,
            mimeType: 'application/octet-stream'
        };
        
        if (fileBuffer.length === 0) {
            validation.valid = false;
            validation.errors.push('Empty file');
        }
        
        if (fileBuffer.length > 5 * 1024 * 1024) {
            validation.valid = false;
            validation.errors.push('File too large');
        }
        
        // Check for dangerous patterns
        const dangerousPatterns = ['<?php', '#!/bin/sh', 'MZ', '../'];
        const fileString = fileBuffer.toString();
        
        for (const pattern of dangerousPatterns) {
            if (fileString.includes(pattern)) {
                validation.valid = false;
                validation.errors.push(`Dangerous pattern detected: ${pattern}`);
            }
        }
        
        return validation;
    }
    
    async scanFileForMalware(fileBuffer) {
        const threats = [];
        const fileString = fileBuffer.toString().toLowerCase();
        
        // Check for common malware signatures
        const malwareSignatures = [
            'eval(',
            'base64_decode',
            'system(',
            'exec(',
            'shell_exec',
            '<script',
            'onerror='
        ];
        
        for (const signature of malwareSignatures) {
            if (fileString.includes(signature)) {
                threats.push(`Detected: ${signature}`);
            }
        }
        
        return {
            infected: threats.length > 0,
            threats: threats,
            scanTime: new Date().toISOString()
        };
    }
    
    async processImage(fileBuffer, options) {
        // Mock image processing
        return {
            processed: true,
            metadata: { width: 800, height: 600 },
            resized: options.resize ? { width: 800, height: 600 } : null,
            metadataRemoved: options.removeMetadata || false
        };
    }
    
    async checkFileAccess(userId, fileId) {
        // Mock access control check
        const filePermissions = {
            1: { ownerId: 1, public: false },
            2: { ownerId: 1, public: true }
        };
        
        const file = filePermissions[fileId];
        if (!file) {
            return { allowed: false, reason: 'File not found' };
        }
        
        const allowed = file.public || file.ownerId === userId;
        
        return { allowed: allowed };
    }
    
    generateSecureFilename(originalName, userId) {
        const extension = path.extname(originalName);
        const timestamp = Date.now();
        const randomBytes = crypto.randomBytes(16).toString('hex');
        return `${timestamp}_${randomBytes}${extension}`;
    }
    
    async createTestFile() {
        const testPath = path.join(__dirname, 'test_file.txt');
        await fs.writeFile(testPath, 'test content');
        return testPath;
    }
    
    async setSecureFilePermissions(filePath) {
        await fs.chmod(filePath, 0o644);
    }
    
    generateReport() {
        const total = this.testResults.length;
        const passed = this.testResults.filter(r => r.passed).length;
        const failed = total - passed;
        const successRate = Math.round((passed / total) * 100);
        
        let report = '\n=== File Upload Security Test Report ===\n';
        report += `Total Tests: ${total}\n`;
        report += `Passed: ${passed}\n`;
        report += `Failed: ${failed}\n`;
        report += `Success Rate: ${successRate}%\n\n`;
        
        // Group by category
        const categories = {};
        this.testResults.forEach(result => {
            if (!categories[result.category]) {
                categories[result.category] = [];
            }
            categories[result.category].push(result);
        });
        
        for (const [category, results] of Object.entries(categories)) {
            const categoryPassed = results.filter(r => r.passed).length;
            const categoryTotal = results.length;
            const categoryRate = Math.round((categoryPassed / categoryTotal) * 100);
            
            report += `${category} (${categoryPassed}/${categoryTotal} - ${categoryRate}%)\n`;
            
            results.forEach(result => {
                const status = result.passed ? '✓' : '✗';
                report += `  ${status} ${result.test}\n`;
                if (!result.passed) {
                    report += `    Expected: ${result.expected}\n`;
                    report += `    Actual: ${result.actual}\n`;
                    if (result.error) {
                        report += `    Error: ${result.error}\n`;
                    }
                }
            });
            report += '\n';
        }
        
        console.log(report);
        
        return {
            summary: {
                total,
                passed,
                failed,
                successRate
            },
            categories: categories,
            results: this.testResults
        };
    }
}

// Run tests if this file is executed directly
if (require.main === module) {
    const tester = new FileUploadSecurityTester();
    tester.runAllTests().then(report => {
        process.exit(report.summary.failed > 0 ? 1 : 0);
    }).catch(error => {
        console.error('Test execution failed:', error);
        process.exit(1);
    });
}

module.exports = { FileUploadSecurityTester };
```

---

## Conclusion

This comprehensive file upload security implementation covers:

1. **File Validation** - MIME type checking, file signature validation, size limits
2. **Malware Scanning** - Integration with ClamAV and custom threat detection
3. **Secure Storage** - Secure filename generation, directory structure, permissions
4. **Access Control** - User-based permissions, file sharing, audit logging
5. **Processing Security** - Image processing with metadata removal, content validation
6. **Security Testing** - Comprehensive test suite for all security controls

**Key Security Principles:**
- **Never trust uploaded files** - Always validate and scan
- **Defense in depth** - Multiple layers of security controls
- **Principle of least privilege** - Minimal necessary access
- **Secure by default** - Conservative security settings
- **Regular security testing** - Continuous validation of security controls

**Remember:** File upload security is critical as it can lead to server compromise, data breaches, and malware distribution. Always implement multiple overlapping security controls and regularly test your implementation against known attack vectors.