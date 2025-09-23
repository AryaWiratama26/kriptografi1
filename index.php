<?php
require_once 'EncryptionHelper.php';
session_start();

$message = '';
$messageType = '';
$encryptedUrl = '';
$decryptedData = '';
$showDecryptForm = false;
$formData = $_SESSION['formData'] ?? null;
unset($_SESSION['formData']);

$action = $_POST['action'] ?? null;

try {
    switch ($action) {
        case 'encrypt':
            $nama = trim($_POST['nama'] ?? '');
            $id = trim($_POST['id'] ?? '');
            $telp = trim($_POST['telp'] ?? '');

            if (!$nama || !$id || !$telp) {
                throw new Exception('Semua field harus diisi!');
            }

            $formData = compact('nama', 'id', 'telp');
            $jsonData = json_encode($formData, JSON_UNESCAPED_UNICODE);
            $encrypted = EncryptionHelper::encryptData($jsonData);

            $url = $_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'] . strtok($_SERVER['REQUEST_URI'], '?');
            $_SESSION['formData'] = $formData;
            $_SESSION['message'] = 'Data berhasil dienkripsi dan URL telah dibuat!';
            $_SESSION['messageType'] = 'success';

            header("Location: {$url}?data={$encrypted}");
            exit;

        case 'decrypt_url':
            $inputUrl = trim($_POST['url_input'] ?? '');
            if (!$inputUrl) throw new Exception('Masukkan URL!');
            if (!EncryptionHelper::isValidUrl($inputUrl)) throw new Exception('URL tidak valid!');

            $encryptedData = EncryptionHelper::extractDataFromUrl($inputUrl);
            if (!$encryptedData) throw new Exception('Data terenkripsi tidak ditemukan di URL.');

            $decryptedJson = EncryptionHelper::decryptData($encryptedData);
            $formData = json_decode($decryptedJson, true);
            if (json_last_error() !== JSON_ERROR_NONE) throw new Exception('Data JSON tidak valid!');

            $decryptedData = json_encode($formData, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
            $message = 'Data berhasil didekripsi dari URL input!';
            $messageType = 'success';
            $showDecryptForm = true;
            break;

        case 'decrypt_current':
            $encryptedData = $_GET['data'] ?? '';
            if (!$encryptedData) throw new Exception('Tidak ada data terenkripsi di URL halaman.');

            $decryptedJson = EncryptionHelper::decryptData($encryptedData);
            $formData = json_decode($decryptedJson, true);
            if (json_last_error() !== JSON_ERROR_NONE) throw new Exception('Data JSON tidak valid!');

            $decryptedData = json_encode($formData, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
            $message = 'Data berhasil didekripsi dari URL halaman ini!';
            $messageType = 'success';
            $showDecryptForm = true;
            break;
    }
} catch (Exception $e) {
    $message = 'Error: ' . $e->getMessage();
    $messageType = 'error';
    $showDecryptForm = true;
}

$hasDataInUrl = !empty($_GET['data']);
if ($hasDataInUrl && !$message) {
    $message = 'Data terenkripsi ditemukan di URL. Gunakan form dekripsi untuk melihat data.';
    $messageType = 'info';
    $showDecryptForm = true;
    if ($formData) {
        $encryptedUrl = $_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    }
}
?>

<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Form Enkripsi AES-256-GCM</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        
        h1 {
            color: #333;
            text-align: center;
            margin-bottom: 10px;
        }
        
        .subtitle {
            text-align: center;
            color: #666;
            margin-bottom: 30px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
        }
        
        input[type="text"], input[type="url"], textarea {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 6px;
            box-sizing: border-box;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        
        input[type="text"]:focus, input[type="url"]:focus, textarea:focus {
            border-color: #007bff;
            outline: none;
        }
        
        button {
            background: linear-gradient(135deg, #007bff, #0056b3);
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            margin-right: 10px;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        button:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0,123,255,0.3);
        }
        
        button:active {
            transform: translateY(0);
        }
        
        .btn-secondary {
            background: linear-gradient(135deg, #6c757d, #545b62);
        }
        
        .btn-secondary:hover {
            box-shadow: 0 4px 12px rgba(108,117,125,0.3);
        }
        
        .message {
            padding: 15px;
            border-radius: 6px;
            margin: 20px 0;
            font-weight: 500;
        }
        
        .message.success {
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }
        
        .message.error {
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }
        
        .message.info {
            background-color: #d1ecf1;
            border: 1px solid #bee5eb;
            color: #0c5460;
        }
        
        .warning {
            background: linear-gradient(135deg, #fff3cd, #ffeaa7);
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 25px;
            font-size: 14px;
        }
        
        .url-display {
            background: linear-gradient(135deg, #e3f2fd, #bbdefb);
            border: 2px solid #2196f3;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
            position: relative;
        }
        
        .url-display::before {
            content: "🔗";
            font-size: 24px;
            position: absolute;
            top: 15px;
            left: 15px;
        }
        
        .url-display .url-title {
            font-weight: 600;
            color: #1976d2;
            margin-bottom: 10px;
            margin-left: 35px;
        }
        
        .url-display .url-link {
            word-break: break-all;
            background: white;
            padding: 12px;
            border-radius: 6px;
            border: 1px solid #90caf9;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }
        
        .url-display .url-link a {
            color: #1976d2;
            text-decoration: none;
        }
        
        .url-display .url-link a:hover {
            text-decoration: underline;
        }
        
        .copy-btn {
            background: #4caf50;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            margin-top: 10px;
            transition: background 0.3s;
        }
        
        .copy-btn:hover {
            background: #45a049;
        }
        
        .decrypted-output {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #dee2e6;
            font-family: 'Courier New', monospace;
            white-space: pre-wrap;
            max-height: 300px;
            overflow-y: auto;
        }
        
        .divider {
            text-align: center;
            margin: 30px 0;
            color: #6c757d;
            position: relative;
        }
        
        .divider::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 0;
            right: 0;
            height: 1px;
            background: #dee2e6;
            z-index: 1;
        }
        
        .divider span {
            background: white;
            padding: 0 20px;
            position: relative;
            z-index: 2;
            font-weight: 600;
        }
        
        .hidden {
            display: none;
        }
        
        .form-row {
            display: flex;
            gap: 15px;
        }
        
        .form-row .form-group {
            flex: 1;
        }
        
        @media (max-width: 600px) {
            .form-row {
                flex-direction: column;
            }
            
            button {
                margin-bottom: 10px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Form Enkripsi AES-256-GCM</h1>
        <p class="subtitle">Enkripsi data form secara aman dengan AES-256-GCM</p>
        
        <div class="warning">
            <strong>⚠️ Catatan Keamanan:</strong> Data akan dienkripsi menggunakan AES-256-GCM dengan kunci random. 
            URL yang dihasilkan mengandung kunci dekripsi, jadi bagikan dengan hati-hati kepada pihak yang berwenang.
        </div>

        <?php if (!empty($message)): ?>
            <div class="message <?php echo $messageType; ?>">
                <?php echo htmlspecialchars($message); ?>
            </div>
        <?php endif; ?>

        <!-- Form Input -->
        <form method="POST">
            <input type="hidden" name="action" value="encrypt">
            
            <h2>Input Data</h2>
            
            <div class="form-row">
                <div class="form-group">
                    <label for="nama">Nama Lengkap:</label>
                    <input type="text" id="nama" name="nama" required 
                           value="<?php echo htmlspecialchars($formDataFromSession['nama'] ?? $_POST['nama'] ?? ''); ?>">
                </div>
                
                <div class="form-group">
                    <label for="id">ID/NIP:</label>
                    <input type="text" id="id" name="id" required 
                           value="<?php echo htmlspecialchars($formDataFromSession['id'] ?? $_POST['id'] ?? ''); ?>">
                </div>
            </div>
            
            <div class="form-group">
                <label for="telp">Nomor Telepon:</label>
                <input type="text" id="telp" name="telp" required 
                       value="<?php echo htmlspecialchars($formDataFromSession['telp'] ?? $_POST['telp'] ?? ''); ?>">
            </div>
            
            <button type="submit">Enkripsi & Generate URL</button>
        </form>

        <?php if (!empty($encryptedUrl)): ?>
            <div class="url-display">
                <div class="url-title">URL Terenkripsi Berhasil Dibuat!</div>
                <div class="url-link">
                    <a href="<?php echo htmlspecialchars($encryptedUrl); ?>" target="_blank">
                        <?php echo htmlspecialchars($encryptedUrl); ?>
                    </a>
                </div>
                <button class="copy-btn" onclick="copyToClipboard('<?php echo htmlspecialchars($encryptedUrl); ?>')">
                    Copy URL
                </button>
            </div>
        <?php endif; ?>
    </div>

    <?php if ($showDecryptForm || $hasDataInUrl): ?>
        <div class="container">
            <div class="divider">
                <span>DEKRIPSI DATA</span>
            </div>
            
            <h2>Dekripsi dari URL</h2>
            
            <form method="POST">
                <input type="hidden" name="action" value="decrypt_url">
                <div class="form-group">
                    <label for="url_input">Masukkan URL untuk didekripsi:</label>
                    <input type="url" id="url_input" name="url_input" 
                           placeholder="https://example.com/page?data=..." 
                           value="<?php echo htmlspecialchars($_POST['url_input'] ?? ''); ?>">
                </div>
                <button type="submit">Dekripsi dari URL Input</button>
            </form>
            
            <?php if ($hasDataInUrl): ?>
                <div class="divider">
                    <span>ATAU</span>
                </div>
                
                <form method="POST">
                    <input type="hidden" name="action" value="decrypt_current">
                    <button type="submit" class="btn-secondary">🔓 Dekripsi Data dari URL Halaman Ini</button>
                </form>
            <?php endif; ?>
            
            <?php if (!empty($decryptedData)): ?>
                <h3>Hasil Dekripsi:</h3>
                <div class="decrypted-output"><?php echo htmlspecialchars($decryptedData); ?></div>
            <?php endif; ?>
        </div>
    <?php endif; ?>
</body>
</html>