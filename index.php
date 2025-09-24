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
    <link rel="stylesheet" href="style.css">

</head>
<body>
    <div class="container">
        <h1>Form Enkripsi AES-256-GCM</h1>
        <p class="subtitle">Enkripsi data form secara aman dengan AES-256-GCM</p>

        <div class="warning">
            <strong>Catatan Keamanan:</strong> Data akan dienkripsi menggunakan AES-256-GCM dengan kunci random. 
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
                    <button type="submit" class="btn-secondary">Dekripsi Data dari URL Halaman Ini</button>
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