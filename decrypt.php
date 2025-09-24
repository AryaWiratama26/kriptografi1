<?php
require_once 'EncryptionHelper.php';
session_start();

$message = '';
$messageType = '';
$decryptedData = '';
$formData = null;

$action = $_POST['action'] ?? null;

try {
    switch ($action) {
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
            break;
    }
} catch (Exception $e) {
    $message = 'Error: ' . $e->getMessage();
    $messageType = 'error';
}

$hasDataInUrl = !empty($_GET['data']);
if ($hasDataInUrl && !$message) {
    $message = 'Data terenkripsi ditemukan di URL. Gunakan tombol dekripsi di bawah untuk melihat data.';
    $messageType = 'info';
}
?>

<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Form Dekripsi AES-256-GCM</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Form Dekripsi AES-256-GCM</h1>
        <p class="subtitle">Dekripsi data terenkripsi dari URL</p>
        
        <div class="warning">
            <strong>Catatan Keamanan:</strong> Pastikan URL yang Anda masukkan berasal dari sumber terpercaya. 
            Proses dekripsi akan menggunakan kunci yang terdapat dalam URL.
        </div>

        <?php if (!empty($message)): ?>
            <div class="message <?php echo $messageType; ?>">
                <?php echo htmlspecialchars($message); ?>
            </div>
        <?php endif; ?>

        <!-- Form Dekripsi dari URL -->
        <h2>Dekripsi dari URL</h2>
        <form method="POST">
            <input type="hidden" name="action" value="decrypt_url">
            <div class="form-group">
                <label for="url_input">Masukkan URL untuk didekripsi:</label>
                <input type="url" id="url_input" name="url_input" 
                       placeholder="https://example.com/decrypt.php?data=..." 
                       value="<?php echo htmlspecialchars($_POST['url_input'] ?? ''); ?>">
            </div>
            <button type="submit">🔍 Dekripsi dari URL Input</button>
        </form>
        
        <?php if ($hasDataInUrl): ?>
            <div class="divider">
                <span>ATAU</span>
            </div>
            
            <h2>Dekripsi data di URL ini</h2>
            <p>Data terenkripsi ditemukan di URL halaman ini. Klik tombol di bawah untuk mendekripsi:</p>
            <form method="POST">
                <input type="hidden" name="action" value="decrypt_current">
                <button type="submit" class="btn-secondary">Dekripsi data dari URL halaman ini</button>
            </form>
        <?php endif; ?>
        
        <?php if (!empty($decryptedData) && $formData): ?>
            <div class="data-display">
                <h3>Hasil dekripsi - Data form</h3>
                <div class="data-field">
                    <strong>Nama Lengkap:</strong> <?php echo htmlspecialchars($formData['nama'] ?? 'N/A'); ?>
                </div>
                <div class="data-field">
                    <strong>ID/NIP:</strong> <?php echo htmlspecialchars($formData['id'] ?? 'N/A'); ?>
                </div>
                <div class="data-field">
                    <strong>Nomor Telepon:</strong> <?php echo htmlspecialchars($formData['telp'] ?? 'N/A'); ?>
                </div>
            </div>
            
            <h3>Raw JSON Data:</h3>
            <div class="decrypted-output"><?php echo htmlspecialchars($decryptedData); ?></div>
        <?php endif; ?>
    </div>
</body>
</html>