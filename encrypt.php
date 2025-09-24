<?php
require_once 'EncryptionHelper.php';
session_start();

$message = '';
$messageType = '';
$encryptedUrl = '';
$encryptedParam = '';
$formData = $_SESSION['formData'] ?? null;
unset($_SESSION['formData']);

// Handle form submission
if ($_POST['action'] ?? '' === 'encrypt') {
    try {
        $nama = trim($_POST['nama'] ?? '');
        $id = trim($_POST['id'] ?? '');
        $telp = trim($_POST['telp'] ?? '');

        if (!$nama || !$id || !$telp) {
            throw new Exception('Semua field harus diisi!');
        }

        $formData = compact('nama', 'id', 'telp');
        $jsonData = json_encode($formData, JSON_UNESCAPED_UNICODE);
        $encrypted = EncryptionHelper::encryptData($jsonData);

        $baseUrl = $_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'] . dirname($_SERVER['REQUEST_URI']);
        $encryptedUrl = $baseUrl . '/decrypt.php?data=' . $encrypted;
        $encryptedParam = $encrypted;
        
        $_SESSION['formData'] = $formData;

        // TETAP di halaman ini; tampilkan URL terenkripsi dan sediakan tombol buka di tab baru

    } catch (Exception $e) {
        $message = 'Error: ' . $e->getMessage();
        $messageType = 'error';
    }
}

// URL akan ditampilkan langsung setelah enkripsi berhasil
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
        
        <div class="navigation">
            <a href="index.php" class="nav-link">Home</a>
            <a href="encrypt.php" class="nav-link active">Enkripsi</a>
        </div>
        
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
                           value="<?php echo htmlspecialchars($formData['nama'] ?? $_POST['nama'] ?? ''); ?>">
                </div>
                
                <div class="form-group">
                    <label for="id">ID/NIP:</label>
                    <input type="text" id="id" name="id" required 
                           value="<?php echo htmlspecialchars($formData['id'] ?? $_POST['id'] ?? ''); ?>">
                </div>
            </div>
            
            <div class="form-group">
                <label for="telp">Nomor Telepon:</label>
                <input type="text" id="telp" name="telp" required 
                       value="<?php echo htmlspecialchars($formData['telp'] ?? $_POST['telp'] ?? ''); ?>">
            </div>
            
            <button type="submit">Enkripsi & Generate URL</button>
        </form>

        <?php if (!empty($encryptedUrl)): ?>
            <div class="url-display">
                <div class="url-title">URL terenkripsi berhasil dibuat</div>
                <div class="url-link">
                    <a href="<?php echo htmlspecialchars($encryptedUrl); ?>" target="_blank">
                        <?php echo htmlspecialchars($encryptedUrl); ?>
                    </a>
                </div>
                <button class="copy-btn" onclick="copyToClipboard('<?php echo htmlspecialchars($encryptedUrl); ?>')">Salin URL</button>
                <button class="copy-btn" onclick="openDecrypt('<?php echo htmlspecialchars($encryptedUrl); ?>')">Buka dekripsi (tab baru)</button>
            </div>
            <script>
                (function(){
                    var enc = '<?php echo rawurlencode($encryptedParam); ?>';
                    if (enc) {
                        var newUrl = 'encrypt.php?data=' + enc;
                        if (window.history && window.history.replaceState) {
                            window.history.replaceState(null, '', newUrl);
                        }
                    }
                })();
            </script>
        <?php endif; ?>
    </div>

    <script>
        function copyToClipboard(text) {
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(text).then(function() {
                    alert('URL berhasil disalin ke clipboard!');
                }, function() {
                    fallbackCopyToClipboard(text);
                });
            } else {
                fallbackCopyToClipboard(text);
            }
        }
        
        function fallbackCopyToClipboard(text) {
            var textArea = document.createElement("textarea");
            textArea.value = text;
            textArea.style.position = "fixed";
            textArea.style.left = "-999999px";
            textArea.style.top = "-999999px";
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            
            try {
                document.execCommand('copy');
                alert('URL berhasil disalin ke clipboard!');
            } catch (err) {
                alert('Tidak dapat menyalin URL. Silakan salin manual.');
            }
            
            document.body.removeChild(textArea);
        }

        function openDecrypt(url) {
            if (!url) return;
            window.open(url, '_blank');
        }
    </script>
</body>
</html>