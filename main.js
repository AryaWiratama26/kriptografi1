// Fungsi untuk menghasilkan kunci AES secara random
async function generateKey() {
  return await window.crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256
    },
    true, // extractable
    ["encrypt", "decrypt"]
  );
}

// Export kunci ke format yang bisa disimpan
async function exportKey(key) {
  const exported = await window.crypto.subtle.exportKey("raw", key);
  return new Uint8Array(exported);
}

// Import kunci dari array buffer
async function importKey(keyData) {
  return await window.crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "AES-GCM" },
    true,
    ["encrypt", "decrypt"]
  );
}

// Fungsi enkripsi AES-GCM dengan kunci random
async function encryptData(data) {
  const enc = new TextEncoder();
  const key = await generateKey();
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  
  const encrypted = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    key,
    enc.encode(data)
  );
  
  // Export kunci untuk disimpan dalam URL
  const exportedKey = await exportKey(key);
  
  // Gabungkan key, iv, dan data terenkripsi
  const result = new Uint8Array(exportedKey.length + iv.length + encrypted.byteLength);
  result.set(exportedKey, 0);
  result.set(iv, exportedKey.length);
  result.set(new Uint8Array(encrypted), exportedKey.length + iv.length);
  
  return result;
}

// Fungsi dekripsi AES-GCM
async function decryptData(encryptedData) {
  const keyData = encryptedData.slice(0, 32); // 32 bytes untuk AES-256 key
  const iv = encryptedData.slice(32, 44); // 12 bytes untuk IV
  const data = encryptedData.slice(44); // Sisanya adalah encrypted data
  
  const key = await importKey(keyData);
  
  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    key,
    data
  );
  
  const dec = new TextDecoder();
  return dec.decode(decrypted);
}

// Base64 URL-safe encoding
function arrayBufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Base64 URL-safe decoding
function base64UrlToArrayBuffer(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '===='.slice(0, (4 - base64.length % 4) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Submit form dengan enkripsi
document.getElementById("myForm").addEventListener("submit", async function(e) {
  e.preventDefault();
  
  const formData = new FormData(e.target);
  const obj = {};
  formData.forEach((v, k) => obj[k] = v);
  
  try {
    // Ubah ke JSON lalu enkripsi
    const jsonStr = JSON.stringify(obj);
    const encrypted = await encryptData(jsonStr);
    
    // Encode ke base64 URL-safe
    const encoded = arrayBufferToBase64Url(encrypted);
    
    // Buat URL
    const url = `${location.origin}${location.pathname}?data=${encoded}`;
    document.getElementById("urlOutput").innerHTML = 
      `<div class="success">URL berhasil dibuat!</div><a href="${url}" target="_blank">${url}</a>`;
    
    // Update URL browser
    history.pushState(null, "", `?data=${encoded}`);
    
    showMessage('Data berhasil dienkripsi dan URL telah dibuat!', 'success');
    
  } catch (err) {
    showMessage('Gagal mengenkripsi data: ' + err.message, 'error');
  }
});

// Fungsi helper untuk mengekstrak data dari URL
function extractDataFromUrl(url) {
  try {
    const urlObj = new URL(url);
    const params = new URLSearchParams(urlObj.search);
    return params.get("data");
  } catch (err) {
    throw new Error("URL tidak valid");
  }
}

// Dekripsi data dari URL input
document.getElementById("btnDecodeFromUrl").addEventListener("click", async function() {
  const urlInput = document.getElementById('urlInput').value.trim();
  
  if (!urlInput) {
    showMessage('Masukkan URL yang akan didekripsi!', 'error');
    return;
  }
  
  try {
    // Extract data dari URL
    const data = extractDataFromUrl(urlInput);
    
    if (!data) {
      document.getElementById("decoded").textContent = "Tidak ada data terenkripsi dalam URL tersebut.";
      showMessage('URL tidak mengandung data terenkripsi!', 'error');
      return;
    }
    
    // Decode dari base64 URL-safe
    const encryptedData = base64UrlToArrayBuffer(data);
    
    // Dekripsi data
    const decryptedJson = await decryptData(encryptedData);
    const obj = JSON.parse(decryptedJson);
    
    document.getElementById("decoded").textContent = JSON.stringify(obj, null, 2);
    showMessage('Data berhasil didekripsi dari URL input!', 'success');
    
    // Update URL browser dengan data yang didekripsi (opsional)
    history.pushState(null, "", `?data=${data}`);
    
  } catch (err) {
    document.getElementById("decoded").textContent = "Gagal mendekripsi data. " + err.message;
    showMessage('Gagal mendekripsi: ' + err.message, 'error');
  }
});

// Dekripsi data dari URL halaman saat ini
document.getElementById("btnDecode").addEventListener("click", async function() {
  const params = new URLSearchParams(location.search);
  const data = params.get("data");
  
  if (!data) {
    document.getElementById("decoded").textContent = "Tidak ada data terenkripsi di URL halaman ini.";
    showMessage('URL halaman ini tidak mengandung data terenkripsi!', 'error');
    return;
  }
  
  try {
    // Decode dari base64 URL-safe
    const encryptedData = base64UrlToArrayBuffer(data);
    
    // Dekripsi data
    const decryptedJson = await decryptData(encryptedData);
    const obj = JSON.parse(decryptedJson);
    
    document.getElementById("decoded").textContent = JSON.stringify(obj, null, 2);
    showMessage('Data berhasil didekripsi dari URL halaman ini!', 'success');
    
  } catch (err) {
    document.getElementById("decoded").textContent = "Gagal mendekripsi data. Data mungkin rusak atau format tidak valid.";
    showMessage('Gagal mendekripsi: ' + err.message, 'error');
  }
});

// Fungsi helper untuk menampilkan pesan
function showMessage(message, type) {
  // Hapus pesan sebelumnya
  const existingMessages = document.querySelectorAll('.message');
  existingMessages.forEach(msg => msg.remove());
  
  const messageDiv = document.createElement('div');
  messageDiv.className = `message ${type}`;
  messageDiv.textContent = message;
  
  document.body.insertBefore(messageDiv, document.body.firstChild);
  
  // Auto remove setelah 5 detik
  setTimeout(() => {
    if (messageDiv.parentNode) {
      messageDiv.remove();
    }
  }, 5000);
}

// Cek apakah ada data di URL saat halaman dimuat
window.addEventListener('load', function() {
  const params = new URLSearchParams(location.search);
  if (params.get('data')) {
    showMessage('Data terenkripsi ditemukan di URL. Klik "Dekripsi Data dari URL" untuk melihat data.', 'success');
  }
});