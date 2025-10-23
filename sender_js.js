// Utility functions for encoding/decoding
const b64encode = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const b64decode = s => {
  const bin = atob(s);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr.buffer;
};
const concatUint8 = (...parts) => {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
};

// AES-GCM encryption functions
async function genAesKey() {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}

async function exportKeyRaw(key) {
  const raw = await crypto.subtle.exportKey("raw", key);
  return b64encode(raw);
}

async function importKeyRaw(b64) {
  const raw = b64decode(b64);
  return crypto.subtle.importKey("raw", raw, "AES-GCM", true, ["encrypt", "decrypt"]);
}

async function aesGcmEncrypt(key, plaintextBytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintextBytes);
  return concatUint8(iv, new Uint8Array(ct));
}

// Steganography functions
function packPayload(payloadUint8) {
  const len = payloadUint8.length;
  const header = new Uint8Array(4);
  header[0] = (len >>> 24) & 0xff;
  header[1] = (len >>> 16) & 0xff;
  header[2] = (len >>> 8) & 0xff;
  header[3] = len & 0xff;
  return concatUint8(header, payloadUint8);
}

function bytesToBits(u8arr) {
  const bits = new Uint8Array(u8arr.length * 8);
  for (let i = 0; i < u8arr.length; i++) {
    for (let b = 0; b < 8; b++) bits[i * 8 + b] = (u8arr[i] >> (7 - b)) & 1;
  }
  return bits;
}

function embedIntoImageData(imgData, payloadBytes) {
  const bits = bytesToBits(payloadBytes);
  const pixels = imgData.data;
  if (bits.length > pixels.length) throw new Error("Carrier image too small for payload.");
  for (let i = 0; i < bits.length; i++) pixels[i] = (pixels[i] & 0xFE) | bits[i];
  return imgData;
}

// DOM elements
const carrierFile = document.getElementById("carrierFile");
const plaintextEl = document.getElementById("plaintext");
const genKeyBtn = document.getElementById("genKey");
const advToggle = document.getElementById("advToggle");
const advancedPanel = document.getElementById("advancedPanel");
const importKeyBtn = document.getElementById("importKey");
const importKeyInput = document.getElementById("importKeyInput");
const exportedKey = document.getElementById("exportedKey");
const copyKeyBtn = document.getElementById("copyKey");
const embedBtn = document.getElementById("embedBtn");
const downloadLink = document.getElementById("downloadLink");
const log = document.getElementById("log");
const canvas = document.getElementById("canvas");
const ctx = canvas.getContext("2d");

// Global state
let currentAESKey = null;

// Utility functions
const setLog = (msg, isError = false) => {
  log.innerText = msg;
  if (isError) log.classList.add("text-red-400");
  else log.classList.remove("text-red-400");
};

async function loadImageToCanvas(file) {
  return new Promise((res, rej) => {
    const img = new Image();
    img.onload = () => {
      canvas.width = img.naturalWidth;
      canvas.height = img.naturalHeight;
      ctx.drawImage(img, 0, 0);
      res();
    };
    img.onerror = rej;
    const reader = new FileReader();
    reader.onload = ev => img.src = ev.target.result;
    reader.readAsDataURL(file);
  });
}

// Event listeners
advToggle.addEventListener("click", () => {
  advancedPanel.classList.toggle("hidden");
});

genKeyBtn.addEventListener("click", async () => {
  try {
    currentAESKey = await genAesKey();
    const b64 = await exportKeyRaw(currentAESKey);
    exportedKey.value = b64;
    setLog("AES-256 key generated. Share the base64 key via a secure channel.");
  } catch (e) {
    setLog("Key generation failed: " + e.message, true);
  }
});

importKeyBtn.addEventListener("click", async () => {
  const b64 = importKeyInput.value.trim();
  if (!b64) { setLog("Paste a base64 key first.", true); return; }
  try {
    currentAESKey = await importKeyRaw(b64);
    exportedKey.value = b64;
    setLog("Key imported successfully.");
  } catch (e) {
    setLog("Import failed: " + e.message, true);
  }
});

copyKeyBtn.addEventListener("click", async () => {
  const key = exportedKey.value.trim();
  if (!key) { setLog("No key to copy.", true); return; }
  try {
    await navigator.clipboard.writeText(key);
    copyKeyBtn.textContent = "Copied!";
    setTimeout(() => copyKeyBtn.textContent = "Copy", 1500);
    setLog("Key copied to clipboard.");
  } catch (e) {
    setLog("Copy failed: " + e.message, true);
  }
});

embedBtn.addEventListener("click", async () => {
  try {
    if (!carrierFile.files[0]) { setLog("Please select a carrier image.", true); return; }
    if (!plaintextEl.value) { setLog("Enter a message to hide.", true); return; }
    if (!currentAESKey) { setLog("Generate or import an AES key first.", true); return; }

    setLog("Processing image...");
    await loadImageToCanvas(carrierFile.files[0]);
    const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);

    const plaintextBytes = new TextEncoder().encode(plaintextEl.value);
    const encrypted = await aesGcmEncrypt(currentAESKey, plaintextBytes);
    const packed = packPayload(encrypted);

    if (packed.length * 8 > imgData.data.length) {
      setLog("Carrier image too small. Choose a larger image or shorter message.", true);
      return;
    }

    const newImgData = embedIntoImageData(imgData, packed);
    ctx.putImageData(newImgData, 0, 0);

    const dataUrl = canvas.toDataURL("image/png");
    downloadLink.href = dataUrl;
    downloadLink.classList.remove("hidden");
    setLog("Success — message embedded. Download the image and share the key separately.");
  } catch (e) {
    setLog("Error during embedding: " + (e && e.message ? e.message : e), true);
  }
});
