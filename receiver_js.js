// Utility function for base64 decoding
const b64decode = s => {
  const bin = atob(s);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr.buffer;
};

// AES-GCM decryption functions
async function importKeyRaw(b64) {
  const raw = b64decode(b64);
  return crypto.subtle.importKey("raw", raw, "AES-GCM", true, ["decrypt"]);
}

async function aesGcmDecrypt(key, blobBytes) {
  const iv = blobBytes.slice(0, 12);
  const ct = blobBytes.slice(12);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, ct);
  return new Uint8Array(pt);
}

// Steganography extraction functions
function bitsToBytes(bits) {
  const n = Math.floor(bits.length / 8);
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    let v = 0;
    for (let b = 0; b < 8; b++) v = (v << 1) | bits[i * 8 + b];
    out[i] = v;
  }
  return out;
}

function extractFromImageData(imgData) {
  const pixels = imgData.data;
  // read first 32 bits (4 bytes) header
  const headerBits = new Uint8Array(32);
  for (let i = 0; i < 32; i++) headerBits[i] = pixels[i] & 1;
  const headerBytes = bitsToBytes(headerBits);
  const len = (headerBytes[0] << 24) | (headerBytes[1] << 16) | (headerBytes[2] << 8) | headerBytes[3];
  const totalBits = (4 + len) * 8;
  if (totalBits > pixels.length) throw new Error("Payload length exceeds image capacity or image truncated.");
  const allBits = new Uint8Array(totalBits);
  for (let i = 0; i < totalBits; i++) allBits[i] = pixels[i] & 1;
  const allBytes = bitsToBytes(allBits);
  return allBytes.slice(4, 4 + len);
}

// DOM elements
const stegoFile = document.getElementById("stegoFile");
const aesKeyInput = document.getElementById("aesKeyInput");
const extractBtn = document.getElementById("extractBtn");
const clearBtn = document.getElementById("clearBtn");
const outputMessage = document.getElementById("outputMessage");
const log = document.getElementById("log");
const canvas = document.getElementById("canvas");
const ctx = canvas.getContext("2d");

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
extractBtn.addEventListener("click", async () => {
  try {
    if (!stegoFile.files[0]) { 
      setLog("Please upload a stego image.", true); 
      return; 
    }
    if (!aesKeyInput.value.trim()) { 
      setLog("Paste the base64 AES key provided by the sender.", true); 
      return; 
    }

    setLog("Processing image...");
    await loadImageToCanvas(stegoFile.files[0]);
    const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const payload = extractFromImageData(imgData);
    const key = await importKeyRaw(aesKeyInput.value.trim());
    const decrypted = await aesGcmDecrypt(key, payload.buffer);
    const text = new TextDecoder().decode(decrypted);
    outputMessage.value = text;
    setLog("Success — message extracted and decrypted.");
  } catch (e) {
    setLog("Error: " + (e && e.message ? e.message : e), true);
  }
});

clearBtn.addEventListener("click", () => {
  stegoFile.value = "";
  aesKeyInput.value = "";
  outputMessage.value = "";
  log.innerText = "";
});