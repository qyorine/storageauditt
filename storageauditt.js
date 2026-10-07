#!/usr/bin/env node

/**
 * ============================================================================
 * UTILITAS AUDIT PENYIMPANAN (STORAGE AUDIT CLI) - storageauditt.js
 * ============================================================================
 * Modul Native: fs, path, crypto, readline
 * Dependensi Eksternal: ZERO (0 npm packages)
 *
 * Fitur:
 * - STG-01: Recursive Scan (Memindai folder & subfolder secara mendalam)
 * - STG-02: Duplicate Detection (Identifikasi file duplikat via hash SHA-256)
 * - STG-03: Giant File Flagging (Menandai file berukuran >= 2 MB / 2.048 KB)
 * - STG-04: Terminal Report (Laporan terstruktur & estimasi penghematan ruang)
 * - STG-05: Safe Cleanup Confirmation (Konfirmasi interaktif & pembersihan aman)
 * - STG-06: Zero-Dependency Portability (Jalan langsung: node storageauditt.js)
 * ============================================================================
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

// Ambang Batas Ukuran File Raksasa: 2 MB (2.048 KB = 2.097.152 bytes)
const GIANT_FILE_THRESHOLD_BYTES = 2 * 1024 * 1024; // 2.048 KB

// Format ukuran byte ke format yang mudah dibaca manusia (B, KB, MB, GB)
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const val = bytes / Math.pow(k, i);
  return `${val.toFixed(2)} ${sizes[i]}`;
}

// Format khusus untuk menampilkan detail MB dan KB secara bersamaan
function formatDualSize(bytes) {
  const mb = (bytes / (1024 * 1024)).toFixed(2);
  const kb = (bytes / 1024).toLocaleString('id-ID', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  return `${mb} MB (${kb} KB)`;
}

// Menghitung hash SHA-256 dari konten file secara efisien
function calculateSha256(filePath) {
  const fileBuffer = fs.readFileSync(filePath);
  const hashSum = crypto.createHash('sha256');
  hashSum.update(fileBuffer);
  return hashSum.digest('hex');
}

/**
 * STG-01: Recursive Scan
 * Memindai direktori target dan semua subdirektorinya secara rekursif.
 * Mengumpulkan nama file, path lengkap, path relatif, ukuran byte, dan SHA-256.
 */
function scanDirectoryRecursive(dirPath, rootDir, fileList = []) {
  if (!fs.existsSync(dirPath)) {
    return fileList;
  }

  const entries = fs.readdirSync(dirPath, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);

    // Lewati skrip audit itu sendiri jika berada di direktori yang sama
    if (entry.name === 'storageauditt.js' || entry.name === 'storageauditt.py' || entry.name === '.git') {
      continue;
    }

    try {
      if (entry.isDirectory()) {
        scanDirectoryRecursive(fullPath, rootDir, fileList);
      } else if (entry.isFile()) {
        const stats = fs.statSync(fullPath);
        const hash = calculateSha256(fullPath);
        const relativePath = path.relative(rootDir, fullPath) || entry.name;
        const isTmp = entry.name.toLowerCase().endsWith('.tmp');

        fileList.push({
          name: entry.name,
          fullPath: fullPath,
          relativePath: relativePath,
          size: stats.size,
          hash: hash,
          isTmp: isTmp
        });
      }
    } catch (err) {
      console.warn(`[PERINGATAN] Gagal memproses file ${fullPath}: ${err.message}`);
    }
  }

  return fileList;
}

/**
 * Menentukan file mana yang menjadi "asli" (original) dan mana yang "salinan" (duplicate).
 * Pola penamaan salinan: " - Copy", " - Salinan", "(1)", "_BACKUP", "_copy", "_v2", dll.
 */
function prioritizeOriginalFile(fileList) {
  return [...fileList].sort((a, b) => {
    const copyPattern = /copy|salinan|backup|edit|\(\d+\)|_v\d+/i;
    const aIsCopy = copyPattern.test(a.name);
    const bIsCopy = copyPattern.test(b.name);

    if (aIsCopy !== bIsCopy) {
      return aIsCopy ? 1 : -1; // Yang bukan salinan diprioritaskan sebagai file asli
    }

    // Jika setara, pilih nama file yang lebih pendek atau secara abjad
    if (a.name.length !== b.name.length) {
      return a.name.length - b.name.length;
    }
    return a.name.localeCompare(b.name);
  });
}

/**
 * STG-02: Duplicate Detection
 * Mengelompokkan file berdasarkan hash SHA-256 yang identik.
 */
function detectDuplicates(files) {
  const hashGroups = {};

  for (const file of files) {
    if (!hashGroups[file.hash]) {
      hashGroups[file.hash] = [];
    }
    hashGroups[file.hash].push(file);
  }

  const duplicateGroups = [];

  for (const [hash, groupFiles] of Object.entries(hashGroups)) {
    if (groupFiles.length > 1) {
      const sorted = prioritizeOriginalFile(groupFiles);
      const original = sorted[0];
      const duplicates = sorted.slice(1);
      const fileSize = original.size;
      const wastedBytes = fileSize * duplicates.length;

      duplicateGroups.push({
        hash: hash,
        original: original,
        duplicates: duplicates,
        allFiles: sorted,
        fileSize: fileSize,
        wastedBytes: wastedBytes
      });
    }
  }

  // Urutkan grup duplikat berdasarkan potensi penghematan ruang (terbesar ke terkecil)
  duplicateGroups.sort((a, b) => b.wastedBytes - a.wastedBytes);

  return duplicateGroups;
}

/**
 * STG-03: Giant File Flagging
 * Menandai file yang ukurannya >= 2 MB (2.048 KB).
 */
function findGiantFiles(files) {
  const giantFiles = files.filter(f => f.size >= GIANT_FILE_THRESHOLD_BYTES);
  // Urutkan dari ukuran terbesar ke terkecil
  giantFiles.sort((a, b) => b.size - a.size);
  return giantFiles;
}

/**
 * STG-04: Terminal Report
 * Menampilkan laporan hasil audit secara terstruktur dan informatif di terminal.
 */
function printAuditReport(targetDir, files, giantFiles, duplicateGroups, tmpFiles) {
  const totalSizeBytes = files.reduce((acc, f) => acc + f.size, 0);
  const totalDupeCopies = duplicateGroups.reduce((acc, g) => acc + g.duplicates.length, 0);
  const totalDupeWastedBytes = duplicateGroups.reduce((acc, g) => acc + g.wastedBytes, 0);
  const totalTmpBytes = tmpFiles.reduce((acc, f) => acc + f.size, 0);
  const totalPotentialSavings = totalDupeWastedBytes + totalTmpBytes;
  const savingsPercent = totalSizeBytes > 0 ? ((totalPotentialSavings / totalSizeBytes) * 100).toFixed(1) : 0;

  console.log('\n' + '='.repeat(80));
  console.log('              LAPORAN SISTEM AUDIT PENYIMPANAN (STORAGE AUDIT)');
  console.log('='.repeat(80));
  console.log(` Direktori Target : ${targetDir}`);
  console.log(` Waktu Audit      : ${new Date().toLocaleString('id-ID')}`);
  console.log('='.repeat(80));

  // 1. RINGKASAN PEMINDAIAN (STG-01)
  console.log('\n[1] RINGKASAN PEMINDAIAN FOLDER (STG-01)');
  console.log('--------------------------------------------------------------------------------');
  console.log(` Total File Terpindai   : ${files.length} file`);
  console.log(` Total Ukuran Direktori : ${formatBytes(totalSizeBytes)} (${totalSizeBytes.toLocaleString('id-ID')} bytes)`);
  console.log(` File Raksasa (>= 2 MB) : ${giantFiles.length} file`);
  console.log(` Kelompok Duplikat      : ${duplicateGroups.length} kelompok (${totalDupeCopies} file salinan berlebih)`);
  if (tmpFiles.length > 0) {
    console.log(` File Sampah (.tmp)     : ${tmpFiles.length} file (${formatBytes(totalTmpBytes)})`);
  }

  // 2. FILE RAKSASA (STG-03)
  console.log('\n[2] DAFTAR FILE RAKSASA / GIANT FILES >= 2 MB (STG-03)');
  console.log('--------------------------------------------------------------------------------');
  if (giantFiles.length === 0) {
    console.log(' (Tidak ada file yang melebihi ambang batas 2 MB)');
  } else {
    console.log(` Menemukan ${giantFiles.length} file raksasa (Ambang Batas: 2 MB / 2.048 KB):`);
    giantFiles.forEach((file, index) => {
      const num = String(index + 1).padStart(2, ' ');
      console.log(`  ${num}. [${formatDualSize(file.size).padEnd(26)}] ${file.relativePath}`);
    });
  }

  // 3. KELOMPOK DUPLIKAT (STG-02)
  console.log('\n[3] DAFTAR KELOMPOK FILE DUPLIKAT (STG-02)');
  console.log('--------------------------------------------------------------------------------');
  if (duplicateGroups.length === 0) {
    console.log(' (Tidak ditemukan file duplikat)');
  } else {
    console.log(` Menemukan ${duplicateGroups.length} kelompok duplikat identik (SHA-256):`);
    duplicateGroups.forEach((grp, index) => {
      const shortHash = grp.hash.substring(0, 16);
      console.log(`\n  Grup #${index + 1} [SHA-256: ${shortHash}...] | Ukuran: ${formatBytes(grp.fileSize)} per file | Terbuang: ${formatBytes(grp.wastedBytes)}`);
      console.log(`    [ASLI DIPERTAHANKAN] -> ${grp.original.relativePath}`);
      grp.duplicates.forEach(dup => {
        console.log(`    [SALINAN DUPLIKAT]   -> ${dup.relativePath}`);
      });
    });
  }

  // 4. DAFTAR FILE SAMPAH .TMP (JIKA ADA)
  if (tmpFiles.length > 0) {
    console.log('\n[4] DAFTAR FILE SAMPAH TEMPORER (.tmp)');
    console.log('--------------------------------------------------------------------------------');
    tmpFiles.forEach((f, i) => {
      console.log(`  ${i + 1}. [${formatBytes(f.size)}] ${f.relativePath}`);
    });
  }

  // 5. ESTIMASI PENGHEMATAN RUANG (STG-04)
  console.log('\n' + '='.repeat(80));
  console.log('                  ESTIMASI PENGHEMATAN RUANG PENYIMPANAN');
  console.log('='.repeat(80));
  console.log(` Jumlah Salinan Duplikat Siap Hapus : ${totalDupeCopies} file`);
  if (tmpFiles.length > 0) {
    console.log(` Jumlah File Sampah (.tmp)          : ${tmpFiles.length} file`);
  }
  console.log(` Potensi Ruang Bebas (Hemat Ruang)  : ${formatDualSize(totalPotentialSavings)}`);
  console.log(` Efisiensi Pembersihan Ruang        : ${savingsPercent}% dari total penyimpanan`);
  console.log('='.repeat(80) + '\n');
}

/**
 * Prompt interaktif untuk konfirmasi pengguna via readline
 */
function askConfirmation(question) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise(resolve => {
    rl.question(question, answer => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

/**
 * STG-05: Safe Cleanup Confirmation & Execution
 * Melakukan pembersihan aman hanya jika disetujui (Y/y).
 */
async function handleSafeCleanup(duplicateGroups, tmpFiles) {
  const totalDupeCopies = duplicateGroups.reduce((acc, g) => acc + g.duplicates.length, 0);
  const totalCandidates = totalDupeCopies + tmpFiles.length;

  if (totalCandidates === 0) {
    console.log('[INFO] Kondisi folder sudah bersih dan optimal. Tidak ada file yang perlu dihapus.');
    return;
  }

  const promptMessage = 'Apakah kamu ingin menghapus file duplikat yang tidak terpakai? (Y/N): ';
  const answer = await askConfirmation(promptMessage);

  if (answer.toUpperCase() === 'Y' || answer.toUpperCase() === 'YA') {
    console.log('\n[MEMULAI PEMBERSIHAN AMAN...]');
    let deletedCount = 0;
    let freedBytes = 0;

    // Hapus salinan duplikat (pertahankan 1 file asli per grup)
    for (const grp of duplicateGroups) {
      for (const dup of grp.duplicates) {
        try {
          if (fs.existsSync(dup.fullPath)) {
            fs.unlinkSync(dup.fullPath);
            deletedCount++;
            freedBytes += dup.size;
            console.log(` [DIHAPUS] Salinan: ${dup.relativePath} (${formatBytes(dup.size)})`);
          }
        } catch (err) {
          console.error(` [GAGAL] Tidak dapat menghapus ${dup.relativePath}: ${err.message}`);
        }
      }
    }

    // Hapus file sampah .tmp
    for (const tmp of tmpFiles) {
      try {
        if (fs.existsSync(tmp.fullPath)) {
          fs.unlinkSync(tmp.fullPath);
          deletedCount++;
          freedBytes += tmp.size;
          console.log(` [DIHAPUS] File sampah: ${tmp.relativePath} (${formatBytes(tmp.size)})`);
        }
      } catch (err) {
        console.error(` [GAGAL] Tidak dapat menghapus ${tmp.relativePath}: ${err.message}`);
      }
    }

    console.log('\n' + '-'.repeat(80));
    console.log(` [SUKSES] Pembersihan berhasil diselesaikan!`);
    console.log(` - File Dihapus      : ${deletedCount} file`);
    console.log(` - Ruang Dibebaskan  : ${formatDualSize(freedBytes)}`);
    console.log('-'.repeat(80));
  } else {
    console.log('\n[BATAL AMAN] Pembersihan dibatalkan oleh pengguna (N). Tidak ada file yang dihapus.');
  }
}

/**
 * Menentukan direktori target audit berdasarkan argumen atau default
 */
function resolveTargetDirectory() {
  const argDir = process.argv[2];

  if (argDir) {
    const resolvedPath = path.resolve(process.cwd(), argDir);
    if (fs.existsSync(resolvedPath)) {
      return resolvedPath;
    }

    // Jika argumen adalah nama latihan "Bahan Latihan P12" tetapi berada di cwd langsung
    const lower = argDir.toLowerCase();
    if (lower.includes('bahan') || lower.includes('p12') || lower.includes('latihan')) {
      return process.cwd();
    }

    console.error(`[ERROR] Folder target "${argDir}" tidak ditemukan!`);
    process.exit(1);
  }

  // Cek apakah ada subfolder "Bahan Latihan P12" di folder saat ini atau parent
  const candidate1 = path.resolve(process.cwd(), 'Bahan Latihan P12');
  const candidate2 = path.resolve(process.cwd(), '..', 'Bahan Latihan P12');

  if (fs.existsSync(candidate1) && fs.statSync(candidate1).isDirectory()) {
    return candidate1;
  }
  if (fs.existsSync(candidate2) && fs.statSync(candidate2).isDirectory()) {
    return candidate2;
  }

  // Default ke direktori saat ini
  return process.cwd();
}

/**
 * Fungsi Utama Eksekusi
 */
async function main() {
  const targetDir = resolveTargetDirectory();

  console.log(`\nMemulai pemindaian penyimpanan pada: ${targetDir}...`);

  // STG-01: Pemindaian Rekursif
  const scannedFiles = scanDirectoryRecursive(targetDir, targetDir);

  if (scannedFiles.length === 0) {
    console.log(`[INFO] Tidak ditemukan file di direktori: ${targetDir}`);
    return;
  }

  // STG-02: Deteksi Duplikat
  const duplicateGroups = detectDuplicates(scannedFiles);

  // STG-03: Penandaan File Raksasa (>= 2 MB)
  const giantFiles = findGiantFiles(scannedFiles);

  // File sampah temporer (.tmp)
  const tmpFiles = scannedFiles.filter(f => f.isTmp);

  // STG-04: Laporan Terminal
  printAuditReport(targetDir, scannedFiles, giantFiles, duplicateGroups, tmpFiles);

  // STG-05: Konfirmasi Pembersihan Aman
  await handleSafeCleanup(duplicateGroups, tmpFiles);
}

// Jalankan program utama
main().catch(err => {
  console.error('[FATAL ERROR]:', err);
  process.exit(1);
});
