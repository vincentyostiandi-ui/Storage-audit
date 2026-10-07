#!/usr/bin/env node

/**
 * =============================================================================
 * STORAGE AUDIT CLI UTILITY (storage_audit.js)
 * =============================================================================
 * Utilitas command-line audit penyimpanan tanpa dependensi pihak ketiga (Zero-Dependency)
 * Menggunakan modul native Node.js: 'fs', 'path', 'crypto', dan 'readline'.
 * 
 * Spesifikasi Kebutuhan:
 * - STG-01: Recursive Scan (SHA-256 hashing, metadata file & path)
 * - STG-02: Duplicate Detection (Pengelompokan hash SHA-256 identik)
 * - STG-03: Giant File Flagging (Ambang batas >= 2 MB / 2.048 KB)
 * - STG-04: Terminal Report (Ringkasan statistik & laporan visual terstruktur)
 * - STG-05: Safe Cleanup Confirmation (Konfirmasi interaktif Y/N, pertahankan 1 asli)
 * - STG-06: Zero-Dependency Portability (Hanya modul bawaan Node.js)
 * =============================================================================
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

// Konfigurasi & Ambang Batas
const GIANT_FILE_THRESHOLD_BYTES = 2 * 1024 * 1024; // 2 MB = 2.048 KB = 2.097.152 bytes

/**
 * Format bytes ke representasi yang mudah dibaca manusia (B, KB, MB, GB)
 */
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Format ukuran khusus MB dan KB
 */
function formatMB_KB(bytes) {
  const mb = (bytes / (1024 * 1024)).toFixed(2);
  const kb = (bytes / 1024).toFixed(2);
  return `${mb} MB (${kb} KB)`;
}

/**
 * Menghitung hash SHA-256 dari sebuah file menggunakan stream
 */
function calculateFileSHA256(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', err => reject(err));
  });
}

/**
 * STG-01: Recursive Scan
 * Memindai direktori target dan semua subdirektorinya secara rekursif
 */
async function scanDirectoryRecursive(dirPath, fileList = []) {
  let entries;
  try {
    entries = fs.readdirSync(dirPath, { withFileTypes: true });
  } catch (err) {
    console.error(`[PERINGATAN] Gagal membaca direktori: ${dirPath} (${err.message})`);
    return fileList;
  }

  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);
    try {
      if (entry.isDirectory()) {
        await scanDirectoryRecursive(fullPath, fileList);
      } else if (entry.isFile()) {
        // Jangan scan skrip audit itu sendiri jika berada di direktori yang sama
        if (entry.name === 'storage_audit.js' || entry.name === 'storage_audit.py') {
          continue;
        }

        const stats = fs.statSync(fullPath);
        const hash = await calculateFileSHA256(fullPath);
        
        fileList.push({
          name: entry.name,
          fullPath: fullPath,
          sizeBytes: stats.size,
          hash: hash,
          isGiant: stats.size >= GIANT_FILE_THRESHOLD_BYTES,
          isTmp: entry.name.toLowerCase().endsWith('.tmp') || entry.name.startsWith('~')
        });
      }
    } catch (err) {
      console.error(`[PERINGATAN] Gagal memproses file: ${fullPath} (${err.message})`);
    }
  }

  return fileList;
}

/**
 * Mengurutkan file dalam grup duplikat untuk menentukan file mana yang merupakan 'asli'
 * Heuristik:
 * 1. File tanpa kata "copy", "salinan", "backup", "(1)", "(2)", dsb diprioritaskan sebagai file asli
 * 2. Panjang path lebih pendek diprioritaskan
 */
function sortDuplicatesOriginalFirst(files) {
  const copyPattern = /copy|salinan|backup|\(\d+\)|_v\d+|_edit|_final|fix/i;
  return [...files].sort((a, b) => {
    const aIsCopy = copyPattern.test(a.name);
    const bIsCopy = copyPattern.test(b.name);
    if (aIsCopy !== bIsCopy) {
      return aIsCopy ? 1 : -1; // Non-copy duluan
    }
    return a.fullPath.length - b.fullPath.length; // Terpendek duluan
  });
}

/**
 * STG-02: Duplicate Detection
 * Mengelompokkan file berdasarkan hash SHA-256
 */
function detectDuplicates(files) {
  const groupsByHash = new Map();

  for (const file of files) {
    if (!groupsByHash.has(file.hash)) {
      groupsByHash.set(file.hash, []);
    }
    groupsByHash.get(file.hash).push(file);
  }

  const duplicateGroups = [];
  for (const [hash, groupFiles] of groupsByHash.entries()) {
    if (groupFiles.length > 1) {
      const sorted = sortDuplicatesOriginalFirst(groupFiles);
      duplicateGroups.push({
        hash: hash,
        original: sorted[0],
        duplicates: sorted.slice(1),
        allFiles: sorted,
        sizePerFile: sorted[0].sizeBytes,
        wastedBytes: (sorted.length - 1) * sorted[0].sizeBytes
      });
    }
  }

  return duplicateGroups;
}

/**
 * STG-04: Terminal Report
 * Menampilkan laporan rapi dan informatif di terminal
 */
function printTerminalReport(targetDir, files, duplicateGroups, giantFiles, tmpFiles) {
  const totalSizeBytes = files.reduce((acc, f) => acc + f.sizeBytes, 0);
  const totalDuplicateCopies = duplicateGroups.reduce((acc, g) => acc + g.duplicates.length, 0);
  const totalDuplicateWastedBytes = duplicateGroups.reduce((acc, g) => acc + g.wastedBytes, 0);
  const totalTmpBytes = tmpFiles.reduce((acc, f) => acc + f.sizeBytes, 0);
  const totalSavingsBytes = totalDuplicateWastedBytes + totalTmpBytes;

  console.log('\n' + '='.repeat(80));
  console.log('              LAPORAN AUDIT SISTEM PENYIMPANAN (STORAGE AUDIT)');
  console.log('='.repeat(80));
  console.log(`Folder Target : ${targetDir}`);
  console.log(`Waktu Audit   : ${new Date().toLocaleString('id-ID')}`);
  console.log(`Status        : Selesai (Pemindaian Rekursif Mendalam)`);
  console.log('-'.repeat(80));

  console.log('\n[1] RINGKASAN AUDIT (SUMMARY STATISTICS)');
  console.log(`- Total File Terpindai           : ${files.length} file`);
  console.log(`- Total Ukuran Penyimpanan       : ${formatBytes(totalSizeBytes)} (${totalSizeBytes.toLocaleString('id-ID')} bytes)`);
  console.log(`- File Raksasa (>= 2 MB / 2048KB): ${giantFiles.length} file`);
  console.log(`- Kelompok Duplikat Terdeteksi   : ${duplicateGroups.length} kelompok`);
  console.log(`- Total Salinan Duplikat         : ${totalDuplicateCopies} file`);
  console.log(`- File Sampah (.tmp)             : ${tmpFiles.length} file`);
  console.log(`- Estimasi Potensi Hemat Ruang   : ${formatBytes(totalSavingsBytes)} (${totalSavingsBytes.toLocaleString('id-ID')} bytes)`);

  console.log('\n' + '-'.repeat(80));
  console.log(`[2] DAFTAR FILE RAKSASA (STG-03: Giant Files >= 2.048 KB / 2 MB) - Total: ${giantFiles.length} file`);
  console.log('-'.repeat(80));
  if (giantFiles.length === 0) {
    console.log('  (Tidak ditemukan file yang melebihi ambang batas 2 MB)');
  } else {
    // Urutkan file raksasa dari yang terbesar
    const sortedGiants = [...giantFiles].sort((a, b) => b.sizeBytes - a.sizeBytes);
    sortedGiants.forEach((file, index) => {
      const relPath = path.relative(targetDir, file.fullPath);
      console.log(`  ${(index + 1).toString().padStart(2, ' ')}. ${file.name}`);
      console.log(`      Path   : ${relPath}`);
      console.log(`      Ukuran : ${formatMB_KB(file.sizeBytes)} [${file.sizeBytes.toLocaleString('id-ID')} bytes]`);
    });
  }

  console.log('\n' + '-'.repeat(80));
  console.log(`[3] DAFTAR KELOMPOK DUPLIKAT (STG-02: Identical SHA-256 Hash) - Total: ${duplicateGroups.length} kelompok`);
  console.log('-'.repeat(80));
  if (duplicateGroups.length === 0) {
    console.log('  (Tidak ditemukan file duplikat)');
  } else {
    duplicateGroups.forEach((group, index) => {
      console.log(`\n  Kelompok #${index + 1} [Ukuran per file: ${formatBytes(group.sizePerFile)}]`);
      console.log(`  SHA-256: ${group.hash}`);
      console.log(`  -> [ASLI / DIPERTAHANKAN] : ${path.relative(targetDir, group.original.fullPath)}`);
      group.duplicates.forEach(dup => {
        console.log(`  -> [SALINAN / KANDIDAT HAPUS] : ${path.relative(targetDir, dup.fullPath)}`);
      });
      console.log(`     Potensi hemat kelompok ini: ${formatBytes(group.wastedBytes)}`);
    });
  }

  if (tmpFiles.length > 0) {
    console.log('\n' + '-'.repeat(80));
    console.log(`[4] DAFTAR FILE SAMPAH (.tmp) - Total: ${tmpFiles.length} file`);
    console.log('-'.repeat(80));
    tmpFiles.forEach((file, index) => {
      console.log(`  ${index + 1}. ${path.relative(targetDir, file.fullPath)} (${formatBytes(file.sizeBytes)})`);
    });
  }

  console.log('\n' + '='.repeat(80));
}

/**
 * STG-05: Safe Cleanup Confirmation
 * Menghapus file duplikat redundan dan .tmp sampah secara interaktif setelah persetujuan
 */
async function handleSafeCleanup(duplicateGroups, tmpFiles) {
  const filesToDelete = [];

  // Salinan duplikat
  for (const group of duplicateGroups) {
    for (const dup of group.duplicates) {
      filesToDelete.push({
        fullPath: dup.fullPath,
        sizeBytes: dup.sizeBytes,
        type: 'Salinan Duplikat',
        relative: dup.name
      });
    }
  }

  // File .tmp
  for (const tmp of tmpFiles) {
    // Pastikan tidak dobel jika file tmp kebetulan juga dideteksi duplikat
    if (!filesToDelete.some(f => f.fullPath === tmp.fullPath)) {
      filesToDelete.push({
        fullPath: tmp.fullPath,
        sizeBytes: tmp.sizeBytes,
        type: 'File Sampah (.tmp)',
        relative: tmp.name
      });
    }
  }

  if (filesToDelete.length === 0) {
    console.log('\nTidak ada file duplikat atau file sampah yang perlu dibersihkan.');
    return;
  }

  const totalFreedEstimated = filesToDelete.reduce((acc, f) => acc + f.sizeBytes, 0);

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise(resolve => {
    console.log('\n[STG-05: KONFIRMASI PEMBERSIHAN AMAN]');
    console.log(`Total kandidat yang akan dihapus: ${filesToDelete.length} file (${formatBytes(totalFreedEstimated)})`);
    console.log(`Catatan: 1 file asli per kelompok duplikat akan SELALU DIPERTAHANKAN dengan aman.`);
    
    rl.question('Apakah kamu ingin menghapus file duplikat yang tidak terpakai? (Y/N): ', answer => {
      rl.close();
      const trimmed = answer.trim().toUpperCase();

      if (trimmed === 'Y') {
        console.log('\nMemulai pembersihan aman...');
        let deletedCount = 0;
        let freedBytes = 0;
        let errorCount = 0;

        for (const item of filesToDelete) {
          try {
            if (fs.existsSync(item.fullPath)) {
              fs.unlinkSync(item.fullPath);
              deletedCount++;
              freedBytes += item.sizeBytes;
              console.log(`  [BERHASIL DIHAPUS] [${item.type}] ${path.basename(item.fullPath)}`);
            }
          } catch (err) {
            errorCount++;
            console.error(`  [GAGAL MENGHAPUS] ${item.fullPath}: ${err.message}`);
          }
        }

        console.log('\n' + '='.repeat(80));
        console.log('                 HASIL PEMBERSIHAN PENYIMPANAN');
        console.log('='.repeat(80));
        console.log(`- File Berhasil Dihapus : ${deletedCount} file`);
        console.log(`- File Gagal Dihapus    : ${errorCount} file`);
        console.log(`- Ruang Berhasil Hemat  : ${formatBytes(freedBytes)} (${freedBytes.toLocaleString('id-ID')} bytes)`);
        console.log('Pembersihan selesai dengan aman.');
        console.log('='.repeat(80) + '\n');
      } else {
        console.log('\n[BATAL] Tindakan pembersihan dibatalkan oleh pengguna.');
        console.log('Tidak ada file yang diubah atau dihapus. Sistem tetap aman.\n');
      }
      resolve();
    });
  });
}

/**
 * Resolusi lokasi folder target
 */
function resolveTargetDirectory() {
  const cliArg = process.argv[2];

  // 1. Jika pengguna memberikan argumen direktori di terminal
  if (cliArg) {
    const resolvedArg = path.resolve(cliArg);
    if (fs.existsSync(resolvedArg) && fs.statSync(resolvedArg).isDirectory()) {
      return resolvedArg;
    }
  }

  // 2. Cek apakah subfolder "Bahan Latihan P12" ada di folder kerja saat ini
  const localBahanP12 = path.resolve('Bahan Latihan P12');
  if (fs.existsSync(localBahanP12) && fs.statSync(localBahanP12).isDirectory()) {
    return localBahanP12;
  }

  // 3. Cek apakah folder "Bahan Latihan P12" ada di parent direktori (..)
  const parentBahanP12 = path.resolve('..', 'Bahan Latihan P12');
  if (fs.existsSync(parentBahanP12) && fs.statSync(parentBahanP12).isDirectory()) {
    return parentBahanP12;
  }

  // 4. Default: gunakan direktori kerja saat ini (CWD)
  return process.cwd();
}

/**
 * Fungsi Utama Program (Entry Point)
 */
async function main() {
  console.log('\n================================================================================');
  console.log('                    STORAGE AUDIT UTILITY v1.0 (Node.js)');
  console.log('================================================================================');

  const targetDir = resolveTargetDirectory();
  console.log(`Memindai direktori target: ${targetDir}`);
  console.log('Sedang membaca file dan menghitung hash SHA-256...\n');

  const startTime = Date.now();
  const allFiles = await scanDirectoryRecursive(targetDir);
  const durationSec = ((Date.now() - startTime) / 1000).toFixed(2);

  if (allFiles.length === 0) {
    console.log(`[INFORMASI] Tidak ditemukan file di dalam folder target: ${targetDir}`);
    return;
  }

  console.log(`Pemindaian selesai dalam ${durationSec} detik. Memproses audit data...`);

  // Identifikasi kategori file
  const duplicateGroups = detectDuplicates(allFiles);
  const giantFiles = allFiles.filter(f => f.isGiant);
  const tmpFiles = allFiles.filter(f => f.isTmp);

  // STG-04: Tampilkan Laporan di Terminal
  printTerminalReport(targetDir, allFiles, duplicateGroups, giantFiles, tmpFiles);

  // STG-05: Konfirmasi Pembersihan Interaktif
  await handleSafeCleanup(duplicateGroups, tmpFiles);
}

// Eksekusi program
main().catch(err => {
  console.error('[FATAL ERROR]:', err);
  process.exit(1);
});
