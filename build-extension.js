import fs from "fs";
import path from "path";
import { ZipArchive } from "archiver";

const zipPath = path.join("public", "veritasai-extension.zip");
const output = fs.createWriteStream(zipPath);
const archive = new ZipArchive({
  zlib: { level: 9 }, // Maximum compression
});

output.on("close", function () {
  console.log(`Successfully packed ${archive.pointer()} bytes into public/veritasai-extension.zip`);
  try {
    // Copy to alternative locations to keep everything perfectly in sync
    fs.copyFileSync(zipPath, path.join("public", "veritas-shield-extension.zip"));
    fs.copyFileSync(zipPath, "veritas-shield-extension.zip");
    console.log("Successfully synchronized backup extension zip files.");
  } catch (e) {
    console.error("Failed to copy backup zip files:", e);
  }
});

archive.on("warning", function (err) {
  if (err.code === "ENOENT") {
    console.warn(err);
  } else {
    throw err;
  }
});

archive.on("error", function (err) {
  throw err;
});

archive.pipe(output);

// Add everything from extension/ into the root of the zip archive
archive.directory("extension/", false);

archive.finalize();
