import fs from "fs";
import path from "path";
import { ZipArchive } from "archiver";

const output = fs.createWriteStream(path.join("public", "veritasai-extension.zip"));
const archive = new ZipArchive({
  zlib: { level: 9 }, // Maximum compression
});

output.on("close", function () {
  console.log(`Successfully packed ${archive.pointer()} bytes into public/veritasai-extension.zip`);
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
