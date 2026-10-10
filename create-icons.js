const fs = require('fs');

// Minimal valid PNG generator (no dependencies)
function createPNG(size) {
  // PNG signature
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  
  // IHDR chunk
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(size, 0);  // width
  ihdrData.writeUInt32BE(size, 4);  // height
  ihdrData[8] = 8;   // bit depth
  ihdrData[9] = 2;   // color type (RGB)
  ihdrData[10] = 0;  // compression
  ihdrData[11] = 0;  // filter
  ihdrData[12] = 0;  // interlace
  
  const ihdr = createChunk('IHDR', ihdrData);
  
  // IDAT chunk - raw image data (purple gradient)
  const rawData = [];
  for (let y = 0; y < size; y++) {
    rawData.push(0); // filter byte
    for (let x = 0; x < size; x++) {
      // Purple gradient: #667eea to #764ba2
      const t = (x + y) / (size * 2);
      rawData.push(Math.round(102 + t * 16));  // R
      rawData.push(Math.round(126 - t * 51));  // G
      rawData.push(Math.round(234 - t * 72));  // B
    }
  }
  
  const zlib = require('zlib');
  const compressed = zlib.deflateSync(Buffer.from(rawData));
  const idat = createChunk('IDAT', compressed);
  
  // IEND chunk
  const iend = createChunk('IEND', Buffer.alloc(0));
  
  return Buffer.concat([signature, ihdr, idat, iend]);
}

function createChunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);
  
  const typeBuffer = Buffer.from(type, 'ascii');
  const crcData = Buffer.concat([typeBuffer, data]);
  
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(crcData) >>> 0, 0);
  
  return Buffer.concat([length, typeBuffer, data, crc]);
}

function crc32(buf) {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) {
    crc ^= buf[i];
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
    }
  }
  return crc ^ 0xFFFFFFFF;
}

// Create icons directory
if (!fs.existsSync('dist/icons')) {
  fs.mkdirSync('dist/icons', { recursive: true });
}

// Generate icons
[16, 48, 128].forEach(size => {
  const png = createPNG(size);
  fs.writeFileSync(`dist/icons/icon${size}.png`, png);
  console.log(`✓ Created icon${size}.png (${png.length} bytes)`);
});

console.log('\n✅ Icons created!');
