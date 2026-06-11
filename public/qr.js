// Minimal QR encoder — byte mode, error-correction level L, versions 1–15.
// Zero dependencies, ~300 lines, written for this project so the app keeps
// its no-runtime-deps guarantee. Output is an SVG string (crisp at any size,
// same pattern as the inline-SVG identicons in app.js).
//
// Spec: ISO/IEC 18004. Algorithm structure follows the public-domain
// reference encoder by Project Nayuki (https://www.nayuki.io/page/qr-code-generator-library),
// reduced to the subset this app needs. Level L suffices: a QR is shown on a
// lit screen and scanned at close range, so we trade redundancy for a less
// dense, easier-to-scan code.
//
// Public API:
//   encodeToMatrix(text) -> boolean[size][size]  (true = dark module)
//   encodeToSvg(text, { modulePx = 4, quietZone = 4, dark = '#000', light = '#fff' }) -> SVG string

// ─── GF(256) arithmetic, reducing polynomial 0x11D ───────────────────────────

function gfMul(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11D);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xFF;
}

// Reed-Solomon generator polynomial coefficients for `degree` ECC codewords
// (highest-order term first, leading 1 omitted).
function rsDivisor(degree) {
  const result = new Array(degree).fill(0);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < result.length; j++) {
      result[j] = gfMul(result[j], root);
      if (j + 1 < result.length) result[j] ^= result[j + 1];
    }
    root = gfMul(root, 0x02);
  }
  return result;
}

function rsRemainder(data, divisor) {
  const result = new Array(divisor.length).fill(0);
  for (const b of data) {
    const factor = b ^ result.shift();
    result.push(0);
    for (let j = 0; j < result.length; j++) {
      result[j] ^= gfMul(divisor[j], factor);
    }
  }
  return result;
}

// ─── Version tables (ECC level L only) ────────────────────────────────────────

const MAX_VERSION = 15;
// Per version 1..15 at level L:
const ECC_PER_BLOCK   = [7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22];
const NUM_ECC_BLOCKS  = [1,  1,  1,  1,  1,  2,  2,  2,  2,  4,  4,  4,  4,  4,  6];

function totalRawBits(ver) {
  let result = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const numAlign = Math.floor(ver / 7) + 2;
    result -= (25 * numAlign - 10) * numAlign - 55;
    if (ver >= 7) result -= 36;
  }
  return result;
}

function totalCodewords(ver) { return Math.floor(totalRawBits(ver) / 8); }

function dataCodewords(ver) {
  return totalCodewords(ver) - ECC_PER_BLOCK[ver - 1] * NUM_ECC_BLOCKS[ver - 1];
}

// ─── Bit assembly ─────────────────────────────────────────────────────────────

function buildCodewords(bytes, ver) {
  const capacityBits = dataCodewords(ver) * 8;
  const countBits = ver <= 9 ? 8 : 16;
  const bits = [];
  const push = (val, n) => { for (let i = n - 1; i >= 0; i--) bits.push((val >>> i) & 1); };

  push(0b0100, 4);                 // byte-mode indicator
  push(bytes.length, countBits);
  for (const b of bytes) push(b, 8);

  // Terminator (up to 4 zero bits), then pad to a byte boundary, then
  // alternate pad codewords 0xEC / 0x11 per spec.
  push(0, Math.min(4, capacityBits - bits.length));
  if (bits.length % 8 !== 0) push(0, 8 - (bits.length % 8));
  for (let pad = 0xEC; bits.length < capacityBits; pad ^= 0xEC ^ 0x11) push(pad, 8);

  const codewords = [];
  for (let i = 0; i < bits.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
    codewords.push(b);
  }
  return codewords;
}

// Split data codewords into RS blocks, append ECC, interleave.
function addEccAndInterleave(data, ver) {
  const numBlocks = NUM_ECC_BLOCKS[ver - 1];
  const eccLen = ECC_PER_BLOCK[ver - 1];
  const rawCodewords = totalCodewords(ver);
  const numShortBlocks = numBlocks - (rawCodewords % numBlocks);
  const shortBlockLen = Math.floor(rawCodewords / numBlocks);

  const blocks = [];
  const divisor = rsDivisor(eccLen);
  for (let i = 0, k = 0; i < numBlocks; i++) {
    const datLen = shortBlockLen - eccLen + (i < numShortBlocks ? 0 : 1);
    const dat = data.slice(k, k + datLen);
    k += datLen;
    const block = dat.concat(rsRemainder(dat, divisor));
    if (i < numShortBlocks) block.splice(datLen, 0, -1); // placeholder for missing byte
    blocks.push(block);
  }

  const result = [];
  for (let i = 0; i < blocks[0].length; i++) {
    for (const block of blocks) {
      if (block[i] !== -1) result.push(block[i]);
    }
  }
  return result;
}

// ─── Matrix construction ──────────────────────────────────────────────────────

function alignmentPositions(ver) {
  if (ver === 1) return [];
  const numAlign = Math.floor(ver / 7) + 2;
  const size = ver * 4 + 17;
  const step = Math.floor((ver * 4 + numAlign * 2 + 1) / (numAlign * 2 - 2)) * 2;
  const result = [6];
  for (let i = numAlign - 1, pos = size - 7; i >= 1; i--, pos -= step) result.splice(1, 0, pos);
  return result;
}

function buildMatrix(codewords, ver) {
  const size = ver * 4 + 17;
  const modules = Array.from({ length: size }, () => new Array(size).fill(false));
  const isFunction = Array.from({ length: size }, () => new Array(size).fill(false));
  const setF = (col, row, dark) => {
    modules[row][col] = dark;
    isFunction[row][col] = true;
  };

  // Timing patterns
  for (let i = 0; i < size; i++) {
    setF(6, i, i % 2 === 0);
    setF(i, 6, i % 2 === 0);
  }

  // Finder patterns + separators (top-left, top-right, bottom-left)
  const drawFinder = (cx, cy) => {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx, y = cy + dy;
        if (x < 0 || x >= size || y < 0 || y >= size) continue;
        const dist = Math.max(Math.abs(dx), Math.abs(dy));
        setF(x, y, dist !== 2 && dist !== 4);
      }
    }
  };
  drawFinder(3, 3);
  drawFinder(size - 4, 3);
  drawFinder(3, size - 4);

  // Alignment patterns (skip the three corners that collide with finders)
  const align = alignmentPositions(ver);
  for (let i = 0; i < align.length; i++) {
    for (let j = 0; j < align.length; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === align.length - 1) || (i === align.length - 1 && j === 0)) continue;
      const cx = align[i], cy = align[j];
      for (let dy = -2; dy <= 2; dy++) {
        for (let dx = -2; dx <= 2; dx++) {
          setF(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
        }
      }
    }
  }

  // Reserve format-info modules (filled per-mask later) + dark module
  for (let i = 0; i <= 5; i++) setF(8, i, false);
  setF(8, 7, false); setF(8, 8, false); setF(7, 8, false);
  for (let i = 9; i < 15; i++) setF(14 - i, 8, false);
  for (let i = 0; i < 8; i++) setF(size - 1 - i, 8, false);
  for (let i = 8; i < 15; i++) setF(8, size - 15 + i, false);
  setF(8, size - 8, true); // dark module

  // Version info (versions 7+)
  if (ver >= 7) {
    let rem = ver;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1F25);
    const bits = (ver << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const bit = ((bits >>> i) & 1) === 1;
      const a = size - 11 + (i % 3), b = Math.floor(i / 3);
      setF(a, b, bit);
      setF(b, a, bit);
    }
  }

  // Zigzag data placement
  let bitIndex = 0;
  const totalBits = codewords.length * 8;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? size - 1 - vert : vert;
        if (!isFunction[y][x] && bitIndex < totalBits) {
          modules[y][x] = ((codewords[bitIndex >>> 3] >>> (7 - (bitIndex & 7))) & 1) === 1;
          bitIndex++;
        }
        // Remaining "remainder bits" stay light (false) per spec.
      }
    }
  }

  return { modules, isFunction, size };
}

// ─── Masking ──────────────────────────────────────────────────────────────────

const MASKS = [
  (x, y) => (x + y) % 2 === 0,
  (x, y) => y % 2 === 0,
  (x, y) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
  (x, y) => (x * y) % 2 + (x * y) % 3 === 0,
  (x, y) => ((x * y) % 2 + (x * y) % 3) % 2 === 0,
  (x, y) => ((x + y) % 2 + (x * y) % 3) % 2 === 0,
];

function applyMask(modules, isFunction, size, mask) {
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      if (!isFunction[y][x] && MASKS[mask](x, y)) modules[y][x] = !modules[y][x];
    }
  }
}

function drawFormatBits(modules, size, mask) {
  // Level L indicator = 0b01; BCH(15,5) over generator 0x537, XOR mask 0x5412.
  const data = (0b01 << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const bits = ((data << 10) | rem) ^ 0x5412;
  const getBit = i => ((bits >>> i) & 1) === 1;

  for (let i = 0; i <= 5; i++) modules[i][8] = getBit(i);
  modules[7][8] = getBit(6);
  modules[8][8] = getBit(7);
  modules[8][7] = getBit(8);
  for (let i = 9; i < 15; i++) modules[8][14 - i] = getBit(i);
  for (let i = 0; i < 8; i++) modules[8][size - 1 - i] = getBit(i);
  for (let i = 8; i < 15; i++) modules[size - 15 + i][8] = getBit(i);
  modules[size - 8][8] = true; // dark module, always
}

// Penalty score per ISO 18004 §8.8.2 (N1=3, N2=3, N3=40, N4=10).
function penaltyScore(modules, size) {
  let result = 0;

  // N1 + N3 via direct scanning of rows and columns
  const scanLine = line => {
    let score = 0;
    // N1: runs of same color length >= 5
    let runColor = line[0], runLen = 1;
    for (let i = 1; i <= line.length; i++) {
      if (i < line.length && line[i] === runColor) { runLen++; continue; }
      if (runLen >= 5) score += 3 + (runLen - 5);
      if (i < line.length) { runColor = line[i]; runLen = 1; }
    }
    // N3: 1011101 pattern with 0000 before or after
    const P = [true, false, true, true, true, false, true];
    for (let i = 0; i + 7 <= line.length; i++) {
      let match = true;
      for (let j = 0; j < 7; j++) if (line[i + j] !== P[j]) { match = false; break; }
      if (!match) continue;
      const lightBefore = i >= 4 && line.slice(i - 4, i).every(m => !m);
      const lightAfter = i + 11 <= line.length && line.slice(i + 7, i + 11).every(m => !m);
      if (lightBefore || lightAfter) score += 40;
    }
    return score;
  };

  for (let y = 0; y < size; y++) result += scanLine(modules[y]);
  for (let x = 0; x < size; x++) result += scanLine(modules.map(row => row[x]));

  // N2: 2x2 blocks of same color
  for (let y = 0; y < size - 1; y++) {
    for (let x = 0; x < size - 1; x++) {
      const c = modules[y][x];
      if (c === modules[y][x + 1] && c === modules[y + 1][x] && c === modules[y + 1][x + 1]) result += 3;
    }
  }

  // N4: deviation of dark-module proportion from 50%, in 5% steps
  let dark = 0;
  for (const row of modules) for (const m of row) if (m) dark++;
  const percent = (dark * 100) / (size * size);
  result += Math.floor(Math.abs(percent - 50) / 5) * 10;

  return result;
}

// ─── Public API ───────────────────────────────────────────────────────────────

export function encodeToMatrix(text) {
  const bytes = Array.from(new TextEncoder().encode(text));

  let ver = null;
  for (let v = 1; v <= MAX_VERSION; v++) {
    const countBits = v <= 9 ? 8 : 16;
    if (4 + countBits + bytes.length * 8 <= dataCodewords(v) * 8) { ver = v; break; }
  }
  if (ver === null) throw new Error(`Data too long for QR version ${MAX_VERSION}-L (${bytes.length} bytes)`);

  const codewords = addEccAndInterleave(buildCodewords(bytes, ver), ver);
  const { modules, isFunction, size } = buildMatrix(codewords, ver);

  // Try all 8 masks, keep the lowest penalty.
  let bestMask = 0, bestScore = Infinity, bestModules = null;
  for (let mask = 0; mask < 8; mask++) {
    const trial = modules.map(row => row.slice());
    applyMask(trial, isFunction, size, mask);
    drawFormatBits(trial, size, mask);
    const score = penaltyScore(trial, size);
    if (score < bestScore) { bestScore = score; bestMask = mask; bestModules = trial; }
  }

  return bestModules;
}

export function encodeToSvg(text, opts = {}) {
  const { modulePx = 4, quietZone = 4, dark = '#000000', light = '#ffffff' } = opts;
  const m = encodeToMatrix(text);
  const size = m.length;
  const total = (size + quietZone * 2) * modulePx;

  // One path element for all dark modules keeps the SVG small.
  let d = '';
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      if (m[y][x]) d += `M${(x + quietZone) * modulePx} ${(y + quietZone) * modulePx}h${modulePx}v${modulePx}h-${modulePx}z`;
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${total} ${total}" shape-rendering="crispEdges">` +
    `<rect width="${total}" height="${total}" fill="${light}"/>` +
    `<path d="${d}" fill="${dark}"/></svg>`;
}
