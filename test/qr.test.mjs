// Structural verification of the QR encoder (public/qr.js).
//
// Beyond fixed vectors, the strongest in-process checks are:
//  1. function patterns (finders, timing, dark module) are exactly per spec;
//  2. unmasking + zigzag re-extraction + block de-interleaving recovers the
//     original payload bytes (validates placement, masking, format info);
//  3. every interleaved RS block is divisible by its generator polynomial
//     (validates the error-correction math).
// The rendered output is additionally verified against a real decoder
// (macOS Vision / iOS camera engine) in manual testing.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encodeToMatrix, encodeToSvg } from '../public/qr.js';

// ─── helpers mirroring the spec (independent re-implementation) ───────────────

function gfMul(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11D);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xFF;
}

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

const ECC_PER_BLOCK  = [7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22];
const NUM_ECC_BLOCKS = [1,  1,  1,  1,  1,  2,  2,  2,  2,  4,  4,  4,  4,  4,  6];

function totalRawBits(ver) {
  let result = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const numAlign = Math.floor(ver / 7) + 2;
    result -= (25 * numAlign - 10) * numAlign - 55;
    if (ver >= 7) result -= 36;
  }
  return result;
}

function alignmentPositions(ver) {
  if (ver === 1) return [];
  const numAlign = Math.floor(ver / 7) + 2;
  const size = ver * 4 + 17;
  const step = Math.floor((ver * 4 + numAlign * 2 + 1) / (numAlign * 2 - 2)) * 2;
  const result = [6];
  for (let i = numAlign - 1, pos = size - 7; i >= 1; i--, pos -= step) result.splice(1, 0, pos);
  return result;
}

// Rebuild the function-module map so we can tell data modules apart.
function functionMap(ver) {
  const size = ver * 4 + 17;
  const isF = Array.from({ length: size }, () => new Array(size).fill(false));
  for (let i = 0; i < size; i++) { isF[i][6] = true; isF[6][i] = true; }
  const finder = (cx, cy) => {
    for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
      const x = cx + dx, y = cy + dy;
      if (x >= 0 && x < size && y >= 0 && y < size) isF[y][x] = true;
    }
  };
  finder(3, 3); finder(size - 4, 3); finder(3, size - 4);
  const align = alignmentPositions(ver);
  for (let i = 0; i < align.length; i++) for (let j = 0; j < align.length; j++) {
    if ((i === 0 && j === 0) || (i === 0 && j === align.length - 1) || (i === align.length - 1 && j === 0)) continue;
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) isF[align[j] + dy][align[i] + dx] = true;
  }
  for (let i = 0; i <= 5; i++) isF[i][8] = true;
  isF[7][8] = true; isF[8][8] = true; isF[8][7] = true;
  for (let i = 9; i < 15; i++) isF[8][14 - i] = true;
  for (let i = 0; i < 8; i++) isF[8][size - 1 - i] = true;   // row 8, right edge
  for (let i = 8; i < 15; i++) isF[size - 15 + i][8] = true; // col 8, bottom edge
  isF[size - 8][8] = true;
  if (ver >= 7) {
    for (let i = 0; i < 18; i++) {
      const a = size - 11 + (i % 3), b = Math.floor(i / 3);
      isF[b][a] = true; isF[a][b] = true;
    }
  }
  return isF;
}

// Read format info from the matrix, decode mask, verify BCH.
function readFormat(m) {
  const size = m.length;
  let bits = 0;
  for (let i = 0; i <= 5; i++) bits |= (m[i][8] ? 1 : 0) << i;
  bits |= (m[7][8] ? 1 : 0) << 6;
  bits |= (m[8][8] ? 1 : 0) << 7;
  bits |= (m[8][7] ? 1 : 0) << 8;
  for (let i = 9; i < 15; i++) bits |= (m[8][14 - i] ? 1 : 0) << i;
  const unmasked = bits ^ 0x5412;
  const data = unmasked >>> 10;
  // verify BCH remainder
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  assert.equal(((data << 10) | rem), unmasked, 'format BCH must verify');
  return { ecc: data >>> 3, mask: data & 7 };
}

// Full inverse pipeline: unmask → zigzag extract → de-interleave → strip
// mode/count headers → payload bytes.
function decodePayload(matrix) {
  const size = matrix.length;
  const ver = (size - 17) / 4;
  const { ecc, mask } = readFormat(matrix);
  assert.equal(ecc, 1, 'encoder emits level L (format bits 01)');

  const isF = functionMap(ver);
  const m = matrix.map((row, y) => row.map((v, x) => (!isF[y][x] && MASKS[mask](x, y)) ? !v : v));

  // zigzag extraction
  const bits = [];
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? size - 1 - vert : vert;
        if (!isF[y][x]) bits.push(m[y][x] ? 1 : 0);
      }
    }
  }
  const totalCw = Math.floor(totalRawBits(ver) / 8);
  const cw = [];
  for (let i = 0; i + 8 <= totalCw * 8; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
    cw.push(b);
  }

  // De-interleave by inverting the encoder's exact emit order: every block is
  // padded to uniform length (shortLen + 1) with a placeholder at the short
  // blocks' data-end position, then emitted column-wise skipping placeholders.
  const numBlocks = NUM_ECC_BLOCKS[ver - 1];
  const eccLen = ECC_PER_BLOCK[ver - 1];
  const numShort = numBlocks - (totalCw % numBlocks);
  const shortLen = Math.floor(totalCw / numBlocks);
  const shortDataLen = shortLen - eccLen;
  const paddedLen = shortLen + 1;

  const blocks = Array.from({ length: numBlocks }, () => []);
  let idx = 0;
  for (let col = 0; col < paddedLen; col++) {
    for (let b = 0; b < numBlocks; b++) {
      if (b < numShort && col === shortDataLen) continue; // placeholder slot
      blocks[b].push(cw[idx++]);
    }
  }

  const dataLens = Array.from({ length: numBlocks }, (_, b) => shortDataLen + (b < numShort ? 0 : 1));
  const data = [];
  for (let b = 0; b < numBlocks; b++) data.push(...blocks[b].slice(0, dataLens[b]));

  // strip headers
  const countBits = ver <= 9 ? 8 : 16;
  let bitPos = 0;
  const readBits = n => {
    let v = 0;
    for (let i = 0; i < n; i++) {
      v = (v << 1) | ((data[(bitPos >> 3)] >>> (7 - (bitPos & 7))) & 1);
      bitPos++;
    }
    return v;
  };
  assert.equal(readBits(4), 0b0100, 'byte mode indicator');
  const len = readBits(countBits);
  const out = [];
  for (let i = 0; i < len; i++) out.push(readBits(8));
  return { bytes: out, blocks, eccLen, dataLens };
}

// ─── tests ────────────────────────────────────────────────────────────────────

test('finder, timing, and dark-module structure', () => {
  const m = encodeToMatrix('structure check');
  const size = m.length;
  // finder centers dark, ring light
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) {
    assert.equal(m[cy][cx], true, 'finder center dark');
    assert.equal(m[cy - 2][cx - 2], false, 'finder inner ring light');
    assert.equal(m[cy - 3][cx - 3], true, 'finder outer ring dark');
  }
  // timing pattern alternates
  for (let i = 8; i < size - 8; i++) {
    assert.equal(m[6][i], i % 2 === 0, `h timing at ${i}`);
    assert.equal(m[i][6], i % 2 === 0, `v timing at ${i}`);
  }
  // dark module
  assert.equal(m[size - 8][8], true, 'dark module');
});

test('version selection: small text → v1, deep-link payload → v11', () => {
  assert.equal(encodeToMatrix('hi').length, 21);
  const deepLink = 'https://blind-edge.pages.dev/#add=' + '0'.repeat(261);
  assert.equal(encodeToMatrix(deepLink).length, 61);
});

test('payload survives the full inverse pipeline (single-block version)', () => {
  const text = 'blind-edge protocol demo';
  const { bytes } = decodePayload(encodeToMatrix(text));
  assert.equal(new TextDecoder().decode(new Uint8Array(bytes)), text);
});

// Independent RS reimplementation (mirrors the spec, not the encoder's code)
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
    for (let j = 0; j < result.length; j++) result[j] ^= gfMul(divisor[j], factor);
  }
  return result;
}

test('extracted ECC codewords match an independent Reed-Solomon computation', () => {
  for (const text of ['rs check', 'a longer message to push into multi-codeword territory!!']) {
    const m = encodeToMatrix(text);
    const { blocks, eccLen, dataLens } = decodePayload(m);
    const divisor = rsDivisor(eccLen);
    blocks.forEach((block, b) => {
      const dat = block.slice(0, dataLens[b]);
      const ecc = block.slice(dataLens[b]);
      assert.deepEqual(ecc, rsRemainder(dat, divisor), `block ${b} ECC must match`);
    });
  }
});

test('multi-block payload survives the inverse pipeline (v6+, interleaved)', () => {
  // ~140 bytes → version 6-L (2 RS blocks) exercises real interleaving
  const text = 'interleave-check '.repeat(8) + 'tail';
  const m = encodeToMatrix(text);
  const { bytes } = decodePayload(m);
  assert.equal(new TextDecoder().decode(new Uint8Array(bytes)), text);
});

test('SVG output is well-formed', () => {
  const svg = encodeToSvg('svg check', { modulePx: 4, quietZone: 4 });
  assert.ok(svg.startsWith('<svg'));
  assert.ok(svg.includes('viewBox'));
  assert.ok(svg.endsWith('</svg>'));
});

test('payload too large throws a clear error', () => {
  assert.throws(() => encodeToMatrix('x'.repeat(600)), /too long/i);
});
