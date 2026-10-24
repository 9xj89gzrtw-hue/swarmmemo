// Node only (C576): qr.js reads back. The grid is decoded the way a reader
// does it (format bits from both copies, unmask, zigzag), the Reed-Solomon
// syndromes of every block are zero when evaluated at the generator's roots
// (independent of the encoder's division), and the payload is the input.
const fs = require('fs'), vm = require('vm'), path = require('path'), assert = require('assert/strict');
const Q = vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'assets', 'qr.js'), 'utf8') + '\nSwarmMemoQR;', {TextEncoder});
const blocks = [null, [16, 1, 10], [28, 1, 16], [44, 1, 26], [32, 2, 18], [43, 2, 24], [27, 4, 16]];
const align = [null, [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34]];
const masks = [(x, y) => (x + y) % 2 === 0, (x, y) => y % 2 === 0, x => x % 3 === 0, (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0, (x, y) => x * y % 2 + x * y % 3 === 0,
  (x, y) => (x * y % 2 + x * y % 3) % 2 === 0, (x, y) => ((x + y) % 2 + x * y % 3) % 2 === 0];
function exp(n) { let v = 1; for (let i = 0; i < n; i++) v = Q.mul(v, 2); return v; }
function decode(grid) {
  const size = grid.length, version = (size - 17) / 4;
  assert.ok(Number.isInteger(version) && version >= 1 && version <= 6, 'size');
  // Finder patterns: the three corners' 7x7 rings.
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) for (let d = -3; d <= 3; d++) {
    assert.equal(grid[cy - 3][cx + d], true); assert.equal(grid[cy + 3][cx + d], true);
    assert.equal(grid[cy + d][cx - 3], true); assert.equal(grid[cy + d][cx + 3], true);
    assert.equal(grid[cy][cx], true);
  }
  for (let i = 8; i < size - 8; i++) { assert.equal(grid[6][i], i % 2 === 0, 'timing row'); assert.equal(grid[i][6], i % 2 === 0, 'timing column'); }
  assert.equal(grid[size - 8][8], true, 'dark module');
  // Format: both copies agree, level M, valid BCH.
  let a = 0, b = 0;
  const first = [[8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5], [8, 7], [8, 8], [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8]];
  first.forEach(([x, y], i) => { if (grid[y][x]) a |= 1 << i; });
  for (let i = 0; i < 8; i++) if (grid[8][size - 1 - i]) b |= 1 << i;
  for (let i = 8; i < 15; i++) if (grid[size - 15 + i][8]) b |= 1 << i;
  assert.equal(a, b, 'format copies');
  const format = a ^ 0x5412, data = format >>> 10;
  let rem = data; for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  assert.equal(format & 0x3ff, rem & 0x3ff, 'format BCH');
  assert.equal(data >>> 3, 0, 'level M');
  const mask = data & 7;
  // Function modules, as a reader knows them.
  const fixed = Array.from({length: size}, () => new Array(size).fill(false));
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
    if (x === 6 || y === 6 || (x < 9 && y < 9) || (x > size - 9 && y < 9) || (x < 9 && y > size - 9)) fixed[y][x] = true;
  }
  const pos = align[version], last = pos.length - 1;
  pos.forEach((ax, i) => pos.forEach((ay, j) => {
    if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) return;
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) fixed[ay + dy][ax + dx] = true;
  }));
  const bits = [];
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) for (let j = 0; j < 2; j++) {
      const x = right - j, up = ((right + 1) & 2) === 0, y = up ? size - 1 - vert : vert;
      if (!fixed[y][x]) bits.push(grid[y][x] !== masks[mask](x, y));
    }
  }
  const [per, count, ec] = blocks[version], total = (per + ec) * count;
  const words = [];
  for (let i = 0; i < total; i++) words.push(bits.slice(i * 8, i * 8 + 8).reduce((v, bit) => (v << 1) | (bit ? 1 : 0), 0));
  // De-interleave and check each block's syndromes.
  const dataOut = [];
  for (let k = 0; k < count; k++) {
    const block = [];
    for (let i = 0; i < per; i++) block.push(words[i * count + k]);
    for (let i = 0; i < ec; i++) block.push(words[per * count + i * count + k]);
    for (let r = 0; r < ec; r++) {
      let s = 0; const root = exp(r);
      for (const c of block) s = Q.mul(s, root) ^ c;
      assert.equal(s, 0, `syndrome ${r} of block ${k}`);
    }
    dataOut.push(...block.slice(0, per));
  }
  const stream = dataOut.flatMap(w => [7, 6, 5, 4, 3, 2, 1, 0].map(i => (w >>> i) & 1));
  const read = (at, n) => stream.slice(at, at + n).reduce((v, bit) => (v << 1) | bit, 0);
  assert.equal(read(0, 4), 4, 'byte mode');
  const n = read(4, 8), out = [];
  for (let i = 0; i < n; i++) out.push(read(12 + i * 8, 8));
  return Buffer.from(out).toString('utf8');
}
for (const text of ['https://swarmmemo.com/me#link=K7QM4XPD', 'https://publicbbs.com/me#link=0123456789', 'x', 'A'.repeat(14), 'B'.repeat(42), 'C'.repeat(62), 'D'.repeat(84), 'é'.repeat(53)]) {
  assert.equal(decode(Q.matrix(text)), text);
}
assert.throws(() => Q.matrix('E'.repeat(107)));
console.log('qr ok');
