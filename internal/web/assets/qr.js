/* SwarmMemo QR: a QR code (ISO/IEC 18004) for a short link, drawn as SVG.
   Byte mode, error correction level M, versions 1 to 6 (up to 106 bytes):
   enough for a link-a-device URL. No dependencies; one global. matrix() is
   the module grid (true is dark), svg() draws it with a 4-module quiet zone. */
const SwarmMemoQR = (() => {
  'use strict';
  // Level M: [data codewords per block, blocks, EC codewords per block]; all
  // blocks of these versions have the same length.
  const blocks = [null, [16, 1, 10], [28, 1, 16], [44, 1, 26], [32, 2, 18], [43, 2, 24], [27, 4, 16]];
  const align = [null, [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34]];
  // GF(256) with the QR polynomial x^8+x^4+x^3+x^2+1.
  function mul(x, y) {
    let z = 0;
    for (let i = 7; i >= 0; i--) { z = (z << 1) ^ ((z >>> 7) * 0x11d); z ^= ((y >>> i) & 1) * x; }
    return z & 0xff;
  }
  function divisor(degree) {
    const out = new Array(degree).fill(0); out[degree - 1] = 1;
    let root = 1;
    for (let i = 0; i < degree; i++) {
      for (let j = 0; j < degree; j++) { out[j] = mul(out[j], root); if (j + 1 < degree) out[j] ^= out[j + 1]; }
      root = mul(root, 2);
    }
    return out;
  }
  function remainder(data, div) {
    const out = new Array(div.length).fill(0);
    for (const b of data) {
      const factor = b ^ out.shift(); out.push(0);
      div.forEach((coef, i) => { out[i] ^= mul(coef, factor); });
    }
    return out;
  }
  function codewords(bytes, version) {
    const [perBlock, count, ec] = blocks[version], capacity = perBlock * count;
    const bits = [];
    const put = (value, length) => { for (let i = length - 1; i >= 0; i--) bits.push((value >>> i) & 1); };
    put(4, 4); put(bytes.length, 8); bytes.forEach(b => put(b, 8));
    put(0, Math.min(4, capacity * 8 - bits.length));
    put(0, (8 - bits.length % 8) % 8);
    const data = [];
    for (let i = 0; i < bits.length; i += 8) data.push(bits.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0));
    for (let pad = 0xec; data.length < capacity; pad ^= 0xec ^ 0x11) data.push(pad);
    const div = divisor(ec), dataBlocks = [], ecBlocks = [];
    for (let i = 0; i < count; i++) { const block = data.slice(i * perBlock, (i + 1) * perBlock); dataBlocks.push(block); ecBlocks.push(remainder(block, div)); }
    const out = [];
    for (let i = 0; i < perBlock; i++) dataBlocks.forEach(b => out.push(b[i]));
    for (let i = 0; i < ec; i++) ecBlocks.forEach(b => out.push(b[i]));
    return out;
  }
  const masks = [
    (x, y) => (x + y) % 2 === 0, (x, y) => y % 2 === 0, x => x % 3 === 0, (x, y) => (x + y) % 3 === 0,
    (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0, (x, y) => x * y % 2 + x * y % 3 === 0,
    (x, y) => (x * y % 2 + x * y % 3) % 2 === 0, (x, y) => ((x + y) % 2 + x * y % 3) % 2 === 0,
  ];
  // The format bits of level M (00) and mask: BCH(15,5), XOR 0x5412.
  function formatBits(mask) {
    let rem = mask;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    return ((mask << 10) | rem) ^ 0x5412;
  }
  function build(version, words, mask) {
    const size = version * 4 + 17;
    const grid = Array.from({length: size}, () => new Array(size).fill(false));
    const fixed = Array.from({length: size}, () => new Array(size).fill(false));
    const set = (x, y, dark) => { grid[y][x] = dark; fixed[y][x] = true; };
    for (let i = 0; i < size; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
    for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) {
      for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx, y = cy + dy, d = Math.max(Math.abs(dx), Math.abs(dy));
        if (x >= 0 && x < size && y >= 0 && y < size) set(x, y, d !== 2 && d !== 4);
      }
    }
    const pos = align[version], last = pos.length - 1;
    pos.forEach((ax, i) => pos.forEach((ay, j) => {
      if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) return;
      for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(ax + dx, ay + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }));
    const format = formatBits(mask), bit = i => ((format >>> i) & 1) === 1;
    for (let i = 0; i <= 5; i++) set(8, i, bit(i));
    set(8, 7, bit(6)); set(8, 8, bit(7)); set(7, 8, bit(8));
    for (let i = 9; i < 15; i++) set(14 - i, 8, bit(i));
    for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(i));
    for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(i));
    set(8, size - 8, true);
    let i = 0;
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let vert = 0; vert < size; vert++) for (let j = 0; j < 2; j++) {
        const x = right - j, up = ((right + 1) & 2) === 0, y = up ? size - 1 - vert : vert;
        if (!fixed[y][x] && i < words.length * 8) { grid[y][x] = ((words[i >>> 3] >>> (7 - (i & 7))) & 1) === 1; i++; }
      }
    }
    for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (!fixed[y][x] && masks[mask](x, y)) grid[y][x] = !grid[y][x];
    return grid;
  }
  // A penalty close to the standard's: long runs, 2x2 blocks and imbalance.
  function penalty(grid) {
    const size = grid.length;
    let score = 0, dark = 0;
    for (let a = 0; a < size; a++) for (const line of [grid[a], grid.map(row => row[a])]) {
      let run = 1;
      for (let k = 1; k <= size; k++) {
        if (k < size && line[k] === line[k - 1]) run++;
        else { if (run >= 5) score += run - 2; run = 1; }
      }
    }
    for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
      if (grid[y][x]) dark++;
      if (x + 1 < size && y + 1 < size && grid[y][x] === grid[y][x + 1] && grid[y][x] === grid[y + 1][x] && grid[y][x] === grid[y + 1][x + 1]) score += 3;
    }
    return score + Math.floor(Math.abs(dark * 20 - size * size * 10) / (size * size)) * 10;
  }
  function matrix(text) {
    const bytes = Array.from(new TextEncoder().encode(text));
    const version = blocks.findIndex(b => b && bytes.length <= b[0] * b[1] - 2);
    if (version < 1) throw Error('Too long for a QR code here.');
    const words = codewords(bytes, version);
    let best = null, bestScore = Infinity;
    for (let mask = 0; mask < 8; mask++) {
      const grid = build(version, words, mask), score = penalty(grid);
      if (score < bestScore) { best = grid; bestScore = score; }
    }
    return best;
  }
  function svg(text, label) {
    const grid = matrix(text), size = grid.length + 8, ns = 'http://www.w3.org/2000/svg';
    const el = document.createElementNS(ns, 'svg');
    el.setAttribute('viewBox', `0 0 ${size} ${size}`);
    el.setAttribute('class', 'qr');
    el.setAttribute('role', 'img');
    el.setAttribute('aria-label', label || 'QR code');
    const back = document.createElementNS(ns, 'rect');
    back.setAttribute('width', size); back.setAttribute('height', size); back.setAttribute('fill', '#fff');
    const path = document.createElementNS(ns, 'path');
    let d = '';
    grid.forEach((row, y) => row.forEach((on, x) => { if (on) d += `M${x + 4} ${y + 4}h1v1h-1z`; }));
    path.setAttribute('d', d); path.setAttribute('fill', '#000');
    el.append(back, path);
    return el;
  }
  return Object.freeze({matrix, svg, codewords, mul});
})();
