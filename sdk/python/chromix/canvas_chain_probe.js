/* Real API operations; pixel evidence is validated independently by Python. */
globalThis.canvasChainProbe = async ({taint = true} = {}) => {
  const width = 32, height = 24;
  const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
  const require = (ok, why) => { if (!ok) throw Error(why); };
  const errorName = async fn => { try { await fn(); return null; } catch (e) { return e.name; } };
  const bytes64 = bytes => btoa(String.fromCharCode(...bytes));
  const make = kind => kind === 'html' ? Object.assign(document.createElement('canvas'), {width, height}) : new OffscreenCanvas(width, height);
  const read = (ctx, colorSpace) => Array.from(ctx.getImageData(0, 0, width, height, {colorSpace}).data);
  const blobFor = (canvas, type, quality = 0.92) => canvas.convertToBlob ? canvas.convertToBlob({type, quality}) :
    new Promise((resolve, reject) => canvas.toBlob(b => b ? resolve(b) : reject(Error('null blob')), type, quality));
  const bitmapRead = async (source, colorSpace, options = {}) => {
    const bitmap = await createImageBitmap(source, options);
    try {
      require(bitmap.width === width && bitmap.height === height, 'bitmap dimensions');
      const target = new OffscreenCanvas(width, height), ctx = target.getContext('2d', {colorSpace});
      ctx.drawImage(bitmap, 0, 0);
      return read(ctx, colorSpace);
    } finally { bitmap.close(); }
  };
  const exportFor = async (canvas, colorSpace, type, quality = 0.92) => {
    const blob = await blobFor(canvas, type, quality), bytes = new Uint8Array(await blob.arrayBuffer());
    require(blob.type === type, 'encoder silently fell back: ' + type + ' -> ' + blob.type);
    const repeat = new Uint8Array(await (await blobFor(canvas, type, quality)).arrayBuffer());
    let dataURL = null, repeatDataURL = null, urlRepeat = null, urlBlobMatches = null;
    if (canvas.toDataURL) {
      dataURL = canvas.toDataURL(type, quality);
      repeatDataURL = canvas.toDataURL(type, quality);
      urlRepeat = dataURL === repeatDataURL;
      urlBlobMatches = dataURL === `data:${type};base64,${bytes64(bytes)}`;
    }
    return {type, quality, bytes:bytes64(bytes), repeatBytes:bytes64(repeat),
      repeat:equal(bytes, repeat), dataURL, repeatDataURL, urlRepeat, urlBlobMatches,
      urlMatches:urlRepeat === null ? null : urlRepeat && urlBlobMatches,
      decoded:await bitmapRead(blob, colorSpace), decodedSrgb:await bitmapRead(blob, 'srgb'),
      decodedNoPremultiply:await bitmapRead(blob, colorSpace, {premultiplyAlpha:'none'})};
  };
  const rows = [], errors = [], unavailable = [];
  const kinds = typeof document === 'undefined' ? ['offscreen'] : ['html', 'offscreen'];
  for (const kind of kinds) for (const colorSpace of ['srgb', 'display-p3']) for (const alpha of [true, false]) {
    const id = `${kind}/${colorSpace}/${alpha}`;
    try {
      const canvas = make(kind), ctx = canvas.getContext('2d', {colorSpace, alpha});
      require(ctx, '2D context missing');
      if (ctx.getContextAttributes().colorSpace !== colorSpace) {
        unavailable.push({id, reason:'requested color space unavailable'}); continue;
      }
      // Sharp bands exercise pixel transfer; subsampled codecs need separate quality evidence.
      const colors = [[48,96,160,255],[160,80,48,128],[40,200,100,64],[200,30,160,0]];
      const data = ctx.createImageData(width, height, {colorSpace});
      for (let y = 0; y < height; y++) for (let x = 0; x < width; x++)
        data.data.set(colors[Math.floor(x / 8)], (y * width + x) * 4);
      ctx.putImageData(data, 0, 0);
      const reference = read(ctx, colorSpace), srgb = read(ctx, 'srgb');
      const crop = ctx.getImageData(3, 2, 7, 6, {colorSpace}).data;
      const padded = ctx.getImageData(-2, -2, width + 4, height + 4, {colorSpace}).data;
      let cropMatches = true, paddingMatches = true;
      for (let y = 0; y < 6; y++) for (let x = 0; x < 7; x++) for (let k = 0; k < 4; k++)
        cropMatches &&= crop[(y * 7 + x) * 4 + k] === reference[((y + 2) * width + x + 3) * 4 + k];
      for (let y = 0; y < height + 4; y++) for (let x = 0; x < width + 4; x++) for (let k = 0; k < 4; k++) {
        const expected = x < 2 || y < 2 || x >= width + 2 || y >= height + 2 ? 0 : reference[((y - 2) * width + x - 2) * 4 + k];
        paddingMatches &&= padded[(y * (width + 4) + x) * 4 + k] === expected;
      }
      const direct = await bitmapRead(canvas, colorSpace);
      const premultiply = {};
      for (const option of ['none', 'premultiply', 'default'])
        premultiply[option] = await bitmapRead(canvas, colorSpace, {premultiplyAlpha:option});
      const noConversion = await bitmapRead(canvas, colorSpace, {colorSpaceConversion:'none'});
      let float16 = {status:'unavailable', reason:'Float16Array missing'};
      if (typeof Float16Array !== 'undefined') {
        const f = ctx.getImageData(0, 0, width, height, {colorSpace, pixelFormat:'rgba-float16'});
        float16 = f.pixelFormat === 'rgba-float16' ? {status:'observed', pixels:Array.from(f.data),
          typed:f.data instanceof Float16Array, colorSpace:f.colorSpace} : {status:'unavailable', reason:'float16 ignored'};
        if (float16.status === 'observed') {
          const input = new Float16Array(Array.from(data.data, v => v / 255));
          const scratch = make(kind), target = scratch.getContext('2d', {colorSpace, alpha});
          target.putImageData(new ImageData(input, width, height, {colorSpace, pixelFormat:'rgba-float16'}), 0, 0);
          float16.inputReadback = read(target, colorSpace);
        }
      }
      const exports = [];
      for (const type of ['image/png', 'image/jpeg', 'image/webp']) {
        const item = await exportFor(canvas, colorSpace, type);
        if (type !== 'image/png') item.fullQuality = await exportFor(canvas, colorSpace, type, 1);
        exports.push(item);
      }
      const qualityCanvas = make(kind), qualityContext = qualityCanvas.getContext('2d', {colorSpace, alpha});
      const qualityData = qualityContext.createImageData(width, height, {colorSpace});
      for (let y = 0; y < height; y++) for (let x = 0; x < width; x++) {
        const position = Math.max(0, Math.min(3, (x - 4) / 8));
        const left = Math.floor(position), right = Math.min(3, left + 1), fraction = position - left;
        for (let k = 0; k < 4; k++) qualityData.data[(y * width + x) * 4 + k] =
          Math.round(colors[left][k] * (1 - fraction) + colors[right][k] * fraction);
      }
      qualityContext.putImageData(qualityData, 0, 0);
      const lossyQuality = {input:Array.from(qualityData.data), reference:read(qualityContext, colorSpace),
        srgb:read(qualityContext, 'srgb'), attributes:qualityContext.getContextAttributes(), exports:[]};
      for (const type of ['image/jpeg', 'image/webp'])
        lossyQuality.exports.push(await exportFor(qualityCanvas, colorSpace, type));
      lossyQuality.finalRead = read(qualityContext, colorSpace);
      const fallback = await blobFor(canvas, 'image/x-chromix-unsupported');
      const invalidRead = await errorName(() => ctx.getImageData(0, 0, 0, 1));
      const finalRead = read(ctx, colorSpace), sourceStable = equal(reference, finalRead);
      let transfer = null;
      if (kind === 'offscreen') {
        const image = canvas.transferToImageBitmap();
        try {
          const dest = make('offscreen'), out = dest.getContext('2d', {colorSpace, alpha});
          out.drawImage(image, 0, 0);
          transfer = {pixels:read(out, colorSpace), cleared:read(ctx, colorSpace)};
        } finally { image.close(); }
      }
      rows.push({id, kind, colorSpace, alpha, width, height, attributes:ctx.getContextAttributes(),
        input:Array.from(data.data), reference, srgb, direct, premultiply, noConversion, float16,
        exports, lossyQuality, crop:Array.from(crop), padded:Array.from(padded), cropMatches, paddingMatches,
        invalidRead, sourceStable, finalRead, fallback:fallback.type, transfer});
    } catch (e) { errors.push({id, name:e.name, message:e.message}); }
  }
  const zero = make('offscreen'); zero.width = 0;
  const zeroBlob = await errorName(() => blobFor(zero, 'image/png'));
  // Fresh backing stores separate options/history-dependent OOB behavior from
  // codec, alpha:false and ImageBitmap paths above.
  const edges = [];
  for (const kind of kinds) for (const history of ['fresh', 'full', 'crop']) for (const explicit of [false, true]) {
    const c = make(kind), ctx = c.getContext('2d');
    ctx.fillStyle = 'rgb(48,96,160)'; ctx.fillRect(0, 0, width, height);
    if (history !== 'fresh') ctx.getImageData(0, 0, width, height);
    if (history === 'crop') ctx.getImageData(3, 2, 7, 6);
    const args = [-2, -2, width + 4, height + 4];
    if (explicit) args.push({colorSpace:'srgb'});
    edges.push({id:`${kind}/${history}/${explicit}`, pixels:Array.from(ctx.getImageData(...args).data)});
  }
  const result = {version:3, rows, errors, unavailable, zeroBlob, edges};
  if (typeof document !== 'undefined') {
    const empty = make('html'); empty.width = 0;
    result.zeroURL = empty.toDataURL();
    result.zeroCallback = await new Promise(resolve => empty.toBlob(b => resolve(b === null)));
    if (!taint) { result.taint = {status:'not_collected'}; return result; }
    // No CORS header on this second loopback origin: security behavior must remain native.
    const img = new Image(); img.src = globalThis.canvasTaintURL;
    await img.decode();
    result.taint = [];
    for (const kind of kinds) {
      const c = make(kind), ctx = c.getContext('2d'); ctx.drawImage(img, 0, 0);
      result.taint.push({kind, read:await errorName(() => ctx.getImageData(0,0,1,1)),
        blob:await errorName(() => blobFor(c, 'image/png')),
        url:c.toDataURL ? await errorName(() => c.toDataURL()) : null});
    }
  }
  return result;
};
