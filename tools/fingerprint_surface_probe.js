/* Bounded browser probes; exceptions are failures, not capability skips. */
(() => {
  'use strict';
  const unavailable = reason => ({available:false, reason});
  const capture = async fn => {
    try { return await fn(); }
    catch (e) { return {error:{name:e.name, message:e.message}}; }
  };
  const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
  const digest = async data => Array.from(new Uint8Array(await crypto.subtle.digest(
    'SHA-256', ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : data)),
    b => b.toString(16).padStart(2, '0')).join('');
  const exception = fn => {
    try { fn(); return null; } catch (e) { return e.name; }
  };
  const width = 16, height = 12;
  const makeCanvas = () => {
    const c = typeof document === 'undefined' ? new OffscreenCanvas(width, height) : document.createElement('canvas');
    c.width = width; c.height = height;
    return c;
  };
  const paint = c => {
    const ctx = c.getContext('2d');
    if (!ctx) return null;
    ctx.fillStyle = '#234567'; ctx.fillRect(2, 2, 12, 8);
    ctx.fillStyle = '#abc123'; ctx.fillRect(4, 3, 5, 4);
    return ctx;
  };
  const blobFor = c => typeof c.convertToBlob === 'function' ? c.convertToBlob({type:'image/png'}) :
    new Promise((resolve, reject) => c.toBlob(b => b ? resolve(b) : reject(new Error('toBlob returned null')), 'image/png'));
  const png = bytes => {
    const header = [137, 80, 78, 71, 13, 10, 26, 10];
    if (bytes.length < 33 || !equal(bytes.slice(0, 8), header)) return false;
    const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return v.getUint32(8) === 13 && v.getUint32(12) === 0x49484452 &&
      v.getUint32(16) === width && v.getUint32(20) === height;
  };
  async function canvasProbe() {
    if (typeof document === 'undefined' && typeof OffscreenCanvas === 'undefined')
      return unavailable('OffscreenCanvas unavailable in worker');
    const canvas = makeCanvas(), ctx = paint(canvas);
    if (!ctx) return unavailable('2D context unavailable');
    const read = () => ctx.getImageData(0, 0, width, height).data;
    const first = new Uint8ClampedArray(read());
    const crop = ctx.getImageData(3, 2, 7, 6).data;
    const padded = ctx.getImageData(-2, -2, width + 4, height + 4).data;
    let cropMatches = true, paddedMatches = true, outsideZero = true;
    for (let y = 0; y < 6; y++) for (let x = 0; x < 7; x++) for (let k = 0; k < 4; k++)
      cropMatches &&= crop[(y * 7 + x) * 4 + k] === first[((y + 2) * width + x + 3) * 4 + k];
    for (let y = 0; y < height + 4; y++) for (let x = 0; x < width + 4; x++) for (let k = 0; k < 4; k++) {
      const v = padded[(y * (width + 4) + x) * 4 + k];
      if (x < 2 || y < 2 || x >= width + 2 || y >= height + 2) outsideZero &&= v === 0;
      else paddedMatches &&= v === first[((y - 2) * width + x - 2) * 4 + k];
    }
    const invalid = exception(() => ctx.getImageData(0, 0, 0, 1));
    const exports = await capture(async () => {
      if (typeof canvas.convertToBlob !== 'function' && typeof canvas.toBlob !== 'function')
        return unavailable('PNG blob export unavailable');
      const blob = await blobFor(canvas), bytes = new Uint8Array(await blob.arrayBuffer());
      const repeat = new Uint8Array(await (await blobFor(canvas)).arrayBuffer());
      let dataURL = unavailable('OffscreenCanvas has no toDataURL');
      if (typeof canvas.toDataURL === 'function') {
        const url = canvas.toDataURL('image/png');
        if (!url.startsWith('data:image/png;base64,')) throw new Error('PNG data URL missing');
        const decoded = Uint8Array.from(atob(url.split(',')[1]), c => c.charCodeAt(0));
        dataURL = {available:true, png:png(decoded), matchesBlob:equal(decoded, bytes),
          repeat:url === canvas.toDataURL('image/png'), hash:await digest(decoded)};
      }
      return {available:true, png:png(bytes), repeat:equal(bytes, repeat), mime:blob.type,
        hash:await digest(bytes), dataURL};
    });
    const bitmap = await capture(async () => {
      if (typeof createImageBitmap !== 'function') return unavailable('createImageBitmap unavailable');
      const readBitmap = image => {
        const target = makeCanvas(), c = target.getContext('2d');
        if (!c) throw new Error('bitmap destination context missing');
        c.drawImage(image, 0, 0);
        const a = new Uint8ClampedArray(c.getImageData(0, 0, width, height).data);
        return {a, repeat:equal(a, c.getImageData(0, 0, width, height).data)};
      };
      const direct = readBitmap(canvas);
      const image = await createImageBitmap(canvas);
      let drawn;
      try { drawn = readBitmap(image); } finally { image.close(); }
      // A readback of decoded PNG pixels is farbled again; it is not the PNG's raw pixels.
      const blob = await blobFor(canvas), decoded = [];
      for (let i = 0; i < 2; i++) {
        const b = await createImageBitmap(blob);
        try {
          if (b.width !== width || b.height !== height) throw new Error('decoded PNG dimensions differ');
          decoded.push(readBitmap(b));
        } finally { b.close(); }
      }
      let transfer = unavailable('OffscreenCanvas transferToImageBitmap unavailable');
      if (typeof OffscreenCanvas !== 'undefined' && typeof OffscreenCanvas.prototype.transferToImageBitmap === 'function') {
        const source = new OffscreenCanvas(width, height), c = paint(source);
        if (!c) throw new Error('transfer source context missing');
        const b = source.transferToImageBitmap();
        try {
          const result = readBitmap(b);
          transfer = {available:true, matchesDirect:equal(result.a, direct.a), repeat:result.repeat,
            sourceCleared:Array.from(c.getImageData(0, 0, width, height).data).every(v => v === 0)};
        } finally { b.close(); }
      }
      return {available:true, matchesDirect:equal(drawn.a, direct.a), repeat:drawn.repeat && direct.repeat,
        decodedRepeat:decoded.every(v => v.repeat) && equal(decoded[0].a, decoded[1].a),
        decodedReadbackHash:await digest(decoded[0].a), transfer};
    });
    const float16 = await capture(async () => {
      if (typeof Float16Array === 'undefined') return unavailable('Float16Array unavailable');
      const a = ctx.getImageData(0, 0, width, height, {pixelFormat:'rgba-float16'});
      if (a.pixelFormat !== 'rgba-float16') return unavailable('getImageData ignores rgba-float16 setting');
      const b = ctx.getImageData(0, 0, width, height, {pixelFormat:'rgba-float16'});
      return {available:true, finite:Array.from(a.data).every(Number.isFinite), typed:a.data instanceof Float16Array,
        repeat:equal(a.data, b.data), length:a.data.length};
    });
    return {available:true, pixelHash:await digest(first), repeat:equal(first, read()), cropMatches,
      paddedMatches, outsideZero, transparentZero:first.slice(0, width * 4).every(v => v === 0),
      invalid, sourceStable:equal(first, read()), exports, bitmap, float16};
  }
  async function glProbe(version) {
    const canvas = document.createElement('canvas'); canvas.width = canvas.height = 4;
    const gl = canvas.getContext(version, {antialias:false, preserveDrawingBuffer:true});
    if (!gl) return unavailable(version + ' context unavailable');
    const buffers = [], shaders = [];
    let program;
    try {
      const initialError = gl.getError();
      const extensions = gl.getSupportedExtensions();
      if (!Array.isArray(extensions) || extensions.length > 128) throw new Error('invalid extension list');
      const requestable = extensions.every(name => gl.getExtension(name) !== null);
      const compile = (type, source) => {
        const shader = gl.createShader(type); shaders.push(shader);
        gl.shaderSource(shader, source); gl.compileShader(shader);
        if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(shader) || 'shader compile failed');
        return shader;
      };
      const v2 = version === 'webgl2';
      const vertex = compile(gl.VERTEX_SHADER, v2 ? '#version 300 es\nin vec2 p;void main(){gl_Position=vec4(p,0.,1.);}' :
        'attribute vec2 p;void main(){gl_Position=vec4(p,0.,1.);}');
      const fragment = compile(gl.FRAGMENT_SHADER, v2 ? '#version 300 es\nprecision mediump float;out vec4 color;void main(){color=vec4(.25,.5,.75,1.);}' :
        'precision mediump float;void main(){gl_FragColor=vec4(.25,.5,.75,1.);}');
      program = gl.createProgram(); gl.attachShader(program, vertex); gl.attachShader(program, fragment); gl.linkProgram(program);
      if (!gl.getProgramParameter(program, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(program) || 'shader link failed');
      gl.useProgram(program);
      const buffer = gl.createBuffer(); buffers.push(buffer); gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
      gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1,-1,3,-1,-1,3]), gl.STATIC_DRAW);
      const location = gl.getAttribLocation(program, 'p');
      gl.enableVertexAttribArray(location); gl.vertexAttribPointer(location, 2, gl.FLOAT, false, 0, 0);
      gl.viewport(0, 0, 4, 4); gl.drawArrays(gl.TRIANGLES, 0, 3);
      const drawError = gl.getError();
      const read = () => { const b = new Uint8Array(64); gl.readPixels(0, 0, 4, 4, gl.RGBA, gl.UNSIGNED_BYTE, b); return b; };
      const first = read(), repeat = read();
      const readError = gl.getError();
      const invalid = [];
      for (const [w, format, expected] of [[-1, gl.RGBA, gl.INVALID_VALUE], [4, 0xdead, gl.INVALID_ENUM]]) {
        const target = new Uint8Array(64).fill(173);
        gl.readPixels(0, 0, w, 4, format, gl.UNSIGNED_BYTE, target);
        invalid.push({error:gl.getError(), expected, unchanged:target.every(v => v === 173)});
      }
      gl.enable(0xdead);
      const afterPending = read(), pendingError = gl.getError(), trailingError = gl.getError();
      gl.pixelStorei(gl.PACK_ALIGNMENT, 8);
      const aligned = new Uint8Array(32).fill(173);
      gl.readPixels(0, 0, 3, 2, gl.RGBA, gl.UNSIGNED_BYTE, aligned);
      let alignedMatches = true, alignedGuards = true;
      for (let i = 0; i < 32; i++) {
        const row = Math.floor(i / 16), col = i % 16;
        if (col < 12) alignedMatches &&= aligned[i] === first[row * 16 + col];
        else alignedGuards &&= aligned[i] === 173;
      }
      const alignedError = gl.getError();
      let pack = unavailable('PACK_ROW_LENGTH and skip parameters require WebGL2');
      if (v2) {
        gl.pixelStorei(gl.PACK_ROW_LENGTH, 6); gl.pixelStorei(gl.PACK_SKIP_ROWS, 2); gl.pixelStorei(gl.PACK_SKIP_PIXELS, 1);
        const packed = new Uint8Array(128).fill(173);
        gl.readPixels(0, 0, 2, 2, gl.RGBA, gl.UNSIGNED_BYTE, packed, 3);
        let matches = true, guards = true;
        for (let i = 0; i < packed.length; i++) {
          const relative = i - 55, row = Math.floor(relative / 24), col = relative % 24;
          if (relative >= 0 && row < 2 && col < 8) matches &&= packed[i] === first[row * 16 + col];
          else guards &&= packed[i] === 173;
        }
        const error = gl.getError(), short = new Uint8Array(8).fill(173);
        gl.readPixels(0, 0, 2, 2, gl.RGBA, gl.UNSIGNED_BYTE, short);
        pack = {available:true, matches, guards, glError:error,
          shortError:gl.getError(), shortUnchanged:short.every(v => v === 173)};
        gl.pixelStorei(gl.PACK_ROW_LENGTH, 0); gl.pixelStorei(gl.PACK_SKIP_ROWS, 0); gl.pixelStorei(gl.PACK_SKIP_PIXELS, 0);
      }
      gl.pixelStorei(gl.PACK_ALIGNMENT, 4);
      return {available:true, initialError, drawError, readError, extensions, requestable,
        pixelHash:await digest(first), repeat:equal(first, repeat),
        shaderPixels:Array.from(first).every((v, i) => Math.abs(v - [64,128,191,255][i % 4]) <= (i % 4 === 3 ? 0 : 2)),
        invalid, pendingError, trailingError, pendingReadStable:equal(first, afterPending),
        alignedMatches, alignedGuards, alignedError, pack, sourceStable:equal(first, read()), finalError:gl.getError()};
    } finally {
      buffers.forEach(b => gl.deleteBuffer(b)); shaders.forEach(s => gl.deleteShader(s));
      if (program) gl.deleteProgram(program);
    }
  }
  async function gpuProbe() {
    if (!navigator.gpu) return unavailable('navigator.gpu unavailable');
    const adapter = await navigator.gpu.requestAdapter();
    if (!adapter) return unavailable('WebGPU adapter unavailable');
    const advertised = Array.from(adapter.features).sort();
    if (advertised.length > 128) throw new Error('unbounded WebGPU feature list');
    const device = await adapter.requestDevice({requiredFeatures:advertised});
    const buffers = [], errors = [];
    device.addEventListener('uncapturederror', e => errors.push(e.error.message));
    let context;
    try {
      const canvas = document.createElement('canvas'); canvas.width = canvas.height = 1;
      context = canvas.getContext('webgpu');
      if (!context) throw new Error('WebGPU adapter exists but canvas context unavailable');
      const format = navigator.gpu.getPreferredCanvasFormat();
      device.pushErrorScope('validation');
      context.configure({device, format, alphaMode:'opaque', usage:GPUTextureUsage.RENDER_ATTACHMENT | GPUTextureUsage.COPY_SRC});
      const src = device.createBuffer({size:16, usage:GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST}); buffers.push(src);
      const dst = device.createBuffer({size:16, usage:GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ}); buffers.push(dst);
      const pixels = device.createBuffer({size:256, usage:GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ}); buffers.push(pixels);
      const words = new Uint32Array([0x12345678, 0, 0xffffffff, 0xabcdef01]); device.queue.writeBuffer(src, 0, words);
      const texture = context.getCurrentTexture(), encoder = device.createCommandEncoder();
      const pass = encoder.beginRenderPass({colorAttachments:[{view:texture.createView(), loadOp:'clear', storeOp:'store',
        clearValue:{r:0.25,g:0.5,b:0.75,a:1}}]}); pass.end();
      encoder.copyBufferToBuffer(src, 0, dst, 0, 16);
      encoder.copyTextureToBuffer({texture}, {buffer:pixels, bytesPerRow:256}, {width:1,height:1,depthOrArrayLayers:1});
      device.queue.submit([encoder.finish()]);
      await Promise.all([dst.mapAsync(GPUMapMode.READ), pixels.mapAsync(GPUMapMode.READ)]);
      const copied = Array.from(new Uint32Array(dst.getMappedRange())), rgba = Array.from(new Uint8Array(pixels.getMappedRange()).slice(0, 4));
      dst.unmap(); pixels.unmap();
      const error = await device.popErrorScope();
      const expected = format === 'bgra8unorm' ? [191,128,64,255] : [64,128,191,255];
      return {available:true, advertised, enabled:Array.from(device.features).sort(), format,
        copied, copyMatches:equal(copied, words), rgba,
        canvasMatches:rgba.every((v, i) => Math.abs(v - expected[i]) <= 1),
        validationError:error ? error.message : null, uncapturedErrors:errors};
    } finally {
      if (context) context.unconfigure();
      buffers.forEach(b => b.destroy()); device.destroy();
    }
  }
  async function audioProbe() {
    if (typeof OfflineAudioContext === 'undefined') return unavailable('OfflineAudioContext unavailable');
    const render = async silent => {
      const c = new OfflineAudioContext(1, 4096, 44100);
      if (!silent) {
        const oscillator = c.createOscillator(), compressor = c.createDynamicsCompressor();
        oscillator.type = 'triangle'; oscillator.frequency.value = 997;
        oscillator.connect(compressor); compressor.connect(c.destination); oscillator.start(0); oscillator.stop(4096 / 44100);
      }
      const buffer = await c.startRendering(), a = new Float32Array(buffer.getChannelData(0));
      return {hash:await digest(a), repeat:equal(a, buffer.getChannelData(0)), finite:Array.from(a).every(Number.isFinite),
        nonzero:a.some(v => v !== 0), zero:a.every(v => v === 0), rate:buffer.sampleRate, length:buffer.length};
    };
    const first = await render(false), second = await render(false), silence = await render(true);
    const c = new OfflineAudioContext(1, 128, 48000), b = c.createBuffer(2, 16, 48000);
    const channel = b.getChannelData(0); channel[3] = 0.25;
    const mutable = b.getChannelData(0)[3] === 0.25;
    b.copyToChannel(new Float32Array([0.5,-0.5,0.75]), 0, 14);
    const copied = new Float32Array(4).fill(0.875); b.copyFromChannel(copied, 0, 14);
    const before = new Float32Array(b.getChannelData(0)), invalid = [];
    for (const index of [2, -1]) {
      const destination = new Float32Array(4).fill(0.625);
      invalid.push({index, from:exception(() => b.copyFromChannel(destination, index)),
        to:exception(() => b.copyToChannel(new Float32Array([1]), index)),
        get:exception(() => b.getChannelData(index)), unchanged:destination.every(v => v === 0.625)});
    }
    const beyond = new Float32Array(4).fill(0.625); b.copyFromChannel(beyond, 0, 16);
    b.copyToChannel(new Float32Array([1]), 0, 16);
    const boundary = {mutable, truncated:equal(copied, [0.5,-0.5,0.875,0.875]),
      beyondUnchanged:beyond.every(v => v === 0.625), sourceStable:equal(before, b.getChannelData(0)),
      otherChannelSilent:b.getChannelData(1).every(v => v === 0), invalid, rates:[c.sampleRate, b.sampleRate]};
    // PCM16 little-endian mono WAV, decoded at the context's rate without resampling.
    const pcm = [0, 8192, -8192, 16384, -16384, 32767, -32768, 0];
    const wav = new ArrayBuffer(44 + pcm.length * 2), view = new DataView(wav);
    const text = (offset, s) => Array.from(s).forEach((v, i) => view.setUint8(offset + i, v.charCodeAt(0)));
    text(0, 'RIFF'); view.setUint32(4, wav.byteLength - 8, true); text(8, 'WAVE'); text(12, 'fmt ');
    view.setUint32(16, 16, true); view.setUint16(20, 1, true); view.setUint16(22, 1, true);
    view.setUint32(24, 48000, true); view.setUint32(28, 96000, true); view.setUint16(32, 2, true); view.setUint16(34, 16, true);
    text(36, 'data'); view.setUint32(40, pcm.length * 2, true); pcm.forEach((v, i) => view.setInt16(44 + 2 * i, v, true));
    const decoded = await c.decodeAudioData(wav.slice(0)), again = await c.decodeAudioData(wav.slice(0));
    const samples = Array.from(decoded.getChannelData(0));
    return {available:true, first, second, silence, boundary,
      wav:{samples, rate:decoded.sampleRate, length:decoded.length, channels:decoded.numberOfChannels,
        repeat:equal(samples, again.getChannelData(0)), sourceBytes:wav.byteLength}};
  }
  async function codecProbe() {
    const types = ['not-a-mime', 'audio/x-chromix-invalid; codecs="missing"', 'audio/wav; codecs="1"',
      'audio/webm; codecs="opus"', 'video/webm; codecs="vp8"', 'video/mp4; codecs="avc1.42E01E"'];
    const media = document.createElement('video');
    const canPlay = types.map(mime => ({mime, value:media.canPlayType(mime)}));
    const observe = (object, method) => object && typeof object[method] === 'function' ?
      {available:true, values:types.map(mime => ({mime, value:object[method](mime)}))} : unavailable(method + ' unavailable');
    const mse = observe(globalThis.MediaSource, 'isTypeSupported'), recorder = observe(globalThis.MediaRecorder, 'isTypeSupported');
    const capabilities = await capture(async () => {
      const mc = navigator.mediaCapabilities;
      if (!mc || typeof mc.decodingInfo !== 'function' || typeof mc.encodingInfo !== 'function')
        return unavailable('MediaCapabilities decodingInfo/encodingInfo unavailable');
      const configs = ['audio/x-chromix-invalid; codecs="missing"', 'audio/webm; codecs="opus"'];
      const decoding = [], encoding = [];
      for (const contentType of configs) {
        const audio = {contentType, channels:'1', bitrate:64000, samplerate:48000};
        decoding.push(await mc.decodingInfo({type:'file', audio}));
      }
      // Record encoding is experimental; WebRTC takes RTP MIME types, not containers.
      for (const contentType of ['audio/x-chromix-invalid', 'audio/opus']) {
        const audio = {contentType, channels:'2', bitrate:64000, samplerate:48000};
        encoding.push(await mc.encodingInfo({type:'webrtc', audio}));
      }
      return {available:true, decoding, encoding};
    });
    return {available:true, canPlay, mse, recorder, capabilities};
  }
  async function networkProbe() {
    if (!performance || typeof performance.getEntriesByName !== 'function') return unavailable('ResourceTiming unavailable');
    const url = new URL('/timing?surface=' + String(performance.now()), location.href).href;
    const response = await fetch(url, {cache:'no-store', mode:'same-origin', redirect:'error'});
    const body = await response.text();
    // Resource timing publication can trail fetch body completion by a task.
    for (let i = 0; i < 20 && !performance.getEntriesByName(url, 'resource').length; i++)
      await new Promise(resolve => setTimeout(resolve, 10));
    const entries = performance.getEntriesByName(url, 'resource');
    return {available:true, ok:response.ok, status:response.status, body, entries:entries.map(e =>
      ({name:e.name, initiatorType:e.initiatorType, startTime:e.startTime, responseStart:e.responseStart,
        responseEnd:e.responseEnd, duration:e.duration, transferSize:e.transferSize, encodedBodySize:e.encodedBodySize,
        decodedBodySize:e.decodedBodySize}))};
  }
  globalThis.fingerprintSurfaceProbe = async mode => {
    const result = {canvas:await capture(canvasProbe)};
    if (mode !== 'canvas') {
      for (const [name, fn] of [['webgl1', () => glProbe('webgl')], ['webgl2', () => glProbe('webgl2')],
        ['webgpu', gpuProbe], ['audio', audioProbe], ['codecs', codecProbe], ['network', networkProbe]]) result[name] = await capture(fn);
    }
    return result;
  };
})();
