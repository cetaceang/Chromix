"""Offline validator/Node regressions, never matching-browser runtime evidence."""
from copy import deepcopy
import json
import math
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from test_fingerprint_smoke import NODE, failures, observation, smoke, surface_absent


HASH = "a" * 64


def absent():
    return {"available": False, "reason": "explicit offline fixture capability absence"}


def canvas():
    return {"available": True, "pixelHash": HASH, "repeat": True, "cropMatches": True,
            "paddedMatches": True, "outsideZero": True, "transparentZero": True,
            "sourceStable": True, "invalid": "IndexSizeError",
            "exports": {"available": True, "png": True, "repeat": True, "mime": "image/png", "hash": HASH,
                        "dataURL": {"available": True, "png": True, "matchesBlob": True, "repeat": True, "hash": HASH}},
            "bitmap": {"available": True, "matchesDirect": True, "repeat": True, "decodedRepeat": True,
                       "decodedReadbackHash": "b" * 64,
                       "transfer": {"available": True, "matchesDirect": True, "repeat": True, "sourceCleared": True}},
            "float16": {"available": True, "finite": True, "repeat": True, "typed": True, "length": 768}}


def gl(version):
    return {"available": True, "pixelHash": HASH, "initialError": 0, "drawError": 0, "readError": 0,
            "extensions": ["OES_example"], "requestable": True, "repeat": True, "shaderPixels": True,
            "invalid": [{"error": 0x501, "unchanged": True}, {"error": 0x500, "unchanged": True}],
            "pendingError": 0x500, "trailingError": 0, "pendingReadStable": True,
            "alignedMatches": True, "alignedGuards": True, "alignedError": 0, "sourceStable": True, "finalError": 0,
            "pack": {"available": True, "matches": True, "guards": True, "glError": 0,
                     "shortError": 0x502, "shortUnchanged": True} if version == 2 else absent()}


def gpu():
    return {"available": True, "advertised": ["shader-f16"], "enabled": ["shader-f16"], "format": "bgra8unorm",
            "copied": [0x12345678, 0, 0xFFFFFFFF, 0xABCDEF01], "copyMatches": True, "rgba": [191, 128, 64, 255],
            "canvasMatches": True, "validationError": None, "uncapturedErrors": []}


def audio():
    rendered = {"hash": HASH, "repeat": True, "finite": True, "nonzero": True, "zero": False, "rate": 44100, "length": 4096}
    return {"available": True, "first": deepcopy(rendered), "second": deepcopy(rendered),
            "silence": {**rendered, "zero": True, "nonzero": False},
            "boundary": {"mutable": True, "truncated": True, "beyondUnchanged": True,
                         "sourceStable": True, "otherChannelSilent": True, "rates": [48000, 48000],
                         "invalid": [{"index": i, "from": "IndexSizeError", "to": "IndexSizeError",
                                      "get": "IndexSizeError", "unchanged": True} for i in (2, -1)]},
            "wav": {"samples": [v / 32768 for v in (0, 8192, -8192, 16384, -16384, 32767, -32768, 0)],
                    "rate": 48000, "length": 8, "channels": 1, "repeat": True, "sourceBytes": 60}}


def codecs():
    rows = [{"mime": mime, "value": False} for mime in smoke.CODEC_TYPES]
    return {"available": True, "canPlay": [{"mime": mime, "value": ""} for mime in smoke.CODEC_TYPES],
            "mse": {"available": True, "values": deepcopy(rows)}, "recorder": {"available": True, "values": rows},
            "capabilities": {"available": True,
                             "decoding": [{"supported": False, "smooth": False, "powerEfficient": False},
                                          {"supported": True, "smooth": True, "powerEfficient": False}],
                             "encoding": [{"supported": False, "smooth": False, "powerEfficient": False},
                                          {"supported": False, "smooth": False, "powerEfficient": False}]}}


def network():
    return {"available": True, "ok": True, "status": 200, "body": "chromix-loopback-timing", "entries": [
        {"name": "http://127.0.0.1:8765/timing?surface=1", "initiatorType": "fetch", "startTime": 10,
         "responseStart": 11, "responseEnd": 12, "duration": 2, "transferSize": 322, "encodedBodySize": 22, "decodedBodySize": 22}]}


def surfaces():
    result = {name: {"canvas": canvas()} for name in smoke.SCOPES}
    result["window"].update(webgl1=gl(1), webgl2=gl(2), webgpu=gpu(), audio=audio(), codecs=codecs(), network=network())
    return result


def test_complete_fixture_and_explicit_skips_are_not_runtime_evidence():
    assert not failures(smoke.evaluate_surfaces(surfaces()))
    checks = smoke.evaluate_surfaces(surface_absent())
    assert len(checks) == 9
    assert all(check["status"] == "not_supported" for check in checks)
    report = smoke.finalize_report({"scenarios": [], "checks": checks, "failures": [], "verification": {"runtime_verified": False}})
    assert report["status"] == "failed"
    assert report["verification"]["runtime_verified"] is False


@pytest.mark.parametrize("category", ["canvas", "webgl1", "webgl2", "webgpu", "audio", "codecs", "network"])
@pytest.mark.parametrize("broken", [None, {}, {"available": False}, {"available": False, "reason": " "},
                                   {"available": False, "reason": 1}, {"available": False, "reason": "unsupported", "error": {}},
                                   {"error": {"name": "OperationError"}}, {"available": True, "error": None}])
def test_missing_and_exception_never_become_unsupported(category, broken):
    sample = surfaces()
    sample["window"][category] = broken
    checks = smoke.evaluate_surfaces(sample)
    assert failures(checks)
    assert not any(c["name"] == "surfaces.window." + category and c["status"] == "not_supported" for c in checks)


@pytest.mark.parametrize("scope", smoke.SCOPES)
def test_missing_scope_fails(scope):
    sample = surfaces()
    del sample[scope]
    assert failures(smoke.evaluate_surfaces(sample))


def true_paths(value, prefix=()):
    paths = []
    if isinstance(value, dict):
        for key, child in value.items():
            if child is True and key != "available":
                paths.append(prefix + (key,))
            elif isinstance(child, (dict, list)):
                paths.extend(true_paths(child, prefix + (key,)))
    elif isinstance(value, list):
        for i, child in enumerate(value):
            paths.extend(true_paths(child, prefix + (i,)))
    return paths


# Native codec support booleans are observations, not mandatory support assertions.
ASSERTED_PATHS = [path for path in true_paths(surfaces()) if "codecs" not in path]


@pytest.mark.parametrize("path", ASSERTED_PATHS, ids=lambda path: ".".join(map(str, path)))
def test_every_positive_invariant_rejects_false(path):
    sample = surfaces()
    parent = sample
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = False
    assert failures(smoke.evaluate_surfaces(sample))


@pytest.mark.parametrize("key", ["exports", "bitmap", "float16"])
def test_canvas_missing_nested_probe_is_failure(key):
    sample = canvas()
    del sample[key]
    assert failures(smoke.evaluate_canvas_surface(sample, "canvas"))


def test_canvas_decoded_readback_is_not_compared_to_export_or_single_read_pixels():
    sample = canvas()
    assert sample["bitmap"]["decodedReadbackHash"] != sample["pixelHash"]
    assert not failures(smoke.evaluate_canvas_surface(sample, "canvas"))
    sample["exports"]["dataURL"]["hash"] = "c" * 64
    assert "canvas.dataURL.hash" in failures(smoke.evaluate_canvas_surface(sample, "canvas"))


@pytest.mark.parametrize("scope", ["iframe", "worker"])
@pytest.mark.parametrize("field", ["pixelHash", "exports"])
def test_canvas_cross_scope_read_and_png_paths_match(scope, field):
    sample = surfaces()
    if field == "exports":
        sample[scope]["canvas"][field]["hash"] = "f" * 64
    else:
        sample[scope]["canvas"][field] = "f" * 64
    assert failures(smoke.evaluate_surfaces(sample))


@pytest.mark.parametrize("field,value", [("pendingError", 0), ("finalError", 0x502), ("drawError", 0x502),
                                         ("extensions", ["duplicate", "duplicate"]), ("pixelHash", "mock")])
def test_webgl_contract_counterexamples(field, value):
    sample = gl(2)
    sample[field] = value
    assert failures(smoke.evaluate_gl_surface(sample, "gl", 2))


def test_pack_is_mandatory_if_webgl2_exists():
    sample = gl(2)
    sample["pack"] = absent()
    assert "gl.pack.required" in failures(smoke.evaluate_gl_surface(sample, "gl", 2))
    sample["pack"] = {"available": True, "matches": True, "guards": True, "glError": 0, "shortError": 0, "shortUnchanged": True}
    assert failures(smoke.evaluate_gl_surface(sample, "gl", 2))


@pytest.mark.parametrize("field,value", [("enabled", []), ("format", "rgba16float"), ("copied", [1, 2, 3, 4]),
                                         ("rgba", [0, 0, 0, 0]), ("validationError", "request rejected"),
                                         ("uncapturedErrors", ["device error"])])
def test_webgpu_advertised_must_be_requestable_and_work(field, value):
    sample = gpu()
    sample[field] = value
    assert failures(smoke.evaluate_webgpu_surface(sample, "gpu"))


@pytest.mark.parametrize("field,value", [("samples", [0] * 8), ("samples", [math.nan] * 8), ("rate", 44100),
                                         ("length", 9), ("channels", 2), ("sourceBytes", 0)])
def test_wav_requires_actual_pcm_decode(field, value):
    sample = audio()
    sample["wav"][field] = value
    assert failures(smoke.evaluate_audio_surface(sample, "audio"))


def test_graph_render_repeat_and_copy_exception_required():
    sample = audio()
    sample["second"]["hash"] = "c" * 64
    sample["boundary"]["invalid"][0]["to"] = None
    checks = smoke.evaluate_audio_surface(sample, "audio")
    assert {"audio.graph_repeat", "audio.boundary.invalid_0"} <= failures(checks)


@pytest.mark.parametrize("field", ["canPlay", "mse", "recorder", "decoding", "encoding"])
def test_invalid_codec_cannot_claim_support(field):
    sample = codecs()
    if field == "canPlay":
        sample[field][0]["value"] = "probably"
    elif field in ("mse", "recorder"):
        sample[field]["values"][0]["value"] = True
    else:
        sample["capabilities"][field][0]["supported"] = True
    assert failures(smoke.evaluate_codec_surface(sample, "codecs"))


def test_encoding_decoding_are_independent_native_observations():
    sample = codecs()
    assert sample["capabilities"]["decoding"] != sample["capabilities"]["encoding"]
    assert not failures(smoke.evaluate_codec_surface(sample, "codecs"))


@pytest.mark.parametrize("field,value", [("responseEnd", -1), ("responseStart", 20), ("duration", 100),
                                         ("transferSize", -1), ("name", "https://external.invalid/timing"),
                                         ("initiatorType", "script")])
def test_resource_timing_counterexamples(field, value):
    sample = network()
    sample["entries"][0][field] = value
    assert failures(smoke.evaluate_network_surface(sample, "network"))


def events():
    return {scope: {"initial": {"online": True}, "offline": {"online": False, "events": [{"type": "offline", "online": False}]},
                    "restored": {"online": True, "events": [{"type": "offline", "online": False}, {"type": "online", "online": True}]}}
            for scope in ("window", "iframe")}


@pytest.mark.parametrize("phase", ["initial", "offline", "restored"])
def test_network_requires_real_transition_and_restore(phase):
    sample = events()
    assert not failures(smoke.evaluate_network_events(sample))
    sample["window"][phase]["online"] = None
    assert failures(smoke.evaluate_network_events(sample))
    sample = events()
    sample["iframe"]["restored"]["events"] = []
    assert failures(smoke.evaluate_network_events(sample))


def test_network_restoration_is_finally_even_on_probe_exception(monkeypatch):
    calls = []
    page = SimpleNamespace(frame=lambda **kw: object())
    def evaluate(target, script, argument, timeout):
        if script == smoke.NETWORK_EVENT_READ:
            raise RuntimeError("probe failed")
        return {"online": True}
    monkeypatch.setattr(smoke, "evaluate", evaluate)
    with pytest.raises(RuntimeError, match="probe failed"):
        smoke.collect_network_events(SimpleNamespace(set_offline=calls.append), page, "http://127.0.0.1:80", 100)
    assert calls == [True, False]


def test_dynamic_surface_network_excluded_from_restart_identity():
    first = {**observation(), "surfaces": surfaces(), "network_events": events()}
    other = deepcopy(first)
    other["surfaces"]["window"]["network"]["entries"][0]["duration"] = 100
    other["network_events"] = {}
    assert smoke.stable_identity(first) == smoke.stable_identity(other)
    other["surfaces"]["worker"]["canvas"]["pixelHash"] = "c" * 64
    assert smoke.stable_identity(first) != smoke.stable_identity(other)


@pytest.mark.parametrize("category", ["canvas", "audio"])
def test_legacy_signal_skip_requires_explicit_reason_without_error(category):
    for broken in ({"available": False}, {"available": False, "reason": "absent", "error": {"name": "Error"}}):
        assert category + ".completed" in failures(smoke.evaluate_signals({category: broken}))


def test_media_exceptions_not_skips_and_no_unconfirmed_capture():
    sample = {"permissions": {key: {"available": True, "state": "denied"} for key in ("camera", "microphone", "notifications")},
              "deviceProbe": {"available": True}, "devices": [], "devicesError": None,
              "permissionGrantsByRunner": 0, "deniedDocument": True,
              "origin": "http://127.0.0.1:9876", "secureContext": True,
              "policyAllows": {"camera": False, "microphone": False}, "capture": {
                  key: {"exception": {"name": "NotAllowedError"}} for key in ("camera", "microphone")}}
    assert not failures(smoke.evaluate_media(sample, True))
    for name in ("camera", "microphone"):
        for exception in ("NotFoundError", "NotReadableError", "TypeError"):
            broken = deepcopy(sample)
            broken["capture"][name] = {"exception": {"name": exception}}
            assert f"media.denied.{name}.capture_rejected" in failures(smoke.evaluate_media(broken, True))
        for state in ("prompt", "granted"):
            broken = deepcopy(sample)
            broken["permissions"][name]["state"] = state
            assert f"media.denied.{name}.policy_denied" in failures(smoke.evaluate_media(broken, True))
        for capture in ({"unexpectedSuccess": True}, {"timeout": True}, {"notRun": "not denied"}):
            broken = deepcopy(sample)
            broken["capture"][name] = capture
            assert f"media.denied.{name}.capture_rejected" in failures(smoke.evaluate_media(broken, True))
    for field, value in (("origin", "null"), ("secureContext", False)):
        broken = deepcopy(sample)
        broken[field] = value
        assert "media.denied.nonopaque_secure_context" in failures(smoke.evaluate_media(broken, True))
    sample["permissions"]["camera"] = {"error": {"name": "OperationError"}}
    sample["deviceProbe"] = {"error": {"name": "OperationError"}}
    assert failures(smoke.evaluate_media(sample, True))
    assert not any(c["status"] == "not_supported" for c in smoke.evaluate_media(sample, True))
    sample["deviceProbe"] = {"available": True}
    sample["policyAllows"]["camera"] = None
    assert "media.denied.camera.capture" in failures(smoke.evaluate_media(sample, True))


NODE_SUPPORT = r'''
const vm = require('node:vm');
const assert = require('node:assert/strict');
const crypto = require('node:crypto').webcrypto;
function realm(fault = '') {
  const stats = {reads:0, blobs:0, bitmaps:0, transfers:0, renders:0, decodes:0, graphs:0,
    shaders:0,draws:0,glReads:0,configures:0,maps:0,devices:0,deviceDestroyed:0,codecDecodes:0,codecEncodes:0};
  const exception = () => { const e = new Error('invalid index'); e.name = 'IndexSizeError'; throw e; };
  const noisy = input => {
    const a = new Uint8ClampedArray(input);
    for (let i = 0; i < a.length; i += 4) if (a[i + 3]) a[i] = Math.min(255, a[i] + 1);
    return a;
  };
  function mockGL(version) {
    const state={error:0,alignment:4,row:0,skipRows:0,skipPixels:0,shaderCount:0};
    const constants={NO_ERROR:0,INVALID_ENUM:0x500,INVALID_VALUE:0x501,INVALID_OPERATION:0x502,
      VERTEX_SHADER:1,FRAGMENT_SHADER:2,COMPILE_STATUS:3,LINK_STATUS:4,ARRAY_BUFFER:5,STATIC_DRAW:6,FLOAT:7,
      TRIANGLES:8,RGBA:9,UNSIGNED_BYTE:10,PACK_ALIGNMENT:11,PACK_ROW_LENGTH:12,PACK_SKIP_ROWS:13,PACK_SKIP_PIXELS:14};
    const gl={...constants,getError(){const e=state.error;state.error=0;return e;},getSupportedExtensions:()=>['OES_example'],
      getExtension:()=>fault==='extension-unrequestable'?null:{},createShader:()=>({}),
      shaderSource(shader,source){assert(source.includes('void main'));if(version==='webgl2')assert(source.startsWith('#version 300 es'));},
      compileShader(){state.shaderCount++;stats.shaders++;},getShaderParameter:()=>fault!=='shader-fails',
      getShaderInfoLog:()=> 'mock shader error',createProgram:()=>({}),attachShader(){},linkProgram(){},
      getProgramParameter:()=>true,useProgram(){},createBuffer:()=>({}),bindBuffer(){},bufferData(target,data){assert.equal(data.length,6);},
      getAttribLocation:()=>0,enableVertexAttribArray(){},vertexAttribPointer(){},viewport(){},
      drawArrays(){assert.equal(state.shaderCount,2);stats.draws++;},
      enable(){state.error=0x500;},pixelStorei(key,value){
        if(key===11)state.alignment=value;if(key===12)state.row=value;if(key===13)state.skipRows=value;if(key===14)state.skipPixels=value;
      },
      readPixels(x,y,w,h,format,type,dst,offset=0){
        stats.glReads++;
        if(w<0||format!==9){state.error=w<0?0x501:0x500;if(fault==='invalid-pollution')dst[0]=0;return;}
        const rowBytes=(state.row||w)*4,stride=Math.ceil(rowBytes/state.alignment)*state.alignment;
        const start=offset+state.skipRows*stride+state.skipPixels*4;
        if(start+(h-1)*stride+w*4>dst.length){state.error=0x502;if(fault==='short-pollution')dst[0]=0;return;}
        if(fault==='pending-swallowed')state.error=0;
        for(let row=0;row<h;row++)for(let col=0;col<w*4;col++)dst[start+row*stride+col]=[64,128,191,255][col%4];
        if(fault==='pack-guard'&&state.skipRows)dst[0]=0;
        if(fault==='pack-row'&&state.skipRows)dst[start]^=1;
        if(fault==='alignment-guard'&&w===3)dst[12]=0;
        if(fault==='shader-empty')dst.fill(0);
      },deleteBuffer(){},deleteShader(){},deleteProgram(){}};
    return gl;
  }
  function mockGPU() {
    const bufferUsage={COPY_SRC:1,COPY_DST:2,MAP_READ:4}, textureUsage={RENDER_ATTACHMENT:1,COPY_SRC:2};
    let configured=false,errorScope=false;
    const gpuContext={configure(config){assert.equal(config.format,'bgra8unorm');assert.equal(config.usage,3);configured=true;stats.configures++;},
      getCurrentTexture(){assert(configured);return {createView:()=>({})};},unconfigure(){configured=false;}};
    const device={features:new Set(['shader-f16']),addEventListener(){},pushErrorScope(kind){assert.equal(kind,'validation');errorScope=true;},
      popErrorScope:async()=>fault==='gpu-validation'?{message:'mock validation failure'}:null,
      createBuffer({size,usage}){
        const bytes=new ArrayBuffer(size);let mapped=false;
        return {bytes,usage,async mapAsync(mode){assert.equal(mode,1);assert(usage&4);if(fault==='gpu-map-fails')throw new Error('map failed');mapped=true;stats.maps++;},
          getMappedRange(){assert(mapped);return bytes;},unmap(){mapped=false;},destroy(){}};
      },
      createCommandEncoder(){
        assert(errorScope);const commands=[];
        return {beginRenderPass({colorAttachments}){assert.equal(colorAttachments[0].clearValue.r,.25);return {end(){}};},
          copyBufferToBuffer(src,so,dst,dof,size){assert(src.usage&1);assert(dst.usage&2);
            commands.push(()=>new Uint8Array(dst.bytes,dof,size).set(new Uint8Array(src.bytes,so,size)));},
          copyTextureToBuffer(src,dst,size){assert.equal(dst.bytesPerRow,256);assert.equal(size.width,1);
            commands.push(()=>new Uint8Array(dst.buffer.bytes).set(fault==='gpu-canvas-wrong'?[0,0,0,0]:[191,128,64,255]));},
          finish(){return commands;}};
      },
      queue:{writeBuffer(dst,offset,words){new Uint8Array(dst.bytes,offset).set(new Uint8Array(words.buffer));},
        submit(lists){for(const commands of lists)for(const command of commands)command();}},destroy(){stats.deviceDestroyed++;}};
    return {bufferUsage,textureUsage,gpuContext,gpu:{getPreferredCanvasFormat:()=> 'bgra8unorm',
      requestAdapter:async()=>({features:new Set(['shader-f16']),requestDevice:async({requiredFeatures})=>{
        assert.deepEqual(Array.from(requiredFeatures),['shader-f16']);stats.devices++;return device;
      }})}};
  }
  let gpuMock;
  class Canvas {
    constructor(w=16,h=12) { this.width=w; this.height=h; this.pixels=new Uint8ClampedArray(768); }
    getContext(kind) {
      if (kind !== '2d') {
        if (fault === 'gl-throws') throw new Error('GL backend failure');
        if (kind === 'webgpu') return gpuMock.gpuContext;
        return mockGL(kind);
      }
      if (fault === 'canvas-throws') throw new Error('2D backend failure');
      if (fault === 'canvas-absent') return null;
      const canvas = this;
      return {
        fillStyle:'', fillRect(x,y,w,h) {
          const color = this.fillStyle === '#234567' ? [35,69,103,255] : [171,193,35,255];
          for (let j=y;j<y+h;j++) for(let i=x;i<x+w;i++) canvas.pixels.set(color, (j*16+i)*4);
        },
        getImageData(x,y,w,h,options) {
          stats.reads++;
          if (!w || !h) exception();
          if (options && fault === 'f16-throws') throw new Error('float16 read failed');
          const data = new Uint8ClampedArray(w*h*4), source = noisy(canvas.pixels);
          for(let j=0;j<h;j++) for(let i=0;i<w;i++) if(x+i>=0 && x+i<16 && y+j>=0 && y+j<12)
            data.set(source.slice(((y+j)*16+x+i)*4, ((y+j)*16+x+i)*4+4), (j*w+i)*4);
          if (fault === 'crop' && w===7) data[0] ^= 1;
          if (fault === 'outside' && x<0) data[0]=1;
          if (fault === 'source-mutation') canvas.pixels[4*35] ^= 2;
          if (options) return {data:Float32Array.from(data, v=>v/255),pixelFormat:'rgba-float16'};
          return {data};
        },
        drawImage(image) { canvas.pixels.set(image.pixels); }
      };
    }
    png() {
      const bytes=new Uint8Array(33+768), view=new DataView(bytes.buffer);
      bytes.set([137,80,78,71,13,10,26,10]); view.setUint32(8,13);view.setUint32(12,0x49484452);
      view.setUint32(16,16);view.setUint32(20,12);bytes.set(noisy(this.pixels),33);
      return bytes;
    }
    toDataURL() { return 'data:image/png;base64,' + Buffer.from(this.png()).toString('base64'); }
    toBlob(callback) {
      stats.blobs++;
      if(fault === 'blob-null') { callback(null); return; }
      const bytes=this.png(); if(fault === 'export-mismatch') bytes[33] ^= 1;
      callback(new Blob([bytes],{type:'image/png'}));
    }
  }
  class Offscreen extends Canvas {
    constructor(...args) {super(...args);this.toDataURL=undefined;this.toBlob=undefined;}
    async convertToBlob() { stats.blobs++; return new Blob([this.png()], {type:'image/png'}); }
    transferToImageBitmap() {
      stats.transfers++;
      const b={width:16,height:12,pixels:new Uint8ClampedArray(this.pixels),close(){}};
      this.pixels.fill(0); return b;
    }
  }
  class AudioBuffer {
    constructor(channels,length,rate) {this.numberOfChannels=channels;this.length=length;this.sampleRate=rate;
      this.channels=Array.from({length:channels},()=>new Float32Array(length));}
    getChannelData(index) {if(index<0 || index>=this.numberOfChannels) exception();return this.channels[index];}
    copyFromChannel(dst,index,offset=0) {
      const src=this.getChannelData(index);if(offset>=src.length)return;
      dst.set(src.slice(offset,offset+dst.length));
    }
    copyToChannel(src,index,offset=0) {
      const dst=this.getChannelData(index);if(offset>=dst.length)return;
      dst.set(src.slice(0,dst.length-offset),offset);
    }
  }
  class OfflineAudioContext {
    constructor(channels,length,rate) {this.channels=channels;this.length=length;this.sampleRate=rate;this.destination={};this.active=false;}
    createBuffer(c,l,r) {return new AudioBuffer(c,l,r);}
    createOscillator() {stats.graphs++;this.active=true;return {frequency:{value:0},connect(){},start(){},stop(){}};}
    createDynamicsCompressor() {return {connect(){}};}
    async startRendering() {
      stats.renders++; const b=this.createBuffer(1,this.length,this.sampleRate);
      if(this.active)b.channels[0].set(Float32Array.from({length:this.length},(_,i)=>Math.sin(i/9)*.25));
      if(fault==='graph-nondeterministic' && stats.renders===2)b.channels[0][100]=.4;
      if(fault==='silence-noise' && !this.active)b.channels[0][10]=.001;
      return b;
    }
    async decodeAudioData(bytes) {
      stats.decodes++;
      if(fault==='decode-throws')throw new Error('decoder backend failed');
      const v=new DataView(bytes);
      assert.equal(Buffer.from(bytes).subarray(0,4).toString(),'RIFF');assert.equal(v.getUint32(4,true),52);
      assert.equal(v.getUint32(24,true),48000);assert.equal(v.getUint16(22,true),1);assert.equal(v.getUint16(34,true),16);
      const b=this.createBuffer(1,v.getUint32(40,true)/2,this.sampleRate);
      for(let i=0;i<b.length;i++)b.channels[0][i]=v.getInt16(44+i*2,true)/32768;
      if(fault==='decode-wrong')b.channels[0].fill(0);
      return b;
    }
  }
  const env={crypto, Blob, Uint8Array,Uint8ClampedArray,Float32Array,Uint32Array,ArrayBuffer,DataView,Float16Array:Float32Array,
    URL,Array,Number, atob:s=>Buffer.from(s,'base64').toString('binary'),OffscreenCanvas:Offscreen, OfflineAudioContext,
    navigator:{}, location:{href:'http://127.0.0.1:8765/'},
    document:{createElement:type=>type==='canvas'?new Canvas():{canPlayType:mime=>fault==='codec-lie'?'probably':''}},
    performance:{now:()=>1,getEntriesByName:url=>[{name:url,initiatorType:'fetch',startTime:10,responseStart:11,responseEnd:12,
      duration:2,transferSize:322,encodedBodySize:22,decodedBodySize:22}]},
    fetch:async(url,opts)=>{assert.equal(new URL(url).hostname,'127.0.0.1');assert.equal(opts.redirect,'error');
      assert.equal(opts.mode,'same-origin');return {ok:true,status:200,text:async()=> 'chromix-loopback-timing'};},
    createImageBitmap:async input=>{
      stats.bitmaps++;
      const pixels=input instanceof Blob ? new Uint8ClampedArray(await input.arrayBuffer()).slice(33) : new Uint8ClampedArray(input.pixels);
      if(fault==='bitmap')pixels[40]^=1;
      return {width:16,height:12,pixels,close(){}};
    }};
  gpuMock=mockGPU();
  env.MediaSource={isTypeSupported:mime=>fault==='mse-lie'||mime.includes('opus')};
  env.MediaRecorder={isTypeSupported:mime=>fault==='recorder-lie'||mime.includes('vp8')};
  env.navigator.mediaCapabilities={
    decodingInfo:async config=>{
      assert.equal(config.type,'file');stats.codecDecodes++;
      if(fault==='capability-throws')throw new Error('capability backend failed');
      return {supported:config.audio.contentType.includes('opus'),smooth:false,powerEfficient:false};
    },
    encodingInfo:async config=>{
      assert.equal(config.type,'webrtc');stats.codecEncodes++;
      assert(['audio/x-chromix-invalid', 'audio/opus'].includes(config.audio.contentType));
      assert.equal(config.audio.channels,'2');assert.equal(config.audio.samplerate,48000);
      return {supported:fault==='capability-lie',smooth:false,powerEfficient:false};}
  };
  env.navigator.gpu=gpuMock.gpu;env.GPUBufferUsage=gpuMock.bufferUsage;env.GPUTextureUsage=gpuMock.textureUsage;env.GPUMapMode={READ:1};
  if(fault==='gpu-no-adapter')env.navigator.gpu={requestAdapter:async()=>null};
  if(fault==='gpu-throws')env.navigator.gpu={requestAdapter:async()=>{throw new Error('adapter backend failure');}};
  if(fault==='gpu-request-throws')env.navigator.gpu={requestAdapter:async()=>({features:new Set(['shader-f16']),
    requestDevice:async()=>{throw new Error('advertised feature not requestable');}})};
  return {env,stats};
}
'''


def node_run(script):
    node = str(NODE) if NODE.is_file() else shutil.which("node")
    if not node:
        pytest.skip("Node unavailable; this test is not browser verification")
    source = "const source = " + json.dumps(smoke.SURFACE_ASSET.read_text()) + ";\n" + NODE_SUPPORT + script
    result = subprocess.run([node, "-"], input=source, text=True, capture_output=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout)


def test_node_surface_execution_and_counterexamples_are_not_browser_evidence():
    result = node_run(r'''
(async()=>{
  new vm.Script(source);
  const rows={};
  for(const fault of ['', 'canvas-absent','canvas-throws','gl-throws','crop','outside','source-mutation','blob-null',
      'export-mismatch','bitmap','f16-throws','graph-nondeterministic','silence-noise','decode-throws','decode-wrong',
      'codec-lie','gpu-no-adapter','gpu-throws','gpu-request-throws','gpu-validation','gpu-map-fails','gpu-canvas-wrong',
      'extension-unrequestable','shader-fails','invalid-pollution','short-pollution','pending-swallowed','pack-guard',
      'pack-row','alignment-guard','shader-empty','mse-lie','recorder-lie','capability-throws','capability-lie']) {
    const {env,stats}=realm(fault);vm.runInNewContext(source,env);
    rows[fault]={result:await env.fingerprintSurfaceProbe('all'),stats};
  }
  const {env,stats}=realm();delete env.document;vm.runInNewContext(source,env);
  rows.worker={result:await env.fingerprintSurfaceProbe('canvas'),stats};
  console.log(JSON.stringify(rows));
})().catch(e=>{console.error(e);process.exitCode=1;});
''')
    good = result[""]["result"]
    sample = {"window": good, "iframe": {"canvas": good["canvas"]}, "worker": result["worker"]["result"]}
    assert not failures(smoke.evaluate_surfaces(sample))
    assert result[""]["stats"]["renders"] == 3
    assert result[""]["stats"]["graphs"] == 2
    assert result[""]["stats"]["decodes"] == 2
    assert result[""]["stats"]["bitmaps"] == 3
    assert result[""]["stats"]["shaders"] == 4
    assert result[""]["stats"]["draws"] == 2
    assert result[""]["stats"]["glReads"] >= 14
    assert result[""]["stats"]["configures"] == 1
    assert result[""]["stats"]["maps"] == 2
    assert result[""]["stats"]["devices"] == result[""]["stats"]["deviceDestroyed"] == 1
    assert result[""]["stats"]["codecDecodes"] == result[""]["stats"]["codecEncodes"] == 2
    assert result["worker"]["stats"]["transfers"] == 1
    assert result["worker"]["result"]["canvas"]["exports"]["dataURL"]["available"] is False
    for fault, row in result.items():
        if fault in ("", "worker", "canvas-absent", "gpu-no-adapter"):
            continue
        broken = deepcopy(sample)
        broken["window"] = row["result"]
        assert failures(smoke.evaluate_surfaces(broken)), fault
    for fault, category in (("canvas-throws", "canvas"), ("gl-throws", "webgl1"),
                            ("decode-throws", "audio"), ("gpu-throws", "webgpu"), ("gpu-request-throws", "webgpu")):
        assert "error" in result[fault]["result"][category]
        assert "available" not in result[fault]["result"][category]
    assert good["canvas"]["bitmap"]["decodedReadbackHash"] != good["canvas"]["pixelHash"]
