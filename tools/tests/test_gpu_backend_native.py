"""Final native methods with dependency shims; NOT a Chromium/GPU build.

Independent pinned source hashes and the complete file-specific predecessor
chains are required when CHROMIX_GPU_POLICY_UPSTREAM_ROOT is configured.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from types import SimpleNamespace

import pytest

import test_fingerprint_canvas as canvas
import test_fingerprint_gpu as gpu
from test_fingerprint_config import config_binary
from test_canvas_native_paths import apply, patch_path
from test_fingerprint_features import block

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).with_name('fixtures')
EVIDENCE = json.loads((FIXTURES/'gpu_backend_sources.json').read_text(encoding='utf-8'))


@pytest.fixture(scope='module')
def final_sources(tmp_path_factory):
    result = {}
    for number,item in EVIDENCE['patches'].items():
        directory = tmp_path_factory.mktemp('gpu-policy-source-'+number)
        lines=[]
        for section in item['sections']:
            start=section['line']-1
            assert start >= len(lines)
            lines.extend('// unrelated pinned source line\n' for _ in range(start-len(lines)))
            lines.extend(section['text'].splitlines(True))
        original=''.join(lines)+'// not EOF\n'
        path=directory/item['target'];path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(original.encode())
        patch=patch_path(number)
        assert hashlib.sha256(patch.read_bytes()).hexdigest() == item['patch_sha256']
        apply(directory,patch)
        result[number]=path.read_text(encoding='utf-8')
        apply(directory,patch,reverse=True)
        assert path.read_bytes() == original.encode()
    return result


@pytest.mark.parametrize('number',EVIDENCE['patches'])
def test_final_patch_roundtrip(final_sources,number):
    assert final_sources[number]


@pytest.fixture(scope='module')
def integrated_sources(tmp_path_factory):
    supplied=os.environ.get('CHROMIX_GPU_POLICY_UPSTREAM_ROOT')
    if not supplied: pytest.skip('independent pinned GPU policy source root required')
    directory=tmp_path_factory.mktemp('gpu-policy-integrated')
    targets={v['target'] for v in EVIDENCE['patches'].values()}
    targets.add('components/ungoogled/persona_profile.h')
    for target,item in EVIDENCE['sources'].items():
        path=Path(supplied)/target;data=path.read_bytes()
        assert hashlib.sha256(data).hexdigest() == item['upstream_sha256']
        dest=directory/target;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data)
    assert EVIDENCE['core_commit'] == 'e71b91c6e336d0f25cfc6b9ef09298a9d2506e24'
    for i,item in enumerate(EVIDENCE['core_inputs']):
        fragment=directory/f'core-{i}.patch';fragment.write_bytes(item['target_fragment'].encode())
        apply(directory,fragment)
    for name in (ROOT/'patches/series').read_text().splitlines():
        if not name or name.startswith('#'): continue
        patch=ROOT/name;raw=patch.read_text(encoding='utf-8')
        target=re.search(r'^\+\+\+ b/(.*)$',raw,re.M)[1]
        if target not in targets: continue
        number=patch.name[:4]
        if number in EVIDENCE['patches']:
            item=EVIDENCE['patches'][number]
            assert hashlib.sha256(patch.read_bytes()).hexdigest() == item['patch_sha256']
            before=(directory/target).read_bytes()
            assert hashlib.sha256(before).hexdigest() == item['preimage_sha256']
            lines=before.decode('utf-8').splitlines(True)
            for section in item['sections']:
                start=section['line']-1
                assert ''.join(lines[start:start+len(section['text'].splitlines())]) == section['text']
        apply(directory,patch,allow_offsets=int(number)<158)
        if number in EVIDENCE['patches']:
            assert hashlib.sha256((directory/target).read_bytes()).hexdigest() == EVIDENCE['patches'][number]['output_sha256']
    for target,item in EVIDENCE['sources'].items():
        assert hashlib.sha256((Path(supplied)/target).read_bytes()).hexdigest() == item['upstream_sha256']
    buffer=(directory/'third_party/blink/renderer/modules/webgpu/gpu_buffer.cc').read_text(encoding='utf-8')
    assert block(buffer,'void GPUBuffer::OnMapAsyncCallback(') == EVIDENCE['map_async_callback']
    return {target:(directory/target).read_text(encoding='utf-8') for target in targets}


def test_independently_acquired_source_and_final_methods(integrated_sources):
    assert len(integrated_sources) == 8


@pytest.fixture(scope='module')
def policy_binary(config_binary,tmp_path_factory):
    directory=tmp_path_factory.mktemp('gpu-config')/'src'
    shutil.copytree(config_binary.parent,directory)
    # The reused dependency shim writes native Windows newlines. Patch inputs
    # have canonical LF bytes; never relax --binary or the preimage assertion.
    for number in ('0158','0159'):
        target=directory/EVIDENCE['patches'][number]['target']
        target.write_bytes(target.read_text(encoding='utf-8').encode('utf-8'))
        assert hashlib.sha256(target.read_bytes()).hexdigest() == EVIDENCE['patches'][number]['preimage_sha256']
        apply(directory,patch_path(number))
    source=directory/'policy.cc'
    source.write_text(r'''
#include "base/uxr_config.h"
#include <cassert>
#include <iostream>
#include <thread>
#include <vector>
int main(int argc, char** argv) {
  auto& c=base::UxrConfig::GetInstance();
  if(argc==2 && std::string(argv[1])=="freeze") {
    assert(c.SetAll({{"uxr-gpu-backend","native"}}));
    auto copy=c.GpuBackendPolicy(); copy.native=false;
    assert(!copy.native);
    assert(c.GpuBackendPolicy().native);
    std::vector<std::thread> threads;
    for(int i=0;i<8;++i) threads.emplace_back([&] {
      for(int n=0;n<100;++n) {
        assert(c.SetAll({{"uxr-gpu-backend","native"}}));
        assert(!c.SetAll({{"uxr-gpu-backend","compatibility"}}));
        auto policy=c.GpuBackendPolicy();
        assert(policy.native && !policy.canvas_pixel_noise && !policy.canvas_bridge);
      }
    });
    for(auto& t:threads)t.join();
    std::cout<<"frozen";return 0;
  }
  base::flat_map<std::string,std::string> cfg;
  for(int i=1;i<argc;++i) {std::string s(argv[i]);auto pos=s.find('=');cfg[s.substr(0,pos)]=s.substr(pos+1);}
  bool accepted=c.SetAll(cfg);auto p=c.GpuBackendPolicy();
  std::cout<<accepted<<' '<<c.IsInitialized()<<' '<<p.native<<' '<<p.canvas_pixel_noise<<' '
           <<p.canvas_text_noise<<' '<<p.canvas_bridge<<' '<<p.capability_overrides;
  if(!accepted) {assert(c.Snapshot().empty());assert(!c.ValidationError().empty());assert(c.SetAll({}));}
}
''',encoding='utf-8')
    binary=directory/'policy'
    result=subprocess.run([canvas.CXX,'-std=c++20','-Wall','-Wextra','-Werror',*canvas.sanitizer_flags(),
        '-I',str(directory),str(directory/'base/uxr_config.cc'),str(source),'-o',str(binary)],capture_output=True,text=True,timeout=90)
    assert not result.returncode,result.stdout+result.stderr
    return binary


@pytest.mark.parametrize('mode,synthetic,disabled',[(m,s,d) for m in (None,'native','compatibility') for s in (None,'true','false') for d in (False,True)])
def test_one_policy_for_pixels_bridge_capabilities_and_text(policy_binary,mode,synthetic,disabled):
    args=[]
    if mode is not None:args.append('uxr-gpu-backend='+mode)
    if synthetic is not None:args.append('uxr-synthetic-device-tests='+synthetic)
    if disabled:args.append('uxr-disable-fingerprint-noise=false')  # presence is the existing disable contract
    native=mode=='native';allowed=not native and synthetic=='true'
    expected=[1,1,native,allowed and not disabled,not native and not disabled,allowed,not native]
    result=subprocess.run([str(policy_binary),*args],text=True,capture_output=True,env=canvas.sanitizer_env(),timeout=15)
    assert not result.returncode,result.stderr
    assert result.stdout.split() == [str(int(v)) for v in expected]


@pytest.mark.parametrize('mode',('', 'Native','native ','software','hardware','native,compatibility'))
def test_invalid_backend_is_atomic_not_a_silent_fallback(policy_binary,mode):
    result=subprocess.run([str(policy_binary),'uxr-gpu-backend='+mode],text=True,capture_output=True,env=canvas.sanitizer_env(),timeout=15)
    assert not result.returncode and result.stdout.split()[:2] == ['0','0']


def test_policy_replay_and_concurrent_reads_are_immutable(policy_binary):
    result=subprocess.run([str(policy_binary),'freeze'],text=True,capture_output=True,env=canvas.sanitizer_env(),timeout=15)
    assert not result.returncode and result.stdout == 'frozen'


def test_real_resource_paths_use_shared_policy_before_mutating_or_connecting(final_sources):
    assert final_sources['0160'].count('GpuBackendPolicy().canvas_pixel_noise') == 2
    assert 'GpuBackendPolicy().canvas_text_noise' in final_sources['0160']
    assert 'GpuBackendPolicy().canvas_pixel_noise' in final_sources['0161']
    bridge=final_sources['0162']
    assert bridge.index('GpuBackendPolicy().canvas_bridge') < bridge.index('!config.Has("uxr-canvas-bridge")')
    assert 'config.GpuBackendPolicy().native ||' in final_sources['0163']
    assert 'config.GpuBackendPolicy().capability_overrides &&' in final_sources['0164']
    lazy=final_sources['0165']
    assert '!snapshot && !HasAlpha() && !isContextLost() &&' in lazy
    assert 'UxrInitializeOpaqueReadback(image_data->GetSkPixmap(), Width(), Height(),' in lazy
    assert 'case wgpu::MapAsyncStatus::Aborted:\n      resolver->RejectWithDOMException(DOMExceptionCode::kAbortError,' in EVIDENCE['map_async_callback']


@pytest.fixture(scope='module')
def opaque_binary(tmp_path_factory,final_sources):
    if not canvas.CXX:pytest.skip('Clang required')
    directory=tmp_path_factory.mktemp('gpu-opaque-native');source=directory/'opaque.cc'
    original=final_sources['0165']
    definitions=block(original,'struct UxrOpaqueAlpha {')+';\n'
    definitions+=block(original,'std::optional<UxrOpaqueAlpha> UxrOpaqueAlphaForColorType(')+'\n'
    definitions+=block(original,'bool UxrInitializeOpaqueReadback(')+'\n'
    definitions+=block(original,'bool UxrCopyOpaqueImageData(')+'\n'
    source.write_text('#include <optional>\n'+(FIXTURES/'canvas_native_shim.h').read_text(encoding='utf-8')+'\n'+definitions+r'''
int main() {
  size_t checks=0;
  for(auto type:{kRGBA_8888_SkColorType,kBGRA_8888_SkColorType,kRGBA_F16_SkColorType,kRGBA_F32_SkColorType}) {
    const int component=SkColorTypeBytesPerPixel(type)/4;
    for(int x:{INT32_MIN,-8,-1,0,1,4,5,INT32_MAX}) for(int y:{INT32_MIN,-6,-1,0,1,3,4,INT32_MAX}) {
      SkImageInfo info{7,6,type,kUnpremul_SkAlphaType};size_t stride=info.minRowBytes()+16;
      std::vector<uint8_t> storage(stride*6,0xa5),expected=storage;
      SkPixmap pm(info,storage.data(),stride);
      assert(UxrInitializeOpaqueReadback(pm,5,4,x,y));
      for(int row=0;row<6;++row)for(int col=0;col<7;++col) {
        const int64_t sx=int64_t{x}+col,sy=int64_t{y}+row;
        if(sx>=0 && sy>=0 && sx<5 && sy<4)WriteComponent(expected.data()+row*stride+col*component*4+3*component,component,1.0f);
      }
      assert(storage==expected);++checks;
    }
    SkImageInfo info{3,2,type,kUnpremul_SkAlphaType};std::vector<uint8_t> bytes(info.minRowBytes()*2,0);
    SkPixmap pm(info,bytes.data(),info.minRowBytes());SkBitmap copy;
    assert(UxrCopyOpaqueImageData(pm,gfx::Rect(0,0,3,2),copy));
    assert(UxrInitializeOpaqueReadback(pm,3,2,0,0));
    const auto copied=gfx::SkPixmapToSpan(copy.pixmap());
    assert(copied.size()==bytes.size() && std::equal(bytes.begin(),bytes.end(),copied.data()));
  }
  SkImageInfo good{3,2,kRGBA_8888_SkColorType,kUnpremul_SkAlphaType};std::vector<uint8_t> bytes(256,0);
  assert(!UxrInitializeOpaqueReadback(SkPixmap(good,nullptr,12),3,2,0,0));
  assert(!UxrInitializeOpaqueReadback(SkPixmap(good,bytes.data(),8),3,2,0,0));
  assert(!UxrInitializeOpaqueReadback(SkPixmap(good,bytes.data(),SIZE_MAX-3),3,2,0,0));
  assert(!UxrInitializeOpaqueReadback(SkPixmap({3,2,kUnknown_SkColorType,kUnpremul_SkAlphaType},bytes.data(),12),3,2,0,0));
  assert(checks==256);std::cout<<checks;
}
''',encoding='utf-8')
    binary=directory/'opaque'
    result=subprocess.run([canvas.CXX,'-std=c++20','-O1','-g','-Wall','-Wextra','-Werror',*canvas.sanitizer_flags(),str(source),'-o',str(binary)],capture_output=True,text=True,timeout=90)
    assert not result.returncode,result.stdout+result.stderr
    return binary


def test_native_lazy_alpha_formats_clipping_extremes_and_upload_agreement(opaque_binary):
    result=subprocess.run([str(opaque_binary)],text=True,capture_output=True,env=canvas.sanitizer_env(),timeout=15)
    assert not result.returncode,result.stdout+result.stderr
    assert result.stdout == '256'


@pytest.fixture(scope='module')
def native_canvas_binary(tmp_path_factory,integrated_sources):
    base=integrated_sources['third_party/blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.cc']
    export=integrated_sources['third_party/blink/renderer/platform/graphics/image_data_buffer.cc']
    # Keep both actual Create overloads; the dependency shim supplies their
    # declarations, not replacement implementations of the allocation path.
    export=export[:export.index('base::span<const uint8_t> ImageDataBuffer::PixelData()')]+ '// not EOF\n'
    support=canvas.CPP_SUPPORT.replace('  bool synthetic = true;', '''  bool synthetic = true;
  bool native = false;
  struct Policy { bool canvas_pixel_noise; };
  Policy GpuBackendPolicy() const { return {!native && synthetic && !disabled}; }''')
    tests=canvas.CPP_TESTS.replace('  const std::string test = argv[1];','''  const std::string test = argv[1];
  if(test=="native-gpu-policy") {
    auto& config=base::UxrConfig::GetInstance();config.native=true;config.synthetic=true;config.disabled=false;
    for(auto type:{kRGBA_8888_SkColorType,kBGRA_8888_SkColorType,kRGBA_F16_SkColorType})
      for(auto alpha:{kUnpremul_SkAlphaType,kPremul_SkAlphaType,kOpaque_SkAlphaType}) {
        Fixture f(type,7,4,16);f.info.at=alpha;auto before=f.bytes;
        ImageData data{f.pm()};ReadNoise(&data,-1,2);assert(f.bytes==before);
        auto encoded=ImageDataBuffer::Create(f.pm());assert(encoded);
        assert(encoded->pixmap_.addr()==f.bytes.data());assert(encoded->pixmap_.info().alphaType()==alpha);
        assert(f.bytes==before);
        for(int mode:{0,1,2}) {
          auto image_encoded=ImageDataBuffer::Create(f.image(mode));assert(image_encoded);
          const auto& pixmap=image_encoded->pixmap_;
          assert(pixmap.info().alphaType()==(alpha==kOpaque_SkAlphaType ? kOpaque_SkAlphaType : kUnpremul_SkAlphaType));
          assert(pixmap.colorType()==type);
          for(int y=0;y<f.info.h;++y)
            assert(std::equal(f.bytes.begin()+size_t(y)*f.rb,
                              f.bytes.begin()+size_t(y)*f.rb+f.info.minRowBytes(),
                              static_cast<const uint8_t*>(pixmap.addr())+size_t(y)*pixmap.rowBytes()));
          assert(f.bytes==before);
        }
      }
    return 0;
  }''')
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(canvas,'CPP_SUPPORT',support);patch.setattr(canvas,'CPP_TESTS',tests)
        return canvas.runtime_binary.__wrapped__(tmp_path_factory,{'0020':base,'0031':export})


@pytest.mark.parametrize('case',('native-gpu-policy','default-native','native-alpha','transparent-oob','channels','padding','failures'))
def test_final_canvas_readback_export_methods(native_canvas_binary,case):
    result=subprocess.run([str(native_canvas_binary),case],text=True,capture_output=True,env=canvas.sanitizer_env(),timeout=15)
    assert not result.returncode,result.stdout+result.stderr


def policy_support():
    return gpu.CPP_SUPPORT.replace('struct UxrConfig {','''struct UxrConfig {
  struct Policy { bool native; bool capability_overrides; };
  Policy GpuBackendPolicy() const { bool native=Get("uxr-gpu-backend")=="native";return {native,!native}; }''',1)


@pytest.fixture(scope='module',params=gpu.SIMULATED_PLATFORMS)
def native_identity_binary(request,tmp_path_factory,integrated_sources):
    # Adapter identity constructor is pinned in the existing GPU suite; apply
    # its final native-identity follow-up rather than testing an old constructor.
    directory=tmp_path_factory.mktemp('gpu-native-adapter')
    target=directory/'third_party/blink/renderer/modules/webgpu/gpu_adapter_info.cc'
    target.parent.mkdir(parents=True);target.write_bytes(gpu.PINNED_0030_UPSTREAM.encode('utf-8'))
    for number in ('0030','0148'): apply(directory,patch_path(number))
    sources={number:integrated_sources['components/ungoogled/persona_profile.'+suffix]
             for number,suffix in (('0091','h'),('0092','cc'))}
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(gpu,'CPP_SUPPORT',policy_support())
        return gpu.identity_binary.__wrapped__(request,tmp_path_factory,{},target.read_text(encoding='utf-8'),sources)


@pytest.mark.parametrize('overrides',({}, {'uxr-fingerprint-seed':'42','uxr-webgl-vendor':'conflict','uxr-webgl-renderer':'conflict',
        'uxr-webgpu-vendor':'conflict','uxr-webgpu-architecture':'conflict','uxr-webgl-max-texture-size':'1'}))
def test_final_native_policy_keeps_real_adapter_and_capabilities(native_identity_binary,overrides):
    result=gpu.run_identity(native_identity_binary,{'uxr-gpu-backend':'native',**overrides},synthetic=True)
    gpu.assert_native_adapter(result)
    assert result['persona.webgl_real'] == '1'


@pytest.fixture(scope='module')
def native_features_binary(tmp_path_factory,integrated_sources):
    # Execute the actual request-feature negotiation method with the existing
    # Dawn/IDL dependency stubs, and preserve its negative feature tests.
    sources=gpu.patched_sources.__wrapped__(tmp_path_factory)
    sources['0041']=integrated_sources['third_party/blink/renderer/modules/webgpu/gpu_adapter.cc']
    tests=gpu.CPP_TESTS.replace('  auto& config = base::UxrConfig::GetInstance();','''  auto& config = base::UxrConfig::GetInstance();
  if(mode=="features-native-policy") {
    config.values["uxr-gpu-backend"]="native";
    config.values["uxr-webgpu-features"]="GPU_POLICY_CONFLICT";
  }''',1)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(gpu,'CPP_SUPPORT',policy_support());patch.setattr(gpu,'CPP_TESTS',tests)
        return gpu.runtime_binary.__wrapped__(tmp_path_factory,sources)


@pytest.mark.parametrize('case',('features-native-policy','features-empty','features-unknown','request-features','request-empty-features','limits-native','limits-alignment'))
def test_native_policy_is_used_in_device_negotiation_not_only_getters(native_features_binary,case):
    result=subprocess.run([str(native_features_binary),case],text=True,capture_output=True,timeout=15)
    assert not result.returncode,result.stdout+result.stderr
