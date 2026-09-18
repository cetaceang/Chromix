"""Backend routing, native callback timing and permission failures using final methods."""
import pytest

from test_backend_completion import EVIDENCE, backend_binary, final_sources, run
from test_backend_media import compile_configured, method
from test_fingerprint_config import config_binary
import test_fingerprint_features as features


SUPPORT = r'''
#include "base/uxr_config.h"
#include <cassert>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>
#define BUILDFLAG(x) x
#define DCHECK(x) assert(x)
namespace base {
std::string ToLowerASCII(std::string value) {
  for(char& c:value) if(c>='A'&&c<='Z') c+='a'-'A';
  return value;
}
}
template<class T,class... A> T* MakeGarbageCollected(A&&... args) {
  static std::vector<std::unique_ptr<T>> allocated;
  allocated.push_back(std::make_unique<T>(std::forward<A>(args)...));return allocated.back().get();
}
enum class DOMExceptionCode {kInvalidStateError,kSecurityError};
struct DOMException {DOMExceptionCode code;DOMException(DOMExceptionCode value,const char*):code(value) {}};
struct ScriptState {bool valid=true;bool ContextIsValid() const {return valid;}};
struct IDLBoolean {};
struct State {bool resolved=false,value=false,rejected=false;};
template<class T> struct ScriptPromise {
  std::shared_ptr<State> state;
  static ScriptPromise RejectWithDOMException(ScriptState*,DOMException*) {
    return {std::make_shared<State>(State{false,false,true})};
  }
};
template<class T> struct ScriptPromiseResolver {
  std::shared_ptr<State> state=std::make_shared<State>();
  explicit ScriptPromiseResolver(ScriptState*) {}
  ScriptPromise<T> Promise() {return {state};}
  void* GetExecutionContext() {return this;}
  void Resolve(bool value) {state->resolved=true;state->value=value;}
};
enum class WebFeature {kCredentialManagerIsUserVerifyingPlatformAuthenticatorAvailable};
struct UseCounter {static void Count(void*,WebFeature) {}};
template<class T> T* WrapPersistent(T* value) {return value;}
template<class F,class T> auto BindOnce(F fn,T* value) {return [=](bool answer){fn(value,answer);};}
struct NativeAuthenticator {
  int calls=0;std::function<void(bool)> pending;
  void IsUserVerifyingPlatformAuthenticatorAvailable(std::function<void(bool)> cb) {++calls;pending=std::move(cb);}
} native_auth;
struct CredentialManagerProxy {
  static CredentialManagerProxy* From(ScriptState*) {static CredentialManagerProxy value;return &value;}
  NativeAuthenticator* Authenticator() {return &native_auth;}
};
struct PublicKeyCredential {static ScriptPromise<IDLBoolean> isUserVerifyingPlatformAuthenticatorAvailable(ScriptState*);};
template<class T> using Member=T*;
struct MimeClassInfo {std::string mime;const std::string& Type() const {return mime;}};
struct PluginData {std::vector<MimeClassInfo*> mimes;const auto& Mimes() const {return mimes;}};
struct DOMPluginArray {
  PluginData* data=nullptr;int calls=0;
  PluginData* GetPluginData() {++calls;return data;}
  bool IsPdfViewerAvailable();
};
using String=std::string;
template<class K,class V> struct HashMap:std::map<K,V> {void Set(K k,V v) {(*this)[k]=v;}};
struct KeyboardLayoutMap {HashMap<String,String> layout;explicit KeyboardLayoutMap(HashMap<String,String> value):layout(std::move(value)) {}};
struct LayoutMapProperty {
  KeyboardLayoutMap* map=nullptr;DOMException* error=nullptr;
  void Resolve(KeyboardLayoutMap* value) {map=value;}
  void Reject(DOMException* value) {error=value;}
};
namespace mojom::blink {
enum class GetKeyboardLayoutMapStatus {kSuccess,kFail,kDenied};
struct GetKeyboardLayoutMapResult {GetKeyboardLayoutMapStatus status;HashMap<String,String> layout_map;};
using GetKeyboardLayoutMapResultPtr=std::unique_ptr<GetKeyboardLayoutMapResult>;
}
constexpr const char* kKeyboardMapRequestFailedErrorMsg="failed";
constexpr const char* kFeaturePolicyBlocked="denied";
struct KeyboardLayout {
  LayoutMapProperty* layout_map_property_;bool is_request_pending_=true;
  void GotKeyboardLayoutMap(mojom::blink::GetKeyboardLayoutMapResultPtr);
};
'''

MAIN = r'''
int main(int argc,char**argv) {
  assert(argc==3);bool synthetic=std::string(argv[1])=="synthetic";
  bool us=std::string(argv[2])=="us";
  auto& config=base::UxrConfig::GetInstance();
  assert(config.SetAll({{"uxr-synthetic-device-tests",synthetic?"true":"false"},
    {"uxr-keyboard-layout",us?"us":"native"},{"uxr-webauthn-uvpaa","true"},
    {"uxr-plugins","chrome"},{"uxr-voices","en-US"},{"uxr-platform","win32"}}));
  ScriptState script;
  auto promise=PublicKeyCredential::isUserVerifyingPlatformAuthenticatorAvailable(&script);
  assert(native_auth.calls==!synthetic);
  assert(promise.state->resolved==synthetic);
  if(!synthetic) {native_auth.pending(false);assert(promise.state->resolved&&!promise.state->value);}
  script.valid=false;
  auto detached=PublicKeyCredential::isUserVerifyingPlatformAuthenticatorAvailable(&script);
  assert(detached.state->rejected&&native_auth.calls==!synthetic);
  DOMPluginArray plugins;
  assert(plugins.IsPdfViewerAvailable()==synthetic);
  MimeClassInfo pdf{"application/pdf"},other{"text/plain"};PluginData data{{&other}};plugins.data=&data;
  assert(plugins.IsPdfViewerAvailable()==synthetic);
  data.mimes.push_back(&pdf);assert(plugins.IsPdfViewerAvailable());
  assert(UseWindowsSpeechVoiceTable()==synthetic);
  using Status=mojom::blink::GetKeyboardLayoutMapStatus;
  for(auto status:{Status::kSuccess,Status::kFail,Status::kDenied}) for(bool empty:{true,false}) {
    LayoutMapProperty property;KeyboardLayout keyboard{&property};
    auto result=std::make_unique<mojom::blink::GetKeyboardLayoutMapResult>();result->status=status;
    if(!empty) {result->layout_map.Set("KeyY","z");result->layout_map.Set("KeyZ","y");}
    keyboard.GotKeyboardLayoutMap(std::move(result));
    assert(!keyboard.is_request_pending_&&!keyboard.layout_map_property_);
    if(status==Status::kSuccess) {
      assert(property.map&&!property.error);
      if(synthetic&&us) assert(property.map->layout.at("KeyY")=="y"&&property.map->layout.size()>40);
      else if(empty) assert(property.map->layout.empty());
      else assert(property.map->layout.at("KeyY")=="z"&&property.map->layout.size()==2);
    } else {
      assert(!property.map&&property.error);
      assert(property.error->code==(status==Status::kDenied?DOMExceptionCode::kSecurityError:DOMExceptionCode::kInvalidStateError));
    }
  }
}
'''


@pytest.fixture(scope='module', params=[0, 1])
def capability_binary(tmp_path_factory, backend_binary, request):
    code = f'#define IS_WIN {request.param}\n' + SUPPORT
    code += method('void OnIsUserVerifyingComplete(')
    code += 'ScriptPromise<IDLBoolean>\n' + method('PublicKeyCredential::isUserVerifyingPlatformAuthenticatorAvailable(')
    for signature in ('bool DOMPluginArray::IsPdfViewerAvailable()', 'bool UseWindowsSpeechVoiceTable()',
                      'void KeyboardLayout::GotKeyboardLayoutMap('):
        code += method(signature)
    return compile_configured(tmp_path_factory.mktemp('capability-parent') / 'src', backend_binary.parent, code + MAIN)


@pytest.mark.parametrize('mode,layout', [('public', 'native'), ('synthetic', 'native'), ('synthetic', 'us')])
def test_backend_capabilities_async_timing_empty_inventory_and_permission_errors(capability_binary, mode, layout):
    run(capability_binary, mode, layout)


@pytest.fixture(scope='module', params=['windows', 'macos', 'linux'])
def final_normalizer(request, tmp_path_factory):
    original = EVIDENCE['methods']['  if (!command_line->HasSwitch(switches::kProcessType))']['text']
    support = features.CPP_BASE.replace('namespace switches {', '''namespace switches {
[[maybe_unused]] constexpr const char* kNoProxyServer = "no-proxy-server";
[[maybe_unused]] constexpr const char* kProxyServer = "proxy-server";
[[maybe_unused]] constexpr const char* kProxyPacUrl = "proxy-pac-url";
[[maybe_unused]] constexpr const char* kProxyAutoDetect = "proxy-auto-detect";
[[maybe_unused]] constexpr const char* kForceWebRtcIPHandlingPolicy = "force-webrtc-ip-handling-policy";
''')
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(features, 'added', lambda number: original)
        patch.setattr(features, 'CPP_BASE', support)
        return features.normalizer.__wrapped__(request, tmp_path_factory)


@pytest.mark.parametrize('suffix,value', [('gpu-backend','native'), ('font-policy','restricted'),
    ('font-whitelist','A Family,Another Family'), ('audio-render','isolated'), ('audio-seed','18446744073709551615'),
    ('timer-resolution','7'), ('max-touch-points','5'), ('color-scheme','dark'), ('pointer','fine'),
    ('hover','hover'), ('preferred-contrast','less'), ('forced-colors','active'), ('keyboard-layout','native')])
def test_final_public_aliases_and_explicit_native_precedence(final_normalizer, suffix, value):
    normalized = features.normalize(final_normalizer, '--fingerprint-' + suffix + '=' + value)
    assert normalized['uxr-' + suffix] == value
    normalized = features.normalize(final_normalizer, '--fingerprint-' + suffix + '=' + value,
                                    '--uxr-' + suffix + '=explicit')
    assert normalized['uxr-' + suffix] == 'explicit'


@pytest.mark.parametrize('route', ['--proxy-server=socks5://example.test:1080',
    '--proxy-pac-url=https://example.test/proxy.pac', '--proxy-auto-detect'])
def test_bare_browser_proxy_defaults_use_native_socket_policy(final_normalizer, route):
    values = features.normalize(final_normalizer, route, '--fingerprint=off')
    assert values['force-webrtc-ip-handling-policy'] == 'disable_non_proxied_udp'
    assert 'force-webrtc-ip-handling-policy' not in features.normalize(final_normalizer, route, '--no-proxy-server')
    assert features.normalize(final_normalizer, route, '--force-webrtc-ip-handling-policy=default')['force-webrtc-ip-handling-policy'] == 'default'
