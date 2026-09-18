"""Font hash byte contracts and pinned 152/153 API signature compilation.

SkSpan uses complete upstream headers; Blink/SkTypeface declarations come from
verbatim pinned sections, with storage/crypto bodies modeled for byte checks.
These bounded tests do not replace a complete Chromium compile.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

import pytest
from test_canvas_native_paths import apply, patch_path
from test_followup_native import native_sources
from test_fingerprint_canvas import CXX, sanitizer_env, sanitizer_flags
from test_fingerprint_features import block

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk/python"))
from chromix import _font_provenance as font

API = json.loads((Path(__file__).with_name("fixtures") / "font_provenance_api.json").read_text(encoding="utf-8"))


def sfnt(tables, base=0):
    count = len(tables)
    data_offset = 12 + count * 16
    directory, payload = b"", b""
    for tag, data in tables.items():
        directory += struct.pack(">4sIII", tag, 0, base + data_offset + len(payload), len(data))
        payload += data
    return struct.pack(">4sHHHH", b"\0\1\0\0", count, 0, 0, 0) + directory + payload


def test_canonical_digest_and_collection_repacking(tmp_path):
    tables = {b"head": bytes(range(16)), b"glyf": b"shape", b"DSIG": b"container-signature"}
    adjusted = {b"glyf": b"shape", b"head": bytes(range(8)) + b"abcd" + bytes(range(12, 16))}
    assert font.table_hash(tables) == font.table_hash(adjusted)
    assert font.table_hash(tables) != font.table_hash({**tables, b"glyf": b"other"})
    path = tmp_path / "face.ttf"
    path.write_bytes(sfnt(tables))
    record = font.font_file_record(path)
    assert record["faces"][0]["table_hash"] == font.table_hash(tables)
    collection = tmp_path / "collection.ttc"
    collection.write_bytes(b"ttcf" + struct.pack(">III", 0x10000, 1, 16) + sfnt(tables, 16))
    assert font.font_file_record(collection)["faces"] == record["faces"]


@pytest.mark.parametrize("data", [b"bad", b"ttcf" + b"\0" * 20,
    b"\0\1\0\0" + struct.pack(">H", 513) + b"\0" * 10,
    sfnt({b"head": b"short"}), sfnt({b"glyf": b"shape"})[:-1]])
def test_malformed_font_bounds(tmp_path, data):
    path = tmp_path / "bad.ttf"
    path.write_bytes(data)
    with pytest.raises(ValueError):
        font.font_file_record(path)


def test_names_never_establish_binding_and_ambiguity_stays_unverified(tmp_path):
    path = tmp_path / "face.ttf"
    path.write_bytes(sfnt({b"glyf": b"shape"}))
    record = font.font_file_record(path)
    sample = [{"platformFonts": [{"postScriptName": "SameName", "glyphCount": 4}]}]
    assert font.bind_font_sources(sample, [record])["file_binding_verified"] is False
    sample[0]["platformFonts"][0].update(fontTableHash=record["faces"][0]["table_hash"],
                                      fontTableHashAlgorithm=font.ALGORITHM)
    assert font.bind_font_sources(sample, [record])["file_binding_verified"] is True
    other = {**record, "path": "different-file.ttf"}
    result = font.bind_font_sources(sample, [record, other])
    assert result["file_binding_verified"] is False
    assert result["bindings"][0]["status"] == "content_matched_multiple_files"
    assert result["rasterization_equivalence"] == "not_verified"


def api_text(version, path):
    source = API["versions"][version]["files"][path]
    content = API["contents"][source["sha256"]]
    return content.get("text") or "\n".join(section["text"] for section in content["sections"])


def declaration(text, name):
    match = re.search(r"[^\n{};]*\b" + name + r"\([^;{}]*\)[^;{}]*[;{]", text)
    assert match, name
    return match[0].strip().removesuffix("{").rstrip().removesuffix(";") + ";"


@pytest.fixture(scope="module", params=["152", "153"])
def pinned_api(request, tmp_path_factory):
    version = request.param
    root = tmp_path_factory.mktemp("font-api-" + version)
    for path, source in API["versions"][version]["files"].items():
        content = API["contents"][source["sha256"]]
        if "text" in content:
            data = content["text"].encode()
            assert hashlib.sha256(data).hexdigest() == source["sha256"]
            dest = root / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
    skia = api_text(version, "third_party/skia/include/core/SkTypeface.h")
    string = api_text(version, "third_party/blink/renderer/platform/wtf/text/wtf_string.h")
    crypto = api_text(version, "third_party/blink/renderer/platform/crypto.h")
    hexadecimal = api_text(version, "base/strings/string_number_conversions.h")
    declarations = r'''
#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include "include/core/SkSpan.h"
using SkFontTableTag = uint32_t;
constexpr uint32_t SkSetFourByteTag(char a,char b,char c,char d){return uint32_t(a)<<24|uint32_t(b)<<16|uint32_t(c)<<8|uint32_t(d);}
namespace base {
template<class T> using span = std::span<T>;
template<size_t N> auto as_byte_span(const char(&v)[N]){return span(reinterpret_cast<const uint8_t*>(v),N);}
inline auto as_byte_span(std::string_view v){return span(reinterpret_cast<const uint8_t*>(v.data()),v.size());}
inline auto U32ToBigEndian(uint32_t v){std::array<uint8_t,4> out{};for(int i=3;i>=0;--i){out[i]=v&255;v>>=8;}return out;}
inline auto U64ToBigEndian(uint64_t v){std::array<uint8_t,8> out{};for(int i=7;i>=0;--i){out[i]=v&255;v>>=8;}return out;}
'''
    declarations += hexadecimal.replace("BASE_EXPORT ", "") + "\n}\nstruct String {\n"
    declarations += string[:string.index("  bool empty()")]
    declarations += declaration(string, "empty") + "\nstd::string text;\n};\n"
    declarations += "using DigestValue=std::vector<uint8_t>;\n" + block(crypto, "enum HashAlgorithm") + ";\n"
    declarations += "struct Digestor {\n" + "\n".join(declaration(crypto, name) for name in ("Digestor", "Update", "Finish"))
    declarations += "\nstd::vector<uint8_t> bytes;\n};\nstruct SkTypeface {\n"
    declarations += "\n".join(declaration(skia, name) for name in ("countTables", "readTableTags", "getTableSize", "getTableData"))
    declarations += "\nstd::map<uint32_t,std::vector<uint8_t>> tables;\nint mode=0;\n};\n"
    return version, root / "third_party/skia", declarations


def test_pinned_api_provenance(pinned_api):
    version, _, _ = pinned_api
    evidence = API["versions"][version]
    assert evidence["chromium_revision"] == {
        "152": "d04cdb24d67b081f6cf80200ffc5233f44b61109",
        "153": "507c6ee3e2f3b2ca0e660547e5b9ea4820c67f4c",
    }[version]
    assert evidence["skia_revision"] in api_text(version, "DEPS")
    assert evidence["skia_revision"] == {
        "152": "0873ec164a06966b90ae0d43ef783cfb180084ae",
        "153": "4f574af2444846ceca4d277a8095c5d4229d175f",
    }[version]
    for path, source in evidence["files"].items():
        expected = evidence["skia_revision"] if path.startswith("third_party/skia/") else evidence["chromium_revision"]
        assert source["revision"] == expected
        assert "/" + expected + "/" in source["url"]
    skia = api_text(version, "third_party/skia/src/core/SkTypeface.cpp")
    assert "return this->onGetTableTags({});" in skia
    assert "return this->onGetTableTags(tags);" in skia


def test_independent_api_sources(pinned_api):
    version, _, _ = pinned_api
    root = os.environ.get("CHROMIX_FONT_API_ROOT_" + version)
    if not root:
        pytest.skip("independently acquired pinned " + version + " API sources required")
    for path, source in API["versions"][version]["files"].items():
        original = (Path(root) / path).read_bytes()
        assert hashlib.sha256(original).hexdigest() == source["sha256"], path
        content = API["contents"][source["sha256"]]
        if "sections" in content:
            lines = original.decode().splitlines(True)
            for section in content["sections"]:
                start = section["line"] - 1
                assert "".join(lines[start:start + len(section["text"].splitlines())]) == section["text"], path


@pytest.mark.parametrize("version,sha256", [
    ("152", "50eb7664d1e9e1fdb5fe783cdcaf3a8a61947aa15d1283a3fd71fa7fe3fab360"),
    ("153", "74d1b35bc7981621edd8651c7704f0fe27b8a60460eec607e6befae5b5a5886d"),
])
def test_independent_patch_roundtrip(tmp_path, version, sha256):
    root = os.environ.get("CHROMIX_FONT_UPSTREAM_ROOT_" + version)
    if not root:
        pytest.skip("independently acquired Chromium " + version + " preimage required")
    target = "third_party/blink/renderer/core/inspector/inspector_css_agent.cc"
    source = Path(root) / target
    original, mtime = source.read_bytes(), source.stat().st_mtime_ns
    assert hashlib.sha256(original).hexdigest() == sha256
    dest = tmp_path / target
    dest.parent.mkdir(parents=True)
    dest.write_bytes(original)
    # Historical 152 lacks three unrelated lines present in the pinned 153 source.
    apply(tmp_path, patch_path("0152"), allow_offsets=version == "152")
    apply(tmp_path, patch_path("0152"), reverse=True, allow_offsets=version == "152")
    assert dest.read_bytes() == original
    assert (source.read_bytes(), source.stat().st_mtime_ns) == (original, mtime)


def compile_api(tmp_path, pinned_api, source, *, link=False):
    if not CXX:
        pytest.skip("C++20 compiler required")
    _, include, declarations = pinned_api
    unit, binary = tmp_path / "font.cc", tmp_path / ("font.exe" if os.name == "nt" else "font")
    unit.write_text(declarations + source, encoding="utf-8")
    command = [CXX, "-std=c++20", "-Wall", "-Wextra", "-Werror", "-I", str(include)]
    command += ["-O1", "-DNDEBUG", *sanitizer_flags(), "-o", str(binary)] if link else ["-fsyntax-only"]
    result = subprocess.run([*command, str(unit)], capture_output=True, text=True, timeout=90)
    return result, binary


@pytest.mark.parametrize("mutation", [None, "getTableTags", "raw-pointer", "FromUTF8", "byte-span", "IsEmpty"])
def test_native_pinned_api_compilation(tmp_path, native_sources, pinned_api, mutation):
    helper = block(native_sources["0152"], "String ComputePlatformFontTableHash(")
    condition = re.search(r"if \((!value\.table_hash\.[^\n]+)\) \{", native_sources["0152"])[1]
    source = helper + "\nstruct Usage { String table_hash; };\nbool publish(const Usage& value) { return " + condition + "; }\n"
    table_tags = re.search(r"readTableTags\((?:SkSpan<SkFontTableTag>\(tags\.data\(\), tags\.size\(\)\)|tags)\)", helper)[0]
    replacements = {
        "getTableTags": (table_tags, "getTableTags(tags.data())"),
        "raw-pointer": (table_tags, "readTableTags(tags.data())"),
        "FromUTF8": ("String::FromUtf8", "String::FromUTF8"),
        "byte-span": ("String::FromUtf8(base::HexEncodeLower(result))", "String::FromUtf8(base::span<const uint8_t>(base::HexEncodeLower(result)))"),
        "IsEmpty": ("table_hash.empty()", "table_hash.IsEmpty()"),
    }
    if mutation:
        before, after = replacements[mutation]
        assert before in source
        source = source.replace(before, after)
    result, _ = compile_api(tmp_path, pinned_api, source)
    if mutation:
        assert result.returncode != 0, "obsolete API unexpectedly compiled: " + mutation
    else:
        assert result.returncode == 0, result.stdout + result.stderr


@pytest.fixture(scope="module")
def native_digest_binary(tmp_path_factory, native_sources, pinned_api):
    helper = block(native_sources["0152"], "String ComputePlatformFontTableHash(")
    protocol = block(native_sources["0152"], "if (!value.table_hash.")
    # Collect every digest input byte, independently of Python's encoder and SHA256.
    bodies = r'''
String String::FromUtf8(base::span<const uint8_t> bytes){String out;out.text.assign(bytes.begin(),bytes.end());return out;}
bool String::empty()const{return text.empty();}
Digestor::Digestor(HashAlgorithm){}
bool Digestor::Update(base::span<const uint8_t> r){bytes.insert(bytes.end(),r.begin(),r.end());return true;}
bool Digestor::Finish(DigestValue& out){out=bytes;return true;}
namespace base {
std::string HexEncodeLower(span<const uint8_t> b){std::string out;for(auto v:b){out+="0123456789abcdef"[v>>4];out+="0123456789abcdef"[v&15];}return out;}
}
int SkTypeface::countTables()const{return mode==1?513:mode==4?0:mode==5?-1:static_cast<int>(tables.size());}
int SkTypeface::readTableTags(SkSpan<SkFontTableTag> tags)const{
  if(mode==6)return 0;
  if(tags.size()!=tables.size())std::abort();
  size_t i=0;for(auto it=tables.rbegin();it!=tables.rend();++it)tags.data()[i++]=it->first;
  if(mode==7)tags.data()[1]=tags.data()[0];
  return static_cast<int>(i);
}
size_t SkTypeface::getTableSize(SkFontTableTag tag)const{return mode==2?65*1024*1024:tables.at(tag).size();}
size_t SkTypeface::getTableData(SkFontTableTag tag,size_t,size_t n,void* out)const{if(mode==3)return 0;std::memcpy(out,tables.at(tag).data(),n);return n;}
struct InspectorPlatformFontUsage {String table_hash;};
struct PlatformFontUsage {
  std::optional<String> table_hash, algorithm;
  void setFontTableHash(const String& value){table_hash=value;}
  void setFontTableHashAlgorithm(const char* value){algorithm=String::FromUtf8(value);}
};
'''
    emit = "\nvoid EmitHash(const InspectorPlatformFontUsage& value, PlatformFontUsage* usage) {\n" + protocol + "\n}\n"
    main = r'''
int main(int argc,char**argv){
  SkTypeface face;face.mode=argc>1?std::stoi(argv[1]):0;
  face.tables[SkSetFourByteTag('h','e','a','d')]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
  face.tables[SkSetFourByteTag('g','l','y','f')]={'s','h','a','p','e'};
  face.tables[SkSetFourByteTag('D','S','I','G')]={'s','i','g'};
  if(face.mode==8)face.tables[SkSetFourByteTag('g','l','y','f')].clear();
  if(face.mode==9)face.tables[SkSetFourByteTag('h','e','a','d')].resize(11);
  if(face.mode==10){auto& head=face.tables[SkSetFourByteTag('h','e','a','d')];std::fill(head.begin()+8,head.begin()+12,255);face.tables.erase(SkSetFourByteTag('D','S','I','G'));}
  if(face.mode==11)face.tables[SkSetFourByteTag('g','l','y','f')]={'o','t','h','e','r'};
  if(face.mode==12)face.tables.clear();
  if(face.mode==14)face.tables[SkSetFourByteTag('D','S','I','G')]={'o','t','h','e','r'};
  InspectorPlatformFontUsage value{ComputePlatformFontTableHash(face)};
  if(face.mode==13)value.table_hash=String();
  PlatformFontUsage usage;
  EmitHash(value,&usage);
  std::cout<<value.table_hash.text<<'\n'
           <<(usage.table_hash?usage.table_hash->text:"absent")<<'\n'
           <<(usage.algorithm?usage.algorithm->text:"absent")<<'\n';
}
'''
    result, binary = compile_api(tmp_path_factory.mktemp("font-digest-" + pinned_api[0]), pinned_api, bodies + helper + emit + main, link=True)
    assert result.returncode == 0, result.stdout + result.stderr
    return binary


@pytest.mark.parametrize("mode", range(15))
def test_native_digest_byte_contract(native_digest_binary, mode):
    result = subprocess.run([str(native_digest_binary), str(mode)], capture_output=True, text=True, timeout=10, env=sanitizer_env())
    assert result.returncode == 0, result.stderr
    digest, table_hash, algorithm = result.stdout.splitlines()
    tables = {b"head": bytes(range(16)), b"glyf": b"other" if mode == 11 else b"shape", b"DSIG": b"sig"}
    expected = b"" if 1 <= mode <= 9 or mode in (12, 13) else b"".join(font.canonical_table_bytes(tables))
    assert bytes.fromhex(digest) == expected
    assert table_hash == (expected.hex() if expected else "absent")
    assert algorithm == (font.ALGORITHM if expected else "absent")


def test_native_protocol_uses_typeface_content_not_names(native_sources):
    source = native_sources["0152"]
    assert "PlatformData().UniqueID()" in source
    assert "ComputePlatformFontTableHash(*typeface)" in source
    assert "setFontTableHashAlgorithm" in source
    assert "experimental optional string fontTableHash" in native_sources["0153"]
