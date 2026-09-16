import os
from pathlib import Path
import struct
import subprocess
import sys

import pytest
from test_followup_native import native_sources
from test_fingerprint_canvas import CXX, sanitizer_env, sanitizer_flags
from test_fingerprint_features import block

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk/python"))
from chromix import _font_provenance as font


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


@pytest.fixture(scope="module")
def native_font_source(native_sources):
    helper = block(native_sources["0152"], "String ComputePlatformFontTableHash(")
    protocol = block(native_sources["0152"], "if (!value.table_hash.")
    # Digestor is a transcript collector here: compare every native hash input
    # byte to the independent Python encoder, not a fake cryptographic digest.
    shim = r'''
#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <cstring>
namespace base {template<class T> using span=std::span<T>;}
template<class T> using SkSpan=std::span<T>;
using SkFontTableTag=uint32_t;
constexpr uint32_t SkSetFourByteTag(char a,char b,char c,char d){return uint32_t(a)<<24|uint32_t(b)<<16|uint32_t(c)<<8|uint32_t(d);}
// Chromium 152 wtf_string.h and its pinned Skia expose only these spellings.
class String {
  std::string value_;
 public:
  String()=default;
  String(const char* value):value_(value){}
  static String FromUtf8(base::span<const uint8_t> value){String out;out.value_.assign(value.begin(),value.end());return out;}
  static String FromUtf8(std::string_view value){return FromUtf8(base::span<const uint8_t>(reinterpret_cast<const uint8_t*>(value.data()),value.size()));}
  bool empty()const{return value_.empty();}
  std::string Utf8()const{return value_;}
};
using DigestValue=std::vector<uint8_t>;
constexpr int kHashAlgorithmSha256=1;
struct Digestor {
  std::vector<uint8_t> bytes;
  explicit Digestor(int){}
  template<class R> bool Update(const R& r){bytes.insert(bytes.end(),r.begin(),r.end());return true;}
  bool Finish(DigestValue& out){out=bytes;return true;}
};
namespace base {
template<size_t N> auto as_byte_span(const char(&v)[N]){return std::span(reinterpret_cast<const uint8_t*>(v),N);}
inline auto U32ToBigEndian(uint32_t v){std::array<uint8_t,4> out{};for(int i=3;i>=0;--i){out[i]=v&255;v>>=8;}return out;}
inline auto U64ToBigEndian(uint64_t v){std::array<uint8_t,8> out{};for(int i=7;i>=0;--i){out[i]=v&255;v>>=8;}return out;}
inline std::string HexEncodeLower(const std::vector<uint8_t>& b){std::string out;for(auto v:b){out+="0123456789abcdef"[v>>4];out+="0123456789abcdef"[v&15];}return out;}
}
struct SkTypeface {
  std::map<uint32_t,std::vector<uint8_t>> tables;
  int mode=0;
  int countTables()const{return mode==1?513:static_cast<int>(tables.size());}
  int readTableTags(SkSpan<SkFontTableTag> tags)const{
    if(mode==4)return 0;
    if(tags.empty())return countTables();
    if(tags.size()<tables.size())return 0;
    size_t i=0;for(auto it=tables.rbegin();it!=tables.rend();++it)tags[i++]=it->first;
    if(mode==5)tags[1]=tags[0];
    return static_cast<int>(i);
  }
  size_t getTableSize(SkFontTableTag tag)const{return mode==2?65*1024*1024:tables.at(tag).size();}
  size_t getTableData(SkFontTableTag tag,size_t,size_t n,void* out)const{if(mode==3)return 0;std::memcpy(out,tables.at(tag).data(),n);return n;}
};
struct InspectorPlatformFontUsage {String table_hash;};
struct PlatformFontUsage {
  std::optional<String> table_hash, algorithm;
  void setFontTableHash(const String& value){table_hash=value;}
  void setFontTableHashAlgorithm(const String& value){algorithm=value;}
};
'''
    emit = "\nvoid EmitHash(const InspectorPlatformFontUsage& value, PlatformFontUsage* usage) {\n" + protocol + "\n}\n"
    return shim + helper + emit


@pytest.fixture(scope="module")
def native_font_binary(tmp_path_factory, native_font_source):
    if not CXX:
        pytest.skip("C++20 compiler required")
    tmp_path = tmp_path_factory.mktemp("font-native")
    main = r'''
int main(int argc,char**argv){
  SkTypeface face;face.mode=argc>1?std::stoi(argv[1]):0;
  const auto head=SkSetFourByteTag('h','e','a','d');
  const auto glyf=SkSetFourByteTag('g','l','y','f');
  const auto dsig=SkSetFourByteTag('D','S','I','G');
  face.tables[head]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
  face.tables[glyf]={'s','h','a','p','e'};
  face.tables[dsig]={'s','i','g'};
  if(face.mode==6)face.tables.clear();
  if(face.mode==7)face.tables[head].resize(11);
  if(face.mode==8)face.tables[glyf].clear();
  if(face.mode==9){std::fill(face.tables[head].begin()+8,face.tables[head].begin()+12,255);face.tables[dsig]={'o','t','h','e','r'};}
  InspectorPlatformFontUsage value{ComputePlatformFontTableHash(face)};
  if(face.mode==10)value.table_hash=String("");
  PlatformFontUsage usage;
  EmitHash(value,&usage);
  std::cout<<value.table_hash.Utf8()<<'\n'
           <<(usage.table_hash?usage.table_hash->Utf8():"absent")<<'\n'
           <<(usage.algorithm?usage.algorithm->Utf8():"absent")<<'\n';
}
'''
    unit, binary = tmp_path / "font.cc", tmp_path / ("font.exe" if os.name == "nt" else "font")
    unit.write_text(native_font_source + main, encoding="utf-8")
    result = subprocess.run([CXX, "-std=c++20", "-O1", "-Wall", "-Wextra", "-Werror", *sanitizer_flags(),
                             str(unit), "-o", str(binary)], capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
    return binary


@pytest.mark.parametrize("mode", range(11))
def test_native_digest_byte_contract(native_font_binary, mode):
    result = subprocess.run([str(native_font_binary), str(mode)], capture_output=True, text=True,
                            timeout=10, env=sanitizer_env())
    assert result.returncode == 0, result.stderr
    digest, table_hash, algorithm = result.stdout.splitlines()
    expected = b"" if mode not in (0, 9) else b"".join(font.canonical_table_bytes(
        {b"head": bytes(range(16)), b"glyf": b"shape", b"DSIG": b"sig"}))
    assert bytes.fromhex(digest) == expected
    assert table_hash == (expected.hex() if expected else "absent")
    assert algorithm == (font.ALGORITHM if expected else "absent")


@pytest.mark.parametrize("current, obsolete, diagnostic", [
    ("readTableTags(SkSpan<SkFontTableTag>(tags.data(), tags.size()))",
     "getTableTags(tags.data())", "getTableTags"),
    ("readTableTags(SkSpan<SkFontTableTag>(tags.data(), tags.size()))",
     "readTableTags(tags.data())", "readTableTags"),
    ("String::FromUtf8(base::HexEncodeLower(result))",
     "String::FromUTF8(base::HexEncodeLower(result))", "FromUTF8"),
    ("value.table_hash.empty()", "value.table_hash.IsEmpty()", "IsEmpty"),
])
def test_native_rejects_obsolete_apis(tmp_path, native_font_source, native_font_binary,
                                     current, obsolete, diagnostic):
    assert native_font_source.count(current) == 1
    unit = tmp_path / "obsolete.cc"
    unit.write_text(native_font_source.replace(current, obsolete), encoding="utf-8")
    result = subprocess.run([CXX, "-std=c++20", "-fsyntax-only", "-Wall", "-Wextra", "-Werror", str(unit)],
                            capture_output=True, text=True, timeout=90)
    assert result.returncode != 0, "obsolete API unexpectedly compiled"
    assert diagnostic in result.stderr, result.stdout + result.stderr


def test_native_protocol_uses_typeface_content_not_names(native_sources):
    source = native_sources["0152"]
    assert "PlatformData().UniqueID()" in source
    assert "ComputePlatformFontTableHash(*typeface)" in source
    assert "setFontTableHashAlgorithm" in source
    assert "experimental optional string fontTableHash" in native_sources["0153"]
