import base64
import gzip
import io
import zlib
from pathlib import Path

from deobfuscator.pipeline import deobfuscate

FIXTURES = Path(__file__).parent / "fixtures"


def test_js_fromcharcode_and_concat():
    src = 'var x = String.fromCharCode(72,101,108,108,111) + " " + "world";'
    result = deobfuscate(src, language="js")
    assert "Hello world" in result.text
    assert "fromCharCode" not in result.text


def test_js_eval_atob():
    inner = "console.log('hi');"
    b64 = base64.b64encode(inner.encode()).decode()
    src = f'eval(atob("{b64}"));'
    result = deobfuscate(src, language="js")
    assert "console.log" in result.text
    assert "atob" not in result.text
    assert "eval" not in result.text


def test_js_hex_string_unescape():
    src = r'var a = "\x48\x69";'
    result = deobfuscate(src, language="js")
    assert "Hi" in result.text


def test_js_array_lookup_concat():
    src = 'var a = ["en"]; var b = [39, "op"]; var x = b[1] + a[0];'
    result = deobfuscate(src, language="js")
    assert "open" in result.text


def test_js_array_literal_index_identifier():
    src = "var x = [26, -9, WScript, 34][2];"
    result = deobfuscate(src, language="js")
    assert "WScript" in result.text
    assert "[2]" not in result.text


def test_js_rename_junk():
    src = "var _0xabc123 = 1; console.log(_0xabc123);"
    result = deobfuscate(src, language="js")
    assert "_0xabc123" not in result.text
    assert "v0" in result.text


def test_php_eval_base64():
    inner = 'echo "hi";'
    b64 = base64.b64encode(inner.encode()).decode()
    src = f"<?php eval(base64_decode('{b64}'));"
    result = deobfuscate(src, language="php")
    assert "echo" in result.text
    assert "hi" in result.text
    assert "base64_decode" not in result.text
    assert "eval" not in result.text


def test_php_nested_gzinflate_base64():
    payload = b'echo "nested";'
    compressor = zlib.compressobj(wbits=-15)
    raw = compressor.compress(payload) + compressor.flush()
    b64 = base64.b64encode(raw).decode()
    src = f"<?php eval(gzinflate(base64_decode('{b64}')));"
    result = deobfuscate(src, language="php")
    assert "nested" in result.text
    assert "gzinflate" not in result.text
    assert "base64_decode" not in result.text


def test_php_gzdecode():
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(b'echo "gz";')
    b64 = base64.b64encode(buf.getvalue()).decode()
    src = f"<?php eval(gzdecode(base64_decode('{b64}')));"
    result = deobfuscate(src, language="php")
    assert "gz" in result.text


def test_php_string_concat_and_fold():
    src = "<?php $x = 'hel' . 'lo'; $n = 1 + 2;"
    result = deobfuscate(src, language="php")
    assert "hello" in result.text
    assert "3" in result.text


def test_php_rot13():
    src = "<?php eval(str_rot13('rpub \"ebg\";'));"
    result = deobfuscate(src, language="php")
    assert "echo" in result.text
    assert "rot" in result.text
    assert "str_rot13" not in result.text


def test_fixture_js_fromcharcode():
    src = (FIXTURES / "fromcharcode.js").read_text(encoding="utf-8")
    result = deobfuscate(src, language="auto", path=str(FIXTURES / "fromcharcode.js"))
    assert result.language == "js"
    assert "Hello world" in result.text


def test_fixture_php_eval_base64():
    src = (FIXTURES / "eval_base64.php").read_text(encoding="utf-8")
    result = deobfuscate(src, language="auto", path=str(FIXTURES / "eval_base64.php"))
    assert result.language == "php"
    assert "echo" in result.text
    assert "hi" in result.text
