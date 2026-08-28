from evilbox.extract import extract_indicators
from evilbox.pipeline import deobfuscate


def test_extract_url_domain_file_and_apis():
    src = '''
    var x = "http://strangerltd.top/777.exe";
    var y = new ActiveXObject("MSXML2.XMLHTTP");
    var z = "WScript.Shell";
    var c = "cmd.exe";
    '''
    iocs = extract_indicators(src)
    assert any("strangerltd.top/777.exe" in u for u in iocs.urls)
    assert "strangerltd.top" in iocs.domains
    assert "wscript.shell" not in iocs.domains
    assert "msxml2.xmlhttp" not in iocs.domains
    assert "777.exe" in iocs.files
    assert "cmd.exe" in iocs.files
    assert "ActiveXObject" in iocs.apis
    assert "MSXML2.XMLHTTP" in iocs.apis
    assert "WScript.Shell" in iocs.apis


def test_extract_skips_container_hostname():
    iocs = extract_indicators("var x = 1;", extra_domains=["ef76d2a6b8a9", "evil.example"])
    assert "ef76d2a6b8a9" not in iocs.domains
    assert "evil.example" in iocs.domains


def test_pipeline_attaches_indicators():
    src = 'var a = ["htt"]; var b = ["p://evil.example/a.exe"]; var x = a[0] + b[0];'
    result = deobfuscate(src, language="js")
    assert "evil.example" in result.indicators.domains
    assert any("evil.example" in u for u in result.indicators.urls)
