from deobfuscator.cli import main


def test_cli_js_stdout(tmp_path, capsys):
    src = tmp_path / "packed.js"
    src.write_text('var x = "a" + "b";\n', encoding="utf-8")
    assert main([str(src), "--lang", "js"]) == 0
    out = capsys.readouterr().out
    assert "ab" in out


def test_cli_output_file(tmp_path):
    src = tmp_path / "packed.php"
    src.write_text("<?php echo 1+2;", encoding="utf-8")
    dest = tmp_path / "clean.php"
    assert main([str(src), "-o", str(dest), "--lang", "php"]) == 0
    assert "3" in dest.read_text(encoding="utf-8")


def test_cli_sandbox_js_uses_static_js(tmp_path, capsys):
    src = tmp_path / "x.js"
    src.write_text('var a = ["en"]; var b = ["op"]; var x = b[0] + a[0];\n', encoding="utf-8")
    assert main([str(src), "--sandbox", "observe"]) == 0
    captured = capsys.readouterr()
    assert "JavaScript" in captured.err
    assert "open" in captured.out
