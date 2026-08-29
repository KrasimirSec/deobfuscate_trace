from evilbox.cli import main


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


def test_cli_report_json(tmp_path, capsys):
    src = tmp_path / "packed.php"
    src.write_text("<?php eval($_POST['x']);", encoding="utf-8")
    dest = tmp_path / "clean.php"
    report = tmp_path / "rep.json"
    assert main([str(src), "-o", str(dest), "--report", str(report), "--lang", "php"]) == 0
    data = report.read_text(encoding="utf-8")
    assert "evilbox.report.v1" in data
    assert "webshell" in data
    assert "surface_signatures" in data
    err = capsys.readouterr().err
    assert "roles:" in err
    assert "surface signatures" in err


def test_cli_batch(tmp_path):
    folder = tmp_path / "samples"
    folder.mkdir()
    (folder / "a.js").write_text('var x = "a" + "b";\n', encoding="utf-8")
    (folder / "b.php").write_text("<?php echo 1+2;", encoding="utf-8")
    out = tmp_path / "out"
    assert main([str(folder), "-o", str(out)]) == 0
    assert (out / "a.clean.js").is_file()
    assert (out / "b.clean.php").is_file()
    assert (out / "a.report.json").is_file()
    assert (out / "clusters.json").is_file()


def test_cli_sandbox_js_uses_static_js(tmp_path, capsys):
    src = tmp_path / "x.js"
    src.write_text('var a = ["en"]; var b = ["op"]; var x = b[0] + a[0];\n', encoding="utf-8")
    assert main([str(src), "--sandbox", "observe"]) == 0
    captured = capsys.readouterr()
    assert "JavaScript" in captured.err
    assert "open" in captured.out


def test_cli_missing_file(tmp_path, capsys):
    missing = tmp_path / "nope.js"
    assert main([str(missing)]) == 2
    err = capsys.readouterr().err
    assert "error: file not found:" in err
    assert "nope.js" in err
    assert "Traceback" not in err


def test_cli_unexpected_error_is_short(tmp_path, monkeypatch, capsys):
    def boom(*_args, **_kwargs):
        raise RuntimeError("simulated crash")

    monkeypatch.setattr("evilbox.cli.deobfuscate", boom)
    src = tmp_path / "x.js"
    src.write_text("var x = 1;\n", encoding="utf-8")
    assert main([str(src), "--lang", "js"]) == 2
    err = capsys.readouterr().err
    assert "error: unexpected failure (RuntimeError): simulated crash" in err
    assert "Traceback" not in err

