from evilbox.detect import detect_language


def test_detect_js_extension():
    assert detect_language("weird $ php looking", path="app.js") == "js"


def test_detect_php_extension():
    assert detect_language("function foo() {}", path="app.php") == "php"


def test_detect_php_tag():
    assert detect_language("<?php echo 1;") == "php"


def test_detect_js_default():
    assert detect_language("const x = 1;") == "js"


def test_detect_explicit():
    assert detect_language("<?php echo 1;", lang="js") == "js"
