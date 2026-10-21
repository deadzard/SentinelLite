"""Static checks on the dashboard code and project text: readability and house style rules."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = (ROOT / "app.py").read_text(encoding="utf-8")
TEXT_SUFFIXES = {".py", ".md", ".bat", ".sh", ".toml", ".txt", ".ini"}
EMOJI = re.compile("[\U0001F000-\U0001FAFF\u2600-\u27BF\u2B00-\u2BFF\uFE0F]")
EXCLUDE = {"analysis.py", "port_policy.py"}  # not part of this project's source


def project_text_files():
    for path in sorted(ROOT.rglob("*")):
        if (path.is_file() and path.suffix in TEXT_SUFFIXES and path.name not in EXCLUDE
                and not {".venv", "__pycache__", ".pytest_cache"} & set(path.parts)):
            yield path


def css_rules():
    css = APP.split('CSS = """', 1)[1].split('"""', 1)[0]
    return re.findall(r"([^{}]+)\{([^}]*)\}", css)


def test_no_gradients_pills_or_animation_in_the_dashboard():
    css = APP.split('CSS = """', 1)[1].split('"""', 1)[0].lower()
    for banned in ("gradient", "999px", "keyframes", "animation", "transition", "cursor:"):
        assert banned not in css, banned


def test_no_emoji_anywhere_in_project_text():
    for path in project_text_files():
        assert not EMOJI.search(path.read_text(encoding="utf-8")), path.name


def test_no_em_or_en_dashes_in_project_text():
    for path in project_text_files():
        text = path.read_text(encoding="utf-8")
        assert "\u2014" not in text and "\u2013" not in text, path.name


def test_every_custom_box_with_a_background_also_sets_its_text_colour():
    # Prevents white-on-white text when Streamlit runs in dark mode.
    checked = 0
    for selector, body in css_rules():
        if re.search(r"(?<![-\w])background\s*:", body):
            checked += 1
            assert re.search(r"(?<![-\w])color\s*:", body), selector.strip()
    assert checked >= 8


def test_dashboard_uses_a_real_favicon_not_an_emoji():
    icon = ROOT / "assets" / "favicon.png"
    assert icon.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    assert "page_icon=_icon" in APP


def test_upload_limit_matches_parser_limit():
    from log_parser import MAX_FILE_BYTES
    config = (ROOT / ".streamlit" / "config.toml").read_text(encoding="utf-8")
    assert f"maxUploadSize = {MAX_FILE_BYTES // (1024 * 1024)}" in config
