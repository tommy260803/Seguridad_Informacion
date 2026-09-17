from pathlib import Path

from PIL import Image

from phishguard_visual.analyzer import analyze_screenshot


def test_visual_analyzer_extracts_bounded_features(tmp_path: Path) -> None:
    image_path = tmp_path / "screen.png"
    Image.new("RGB", (40, 20), (20, 80, 200)).save(image_path)
    result = analyze_screenshot(image_path)
    assert result.status == "success"
    assert result.features["visual_width"] == 40
    assert 1.9 < result.features["visual_aspect_ratio"] < 2.1
    assert len(result.evidence) == 9


def test_visual_analyzer_blocks_large_files_and_invalid_images(tmp_path: Path) -> None:
    image_path = tmp_path / "screen.png"
    Image.new("RGB", (10, 10), "white").save(image_path)
    assert analyze_screenshot(image_path, max_bytes=1).error_code == "size_limit"
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"not-an-image")
    assert analyze_screenshot(bad).error_code == "invalid_image"
