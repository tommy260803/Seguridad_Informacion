from __future__ import annotations

from pathlib import Path

import numpy as np
from PIL import Image, UnidentifiedImageError

from phishguard_visual.models import VisualEvidence, VisualResult


class VisualAnalyzerError(ValueError):
    """Raised when a screenshot violates bounded visual-analysis limits."""


def analyze_screenshot(path: str | Path, *, max_bytes: int = 8_000_000, max_pixels: int = 12_000_000) -> VisualResult:
    file_path = Path(path)
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        return VisualResult("error", 0, {}, (), "read_error", str(exc))
    if size > max_bytes:
        return VisualResult("blocked", size, {}, (), "size_limit", "Screenshot exceeds byte limit")
    try:
        with Image.open(file_path) as image:
            width, height = image.size
            if width <= 0 or height <= 0 or width * height > max_pixels:
                return VisualResult("blocked", size, {}, (), "pixel_limit", "Screenshot exceeds pixel limit")
            rgb = np.asarray(image.convert("RGB"), dtype=np.float32) / 255.0
    except (OSError, UnidentifiedImageError) as exc:
        return VisualResult("error", size, {}, (), "invalid_image", str(exc))
    luminance = 0.2126 * rgb[:, :, 0] + 0.7152 * rgb[:, :, 1] + 0.0722 * rgb[:, :, 2]
    edge_x = np.abs(np.diff(luminance, axis=1)).mean() if width > 1 else 0.0
    edge_y = np.abs(np.diff(luminance, axis=0)).mean() if height > 1 else 0.0
    features = {
        "visual_observation_available": 1.0,
        "visual_width": float(width),
        "visual_height": float(height),
        "visual_aspect_ratio": float(width / height),
        "visual_mean_luminance": float(luminance.mean()),
        "visual_luminance_std": float(luminance.std()),
        "visual_edge_density": float((edge_x + edge_y) / 2.0),
        "visual_dark_pixel_ratio": float((luminance < 0.2).mean()),
        "visual_saturated_pixel_ratio": float((rgb.max(axis=2) - rgb.min(axis=2) > 0.35).mean()),
    }
    evidence = tuple(VisualEvidence(name, value) for name, value in features.items())
    return VisualResult("success", size, features, evidence)
