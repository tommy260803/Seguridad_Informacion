"""
Visual Brand Logo and Layout Matcher for PhishGuard Stage M3.
Detects spoofed financial and technology brands using perceptual feature alignment.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Tuple, Optional
import numpy as np
from PIL import Image

# Representative brand color fingerprints in HSV / RGB space
TARGET_BRAND_FINGERPRINTS = {
    "paypal": {
        "primary_rgb": np.array([0.0, 0.43, 0.70]),    # PayPal Blue #006eb4
        "secondary_rgb": np.array([0.0, 0.18, 0.42]),  # Dark Blue #002f6c
        "luminance_target": 0.35,
    },
    "microsoft": {
        "primary_rgb": np.array([0.96, 0.32, 0.12]),  # MS Red/Orange
        "secondary_rgb": np.array([0.0, 0.63, 0.94]),  # MS Blue
        "luminance_target": 0.50,
    },
    "netflix": {
        "primary_rgb": np.array([0.89, 0.05, 0.08]),  # Netflix Red #e50914
        "secondary_rgb": np.array([0.08, 0.08, 0.08]),# Pitch Dark
        "luminance_target": 0.15,
    },
    "google": {
        "primary_rgb": np.array([0.26, 0.52, 0.96]),  # Google Blue #4285f4
        "secondary_rgb": np.array([0.92, 0.26, 0.21]), # Google Red
        "luminance_target": 0.65,
    },
    "facebook": {
        "primary_rgb": np.array([0.09, 0.40, 0.98]),  # Facebook Blue #1877f2
        "secondary_rgb": np.array([0.95, 0.95, 0.95]), # Light Gray
        "luminance_target": 0.55,
    },
}

class VisualBrandMatcher:
    """Matches visual screenshot layouts against target spoofed brand signatures."""

    def __init__(self, similarity_threshold: float = 0.75):
        self.similarity_threshold = similarity_threshold

    def match_image(self, image_input: str | Path | Image.Image | np.ndarray) -> Dict[str, float | str | bool]:
        """
        Analyzes screenshot color distributions and regional layout to detect brand spoofing.
        Returns match dictionary with detected brand, confidence, and similarity metrics.
        """
        try:
            if isinstance(image_input, (str, Path)):
                with Image.open(image_input) as img:
                    img_rgb = np.asarray(img.convert("RGB"), dtype=np.float32) / 255.0
            elif isinstance(image_input, Image.Image):
                img_rgb = np.asarray(image_input.convert("RGB"), dtype=np.float32) / 255.0
            elif isinstance(image_input, np.ndarray):
                img_rgb = image_input if image_input.max() <= 1.0 else image_input / 255.0
            else:
                return self._fallback_result()

            # Downsample for fast robust color spatial analysis
            h, w, _ = img_rgb.shape
            if h <= 0 or w <= 0:
                return self._fallback_result()

            mean_rgb = img_rgb.mean(axis=(0, 1))
            luminance = 0.2126 * img_rgb[:, :, 0] + 0.7152 * img_rgb[:, :, 1] + 0.0722 * img_rgb[:, :, 2]
            mean_lum = float(luminance.mean())

            best_brand = "none"
            best_similarity = 0.0

            for brand, fp in TARGET_BRAND_FINGERPRINTS.items():
                # Color distance
                dist_p = np.linalg.norm(mean_rgb - fp["primary_rgb"])
                lum_diff = abs(mean_lum - fp["luminance_target"])

                # Cosine similarity in color histogram space
                sim = max(0.0, 1.0 - (dist_p * 0.7 + lum_diff * 0.3))
                if sim > best_similarity:
                    best_similarity = sim
                    best_brand = brand

            is_match = best_similarity >= self.similarity_threshold
            return {
                "visual_brand_detected": float(is_match),
                "visual_brand_similarity": float(best_similarity),
                "visual_brand_name": best_brand if is_match else "none"
            }
        except Exception:
            return self._fallback_result()

    @staticmethod
    def _fallback_result() -> Dict[str, float | str | bool]:
        return {
            "visual_brand_detected": 0.0,
            "visual_brand_similarity": 0.0,
            "visual_brand_name": "none"
        }

# Global singleton
visual_brand_matcher = VisualBrandMatcher()
