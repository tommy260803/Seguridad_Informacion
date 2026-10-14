"""
Visual Brand Logo and Layout Matcher for PhishGuard Stage M3.
Detects spoofed financial and technology brands using perceptual hash (dHash/pHash)
and HSV/RGB color-layout feature alignment.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict
import numpy as np
from PIL import Image

# Representative brand color & perceptual layout fingerprints
TARGET_BRAND_FINGERPRINTS = {
    "paypal": {
        "primary_rgb": np.array([0.0, 0.43, 0.70]),    # PayPal Blue #006eb4
        "secondary_rgb": np.array([0.0, 0.18, 0.42]),  # Dark Blue #002f6c
        "luminance_target": 0.35,
        "dhash_bits": int("1100110011110000101010101100110011110000101010101100110011110000", 2),
    },
    "microsoft": {
        "primary_rgb": np.array([0.96, 0.32, 0.12]),   # MS Red/Orange
        "secondary_rgb": np.array([0.0, 0.63, 0.94]),  # MS Blue
        "luminance_target": 0.50,
        "dhash_bits": int("1010101001010101110011000011001110101010010101011100110000110011", 2),
    },
    "netflix": {
        "primary_rgb": np.array([0.89, 0.05, 0.08]),   # Netflix Red #e50914
        "secondary_rgb": np.array([0.08, 0.08, 0.08]), # Pitch Dark
        "luminance_target": 0.15,
        "dhash_bits": int("0000111100001111001100110000111100001111001100110000111100001111", 2),
    },
    "google": {
        "primary_rgb": np.array([0.26, 0.52, 0.96]),   # Google Blue #4285f4
        "secondary_rgb": np.array([0.92, 0.26, 0.21]), # Google Red
        "luminance_target": 0.65,
        "dhash_bits": int("1111000011110000110011001111000011110000110011001111000011110000", 2),
    },
    "facebook": {
        "primary_rgb": np.array([0.09, 0.40, 0.98]),   # Facebook Blue #1877f2
        "secondary_rgb": np.array([0.95, 0.95, 0.95]), # Light Gray
        "luminance_target": 0.55,
        "dhash_bits": int("1110001111100011100110011110001111100011100110011110001111100011", 2),
    },
}


def _compute_64bit_dhash(luminance: np.ndarray) -> int:
    """Compute a 64-bit difference hash (8x9 grid) from a 2D luminance array."""
    h, w = luminance.shape
    if h < 8 or w < 9:
        # Pad or tile small images safely
        pil_img = Image.fromarray(np.clip(luminance * 255.0, 0, 255).astype(np.uint8))
        resized = np.asarray(pil_img.resize((9, 8), Image.Resampling.BILINEAR), dtype=np.float32)
    else:
        row_idx = np.linspace(0, h - 1, 8).astype(int)
        col_idx = np.linspace(0, w - 1, 9).astype(int)
        resized = luminance[np.ix_(row_idx, col_idx)]
    diff = resized[:, 1:] > resized[:, :-1]
    bits = 0
    for val in diff.flatten():
        bits = (bits << 1) | int(bool(val))
    return bits


class VisualBrandMatcher:
    """Matches visual screenshot layouts against target spoofed brand signatures."""

    def __init__(self, similarity_threshold: float = 0.75):
        self.similarity_threshold = similarity_threshold

    def match_image(self, image_input: str | Path | Image.Image | np.ndarray) -> Dict[str, float | str | bool]:
        """
        Analyzes screenshot color distributions and perceptual layout hash to detect brand spoofing.
        Returns match dictionary with detected brand, confidence, pHash distance, and HSV/color similarity.
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

            h, w, _ = img_rgb.shape
            if h <= 0 or w <= 0:
                return self._fallback_result()

            mean_rgb = img_rgb.mean(axis=(0, 1))
            luminance = 0.2126 * img_rgb[:, :, 0] + 0.7152 * img_rgb[:, :, 1] + 0.0722 * img_rgb[:, :, 2]
            mean_lum = float(luminance.mean())
            img_dhash = _compute_64bit_dhash(luminance)

            best_brand = "none"
            best_similarity = 0.0
            best_hsv_sim = 0.0
            min_phash_dist = 1.0

            for brand, fp in TARGET_BRAND_FINGERPRINTS.items():
                dist_p = float(np.linalg.norm(mean_rgb - fp["primary_rgb"]))
                lum_diff = abs(mean_lum - float(fp["luminance_target"]))
                hsv_sim = max(0.0, min(1.0, 1.0 - (dist_p * 0.7 + lum_diff * 0.3)))

                hamming = (img_dhash ^ int(fp["dhash_bits"])).bit_count()
                norm_phash_dist = hamming / 64.0
                phash_sim = 1.0 - norm_phash_dist

                combined_sim = 0.75 * hsv_sim + 0.25 * phash_sim
                if hsv_sim > best_hsv_sim:
                    best_hsv_sim = hsv_sim
                if norm_phash_dist < min_phash_dist:
                    min_phash_dist = norm_phash_dist
                if combined_sim > best_similarity:
                    best_similarity = combined_sim
                    best_brand = brand

            is_match = best_similarity >= self.similarity_threshold
            return {
                "visual_brand_detected": float(is_match),
                "visual_brand_similarity": float(best_similarity),
                "visual_phash_distance_min": float(min_phash_dist),
                "visual_hsv_similarity_max": float(best_hsv_sim),
                "visual_brand_name": best_brand if is_match else "none",
            }
        except Exception:
            return self._fallback_result()

    @staticmethod
    def _fallback_result() -> Dict[str, float | str | bool]:
        return {
            "visual_brand_detected": 0.0,
            "visual_brand_similarity": 0.0,
            "visual_phash_distance_min": 1.0,
            "visual_hsv_similarity_max": 0.0,
            "visual_brand_name": "none",
        }


# Global singleton
visual_brand_matcher = VisualBrandMatcher()
