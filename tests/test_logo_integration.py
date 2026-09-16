"""Unit tests for SIDIK logo assets and GUI branding integration."""

import os
import sys
import unittest
from PIL import Image

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


class TestLogoIntegration(unittest.TestCase):
    """Tests to verify that logo assets exist, are valid, and integrate cleanly with the GUI."""

    def setUp(self):
        self.logo_dir = os.path.join(BASE_DIR, "logo")

    def test_logo_assets_exist(self):
        """Verifies that all standard logo formats are present in the logo directory."""
        required_assets = [
            "SIDIK-bg.png",
            "SIDIK-nobg-purelogo.png",
            "SIDIK-nobg-purelogo-dark.png",
            "SIDIK-nobg.png",
            "SIDIK-nobg-dark.png",
            "SIDIK-purelogo.png",
            "sidik_icon.ico"
        ]
        for asset in required_assets:
            path = os.path.join(self.logo_dir, asset)
            self.assertTrue(os.path.exists(path), f"Asset {asset} must exist in {self.logo_dir}")
            self.assertGreater(os.path.getsize(path), 0, f"Asset {asset} must not be empty")

    def test_icon_file_validity(self):
        """Verifies that the generated ICO file can be opened and parsed by PIL."""
        ico_path = os.path.join(self.logo_dir, "sidik_icon.ico")
        with Image.open(ico_path) as im:
            self.assertEqual(im.format, "ICO")

    def test_nobg_assets_have_transparency(self):
        """Verifies that all assets with 'nobg' in filename have transparent alpha channels."""
        nobg_assets = [
            "SIDIK-nobg.png",
            "SIDIK-nobg-dark.png",
            "SIDIK-nobg-purelogo.png",
            "SIDIK-nobg-purelogo-dark.png",
        ]
        for asset in nobg_assets:
            path = os.path.join(self.logo_dir, asset)
            with Image.open(path) as im:
                self.assertEqual(im.mode, "RGBA", f"{asset} must be RGBA mode")
                alpha = im.getchannel("A")
                min_alpha, _ = alpha.getextrema()
                self.assertEqual(min_alpha, 0, f"{asset} must have transparent pixels (min alpha == 0)")
                # Check corners are transparent
                w, h = im.size
                corners = [
                    alpha.getpixel((0, 0)),
                    alpha.getpixel((w - 1, 0)),
                    alpha.getpixel((0, h - 1)),
                    alpha.getpixel((w - 1, h - 1)),
                ]
                for c in corners:
                    self.assertEqual(c, 0, f"{asset} corners must be transparent")

    def test_gui_branding_and_image_refs(self):
        """Verifies that the GUI initializes and creates image references for the app icon, header, and about tab."""
        try:
            import tkinter as tk
            from sidik.gui import SecurityAnalyzerGUI
        except ImportError:
            self.skipTest("Tkinter not available in this environment")

        try:
            root = tk.Tk()
        except tk.TclError:
            self.skipTest("No display available for Tkinter GUI test")

        try:
            app = SecurityAnalyzerGUI(root)
            self.assertIn("app_icon", app._image_refs)
            self.assertIn("header_logo", app._image_refs)
            self.assertIn("about_logo", app._image_refs)
            self.assertIn("SIDIK", root.title())
        finally:
            root.destroy()


if __name__ == "__main__":
    unittest.main()
