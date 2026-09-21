"""
SLOPGUARD VS Code Demo File
Showcases:
1. Valid package (requests) -> ALLOW
2. Hallucinated / typo package (requets) -> BLOCK
3. Import/distribution identity resolution (cv2 -> opencv-python) -> ALIAS RESOLUTION
4. Valid framework (fastapi) -> ALLOW
5. QuickFix & Rescan loop
"""

import requests
import requets
import cv2
import fastapi


def main():
    print("SLOPGUARD Demo Active")


if __name__ == "__main__":
    main()
