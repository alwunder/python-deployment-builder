import os
import tkinter as tk
from pathlib import Path

import yaml
from PIL import Image
from pydantic import BaseModel

try:
    from tksheet import Sheet
except ImportError:
    Sheet = None

ROOT = Path(__file__).resolve().parents[2]
PROFILES = ROOT / "profiles"
PROMPT = ROOT / "prompts" / "extraction_prompt.md"
CACHE = ROOT / ".cache"
output_dir = Path(__file__).resolve().parents[2] / "outputs"
API_KEY = os.environ.get("OPENAI_API_KEY")


class Settings(BaseModel):
    name: str = "fixture"


def main() -> None:
    CACHE.mkdir(parents=True, exist_ok=True)
    _ = next(PROFILES.glob("*.json"), None)
    _ = PROMPT.read_text(encoding="utf-8")
    tk.Tk()
    _ = (yaml, Image, Sheet, Settings)
