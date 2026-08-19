from pathlib import Path

target = Path("C:\\Program Files\\BadApp\\state.json")
target.write_text("state", encoding="utf-8")
