#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

from ds_store import DSStore
from mac_alias import Alias


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: write_dmg_dsstore.py <mounted-volume-path> <volume-name>")

    volume = Path(sys.argv[1])
    volume_name = sys.argv[2]
    background = volume / ".background" / "DMGBackground.png"
    ds_store = volume / ".DS_Store"
    app_name = f"{volume_name}.app"

    if not background.exists():
        raise SystemExit(f"missing background: {background}")
    if not (volume / app_name).exists():
        raise SystemExit(f"missing app: {volume / app_name}")
    if not (volume / "Applications").exists():
        raise SystemExit(f"missing Applications link: {volume / 'Applications'}")

    background_alias = Alias.for_file(str(background)).to_bytes()

    with DSStore.open(str(ds_store), "w+") as store:
        store["."]["bwsp"] = {
            "ContainerShowSidebar": False,
            "ShowPathbar": False,
            "ShowSidebar": False,
            "ShowStatusBar": False,
            "ShowTabView": False,
            "ShowToolbar": False,
            "WindowBounds": "{{180, 120}, {960, 540}}",
        }
        store["."]["icvp"] = {
            "arrangeBy": "none",
            "backgroundColorBlue": 0.07,
            "backgroundColorGreen": 0.07,
            "backgroundColorRed": 0.07,
            "backgroundImageAlias": background_alias,
            "backgroundImagePath": str(background),
            "backgroundType": 2,
            "gridOffsetX": 0.0,
            "gridOffsetY": 0.0,
            "gridSpacing": 100.0,
            "iconSize": 88.0,
            "labelOnBottom": True,
            "showIconPreview": True,
            "showItemInfo": False,
            "textSize": 10.0,
            "viewOptionsVersion": 1,
        }
        store[app_name]["Iloc"] = (632, 276)
        store["Applications"]["Iloc"] = (792, 276)

    print(ds_store)


if __name__ == "__main__":
    main()
