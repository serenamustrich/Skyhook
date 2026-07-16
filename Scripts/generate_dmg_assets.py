#!/usr/bin/env python3
from __future__ import annotations

import math
import random
import shutil
import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont


ROOT = Path(__file__).resolve().parents[1]
RESOURCES = ROOT / "Resources"
BACKGROUND_SOURCE = RESOURCES / "DMGBackgroundSource.png"
BACKGROUND = RESOURCES / "DMGBackground.png"
APP_ICON_SOURCE = RESOURCES / "AppIconSource.png"
ICONSET = RESOURCES / "AppIcon.iconset"
ICNS = RESOURCES / "AppIcon.icns"


def font(size: int, weight: str = "regular") -> ImageFont.FreeTypeFont:
    candidates = [
        "/System/Library/Fonts/PingFang.ttc",
        "/System/Library/Fonts/STHeiti Light.ttc",
        "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
        "/Library/Fonts/Arial Unicode.ttf",
    ]
    for path in candidates:
        try:
            return ImageFont.truetype(path, size=size, index=0)
        except Exception:
            continue
    return ImageFont.load_default()


def lerp(a: int, b: int, t: float) -> int:
    return int(a + (b - a) * t)


def vertical_gradient(width: int, height: int, top: tuple[int, int, int], bottom: tuple[int, int, int]) -> Image.Image:
    img = Image.new("RGB", (width, height))
    px = img.load()
    for y in range(height):
        t = y / max(1, height - 1)
        color = tuple(lerp(top[i], bottom[i], t) for i in range(3))
        for x in range(width):
            px[x, y] = color
    return img


def draw_glow(draw: ImageDraw.ImageDraw, center: tuple[int, int], radius: int, color: tuple[int, int, int], alpha: int) -> None:
    cx, cy = center
    for step in range(18, 0, -1):
        r = radius * step / 18
        a = int(alpha * (step / 18) ** 2)
        draw.ellipse((cx - r, cy - r, cx + r, cy + r), fill=(*color, a))


def draw_background() -> None:
    width, height = 960, 540
    if BACKGROUND_SOURCE.exists():
        source = Image.open(BACKGROUND_SOURCE).convert("RGB")
        cover = source.resize((width, height), Image.Resampling.LANCZOS).convert("RGBA")
        cover = Image.alpha_composite(cover, Image.new("RGBA", (width, height), (0, 0, 0, 50)))
        base = cover.filter(ImageFilter.GaussianBlur(14))
        scaled = source.resize((888, 500), Image.Resampling.LANCZOS).convert("RGBA")
        scaled_mask = Image.new("L", scaled.size, 0)
        mask_draw = ImageDraw.Draw(scaled_mask)
        mask_draw.rectangle((34, 0, 372, 466), fill=255)
        scaled_mask = scaled_mask.filter(ImageFilter.GaussianBlur(30))
        scaled.putalpha(scaled_mask)
        base.alpha_composite(scaled, (54, 0))

        panel_eraser = Image.new("RGBA", (width, height), (0, 0, 0, 0))
        eraser_mask = Image.new("L", (width, height), 0)
        eraser_draw = ImageDraw.Draw(eraser_mask)
        eraser_draw.rectangle((386, 34, 960, 500), fill=255)
        eraser_mask = eraser_mask.filter(ImageFilter.GaussianBlur(26))
        panel_fill = Image.new("RGBA", (width, height), (4, 12, 19, 246))
        panel_eraser = Image.composite(panel_fill, panel_eraser, eraser_mask)
        base = Image.alpha_composite(base, panel_eraser)

        overlay = Image.new("RGBA", (width, height), (0, 0, 0, 0))
        draw = ImageDraw.Draw(overlay)

        for box, alpha in [
            ((246, 150, 1010, 410), 28),
            ((302, 116, 1066, 438), 20),
            ((354, 198, 1014, 524), 16),
        ]:
            draw.arc(box, start=198, end=350, fill=(88, 205, 246, alpha), width=1)
        for start, end, alpha in [
            ((384, 248), (904, 280), 50),
            ((428, 292), (914, 248), 40),
            ((472, 338), (892, 320), 30),
        ]:
            draw.line((*start, *end), fill=(78, 206, 246, alpha), width=1)
            for t in (0.26, 0.54, 0.78):
                x = lerp(start[0], end[0], t)
                y = lerp(start[1], end[1], t)
                draw.ellipse((x - 2, y - 2, x + 2, y + 2), fill=(255, 214, 130, alpha + 22))

        body_font = font(16)
        label_font = font(15)
        title_font = font(21)

        def centered_text(text: str, x: int, y: int, text_font: ImageFont.FreeTypeFont, fill=(238, 248, 255, 238)) -> None:
            w = draw.textlength(text, font=text_font)
            draw.text((x - w / 2 + 1, y + 1), text, font=text_font, fill=(0, 0, 0, 160))
            draw.text((x - w / 2, y), text, font=text_font, fill=fill)

        centered_text("拖入 Applications 完成安装", 712, 105, title_font, fill=(240, 248, 252, 235))
        centered_text("保留订阅配置，菜单栏一键启停", 712, 136, body_font, fill=(170, 204, 222, 215))

        icon_centers = [(632, 276), (792, 276)]
        draw.line((690, 276, 729, 276), fill=(255, 216, 133, 215), width=2)
        draw.polygon([(729, 276), (717, 268), (717, 284)], fill=(255, 216, 133, 215))

        centered_text("玥球电梯", 632, 344, label_font)
        centered_text("Applications", 792, 344, label_font)

        base = Image.alpha_composite(base, overlay)
        base = base.filter(ImageFilter.UnsharpMask(radius=1.0, percent=105, threshold=3))
        RESOURCES.mkdir(parents=True, exist_ok=True)
        base.convert("RGB").save(BACKGROUND, quality=96)
        return

    random.seed(260605)
    base = vertical_gradient(width, height, (8, 14, 22), (18, 24, 33)).convert("RGBA")
    overlay = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)

    for _ in range(130):
        x = random.randint(0, width)
        y = random.randint(0, height)
        a = random.randint(20, 95)
        draw.point((x, y), fill=(195, 228, 255, a))

    draw_glow(draw, (210, 276), 260, (84, 204, 255), 52)
    draw_glow(draw, (250, 272), 180, (255, 220, 148), 26)

    moon = Image.new("RGBA", (360, 360), (0, 0, 0, 0))
    md = ImageDraw.Draw(moon)
    mc = (180, 180)
    for r in range(178, 0, -1):
        t = r / 178
        shade = int(220 - 52 * t)
        md.ellipse((mc[0] - r, mc[1] - r, mc[0] + r, mc[1] + r), fill=(shade, shade + 8, min(255, shade + 22), 235))
    for x, y, r, a in [
        (112, 110, 24, 34), (230, 88, 14, 28), (260, 182, 32, 34),
        (146, 240, 20, 28), (204, 270, 12, 22), (86, 190, 16, 22),
    ]:
        md.ellipse((x - r, y - r, x + r, y + r), fill=(105, 124, 145, a))
    moon = moon.filter(ImageFilter.GaussianBlur(0.25))
    base.alpha_composite(moon, (35, 92))

    # Lunar elevator shaft and cabin.
    shaft_x = 265
    draw.rounded_rectangle((shaft_x - 8, 62, shaft_x + 8, 470), radius=8, fill=(112, 226, 255, 46))
    draw.line((shaft_x, 58, shaft_x, 474), fill=(118, 230, 255, 178), width=2)
    for y in range(95, 450, 38):
        draw.line((shaft_x - 22, y, shaft_x + 22, y), fill=(186, 236, 255, 42), width=1)
    draw.rounded_rectangle((shaft_x - 30, 216, shaft_x + 30, 286), radius=14, fill=(20, 40, 55, 220), outline=(142, 236, 255, 155), width=2)
    draw.line((shaft_x, 226, shaft_x, 276), fill=(255, 211, 120, 150), width=2)

    # Orbital routes and network lanes.
    for i, alpha in enumerate([70, 50, 34]):
        box = (52 - i * 20, 64 + i * 22, 610 + i * 40, 502 - i * 10)
        draw.arc(box, start=202, end=336, fill=(115, 218, 255, alpha), width=2)
    for idx, y in enumerate([150, 205, 260, 316, 370]):
        start = (330, y + idx * 3)
        end = (860, y - 45 + idx * 18)
        draw.line((start, end), fill=(82, 206, 245, 52), width=2)
        for t in [0.22, 0.58, 0.82]:
            x = lerp(start[0], end[0], t)
            yy = lerp(start[1], end[1], t)
            draw.ellipse((x - 3, yy - 3, x + 3, yy + 3), fill=(255, 214, 130, 95))

    title_font = font(38)
    body_font = font(16)
    draw.text((54, 46), "玥球电梯", font=title_font, fill=(242, 248, 255, 245))
    draw.text((56, 96), "安全接入 · TUN 模式 · 订阅节点", font=body_font, fill=(178, 211, 230, 210))

    panel = (410, 88, 904, 454)
    draw.rounded_rectangle(panel, radius=30, fill=(10, 18, 27, 104), outline=(156, 217, 240, 42), width=1)
    draw.text((490, 126), "拖入 Applications 完成安装", font=font(24), fill=(236, 246, 252, 230))
    draw.text((524, 160), "保留订阅配置，菜单栏一键启停", font=body_font, fill=(158, 190, 210, 205))
    for cx in [560, 758]:
        draw.rounded_rectangle((cx - 66, 248, cx + 66, 380), radius=24, fill=(255, 255, 255, 18), outline=(170, 220, 240, 50), width=1)
        draw.rounded_rectangle((cx - 84, 368, cx + 84, 426), radius=14, fill=(232, 242, 248, 210))
    draw.line((637, 314, 680, 314), fill=(255, 211, 120, 190), width=3)
    draw.polygon([(680, 314), (666, 305), (666, 323)], fill=(255, 211, 120, 190))

    base = Image.alpha_composite(base, overlay)
    base = base.filter(ImageFilter.UnsharpMask(radius=1.2, percent=108, threshold=3))
    RESOURCES.mkdir(parents=True, exist_ok=True)
    base.convert("RGB").save(BACKGROUND, quality=96)


def rounded_mask(size: int, radius: int) -> Image.Image:
    mask = Image.new("L", (size, size), 0)
    d = ImageDraw.Draw(mask)
    d.rounded_rectangle((0, 0, size, size), radius=radius, fill=255)
    return mask


def draw_icon_png(size: int) -> Image.Image:
    scale = size / 1024
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    mask = rounded_mask(size, int(220 * scale))
    bg = vertical_gradient(size, size, (14, 31, 44), (8, 14, 24)).convert("RGBA")
    glow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    draw_glow(gd, (int(395 * scale), int(448 * scale)), int(400 * scale), (91, 218, 255), 88)
    bg = Image.alpha_composite(bg, glow)
    img.alpha_composite(bg)
    img.putalpha(mask)

    d = ImageDraw.Draw(img)
    cx, cy, r = int(410 * scale), int(455 * scale), int(245 * scale)
    for rr in range(r, 0, -2):
        t = rr / r
        shade = int(232 - 60 * t)
        d.ellipse((cx - rr, cy - rr, cx + rr, cy + rr), fill=(shade, shade + 7, min(255, shade + 20), 235))
    sx = int(565 * scale)
    d.rounded_rectangle((sx - int(16 * scale), int(168 * scale), sx + int(16 * scale), int(828 * scale)), radius=int(16 * scale), fill=(116, 228, 255, 86))
    d.line((sx, int(150 * scale), sx, int(850 * scale)), fill=(148, 239, 255, 230), width=max(2, int(6 * scale)))
    d.rounded_rectangle((sx - int(78 * scale), int(390 * scale), sx + int(78 * scale), int(552 * scale)), radius=int(34 * scale), fill=(16, 36, 52, 235), outline=(177, 244, 255, 180), width=max(2, int(7 * scale)))
    d.line((sx, int(412 * scale), sx, int(530 * scale)), fill=(255, 214, 124, 180), width=max(2, int(5 * scale)))
    d.text((int(342 * scale), int(618 * scale)), "玥", font=font(max(16, int(185 * scale))), fill=(245, 250, 255, 238))
    return img


def draw_icon() -> None:
    if ICONSET.exists():
        shutil.rmtree(ICONSET)
    ICONSET.mkdir(parents=True)
    source_icon = Image.open(APP_ICON_SOURCE).convert("RGBA") if APP_ICON_SOURCE.exists() else None
    specs = [
        ("icon_16x16.png", 16),
        ("icon_16x16@2x.png", 32),
        ("icon_32x32.png", 32),
        ("icon_32x32@2x.png", 64),
        ("icon_128x128.png", 128),
        ("icon_128x128@2x.png", 256),
        ("icon_256x256.png", 256),
        ("icon_256x256@2x.png", 512),
        ("icon_512x512.png", 512),
        ("icon_512x512@2x.png", 1024),
    ]
    for filename, size in specs:
        if source_icon is not None:
            source_icon.resize((size, size), Image.Resampling.LANCZOS).save(ICONSET / filename)
        else:
            draw_icon_png(size).save(ICONSET / filename)
    subprocess.run(["iconutil", "-c", "icns", str(ICONSET), "-o", str(ICNS)], check=True)


def main() -> None:
    draw_background()
    draw_icon()
    print(BACKGROUND)
    print(ICNS)


if __name__ == "__main__":
    main()
