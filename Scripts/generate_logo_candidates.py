#!/usr/bin/env python3
from __future__ import annotations

import math
import random
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "Resources" / "logo-candidates"
SIZE = 1024
SCALE = 3
CANVAS = SIZE * SCALE


def c(v: int) -> int:
    return int(v * SCALE)


def font(size: int) -> ImageFont.FreeTypeFont:
    for path in [
        "/System/Library/Fonts/PingFang.ttc",
        "/System/Library/Fonts/SFNS.ttf",
        "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
    ]:
        try:
            return ImageFont.truetype(path, size=size)
        except Exception:
            continue
    return ImageFont.load_default()


def lerp(a: int, b: int, t: float) -> int:
    return int(a + (b - a) * t)


def rounded_mask(size: int, radius: int) -> Image.Image:
    mask = Image.new("L", (size, size), 0)
    d = ImageDraw.Draw(mask)
    d.rounded_rectangle((0, 0, size, size), radius=radius, fill=255)
    return mask


def gradient_bg(top=(9, 18, 30), bottom=(2, 7, 14)) -> Image.Image:
    img = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 255))
    px = img.load()
    for y in range(CANVAS):
        t = y / max(1, CANVAS - 1)
        color = tuple(lerp(top[i], bottom[i], t) for i in range(3))
        for x in range(CANVAS):
            px[x, y] = (*color, 255)
    return img


def composite_icon(layer: Image.Image) -> Image.Image:
    mask = rounded_mask(CANVAS, c(220))
    shadow = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))
    sd = ImageDraw.Draw(shadow)
    sd.rounded_rectangle((c(32), c(42), c(992), c(1000)), radius=c(210), fill=(0, 0, 0, 90))
    shadow = shadow.filter(ImageFilter.GaussianBlur(c(22)))
    out = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))
    out.alpha_composite(shadow)
    layer.putalpha(mask)
    out.alpha_composite(layer)
    d = ImageDraw.Draw(out)
    d.rounded_rectangle((c(18), c(18), c(1006), c(1006)), radius=c(214), outline=(220, 246, 255, 45), width=c(2))
    return out.resize((SIZE, SIZE), Image.Resampling.LANCZOS)


def glow(draw: ImageDraw.ImageDraw, x: int, y: int, r: int, color, alpha=120) -> None:
    for i in range(18, 0, -1):
        rr = r * i / 18
        a = int(alpha * (i / 18) ** 2)
        draw.ellipse((x - rr, y - rr, x + rr, y + rr), fill=(*color, a))


def line_glow(draw: ImageDraw.ImageDraw, points, color=(78, 216, 255), width=4, alpha=180) -> None:
    for extra, a in [(18, 18), (10, 35), (4, 75)]:
        draw.line(points, fill=(*color, a), width=c(width) + extra)
    draw.line(points, fill=(*color, alpha), width=c(width))


def node(draw: ImageDraw.ImageDraw, x: int, y: int, r=9, color=(91, 225, 255), hot=False) -> None:
    glow(draw, x, y, c(r * (5 if hot else 3)), color, 90 if hot else 55)
    draw.ellipse((x - c(r), y - c(r), x + c(r), y + c(r)), fill=(*color, 230))
    draw.ellipse((x - c(r // 2), y - c(r // 2), x + c(r // 2), y + c(r // 2)), fill=(255, 255, 255, 230))


def moon(draw: ImageDraw.ImageDraw, x: int, y: int, r: int, alpha=240) -> None:
    for i in range(r, 0, -2):
        t = i / r
        shade = int(230 - 60 * t)
        draw.ellipse((x - c(i), y - c(i), x + c(i), y + c(i)), fill=(shade, shade + 7, min(255, shade + 21), alpha))
    for dx, dy, rr, a in [(-22, -16, 10, 36), (24, -26, 7, 28), (26, 20, 15, 32), (-12, 32, 8, 26)]:
        draw.ellipse((x + c(dx - rr), y + c(dy - rr), x + c(dx + rr), y + c(dy + rr)), fill=(90, 112, 134, a))


def earth_arc(draw: ImageDraw.ImageDraw, box, tilt=False) -> None:
    x0, y0, x1, y1 = [c(v) for v in box]
    draw.ellipse((x0, y0, x1, y1), fill=(18, 62, 92, 240), outline=(116, 226, 255, 190), width=c(3))
    for off, a in [(0, 80), (32, 36), (-42, 28)]:
        draw.arc((x0 + c(off), y0 + c(15), x1 + c(off), y1 - c(26)), 196, 330, fill=(140, 238, 255, a), width=c(2))
    draw.arc((x0 - c(16), y0 - c(10), x1 + c(12), y1 + c(8)), 205, 324, fill=(255, 211, 126, 90), width=c(3))
    for x, y in [(145, 720), (230, 650), (318, 590), (400, 676), (250, 790)]:
        node(draw, c(x), c(y), 6, (255, 209, 122), hot=False)


def glass_highlight(draw: ImageDraw.ImageDraw) -> None:
    draw.arc((c(70), c(50), c(950), c(930)), 218, 318, fill=(255, 255, 255, 45), width=c(2))
    draw.arc((c(62), c(42), c(962), c(942)), 220, 315, fill=(92, 218, 255, 38), width=c(2))


def option_a() -> Image.Image:
    img = gradient_bg((10, 24, 38), (3, 8, 15))
    d = ImageDraw.Draw(img)
    glow(d, c(455), c(490), c(380), (41, 190, 235), 70)
    earth_arc(d, (-120, 560, 540, 1220))
    moon(d, c(280), c(188), 58)
    line_glow(d, [(c(275), c(238)), (c(306), c(352)), (c(360), c(475)), (c(462), c(590))], width=3)
    for p in [(306, 352), (360, 475), (462, 590), (610, 520), (720, 430), (820, 340), (580, 710)]:
        node(d, c(p[0]), c(p[1]), 8, (87, 222, 255), hot=p in [(462, 590), (720, 430)])
    for start, end in [((120, 745), (830, 340)), ((190, 640), (910, 565)), ((242, 802), (730, 430)), ((318, 586), (870, 690))]:
        line_glow(d, [(c(start[0]), c(start[1])), (c((start[0]+end[0])//2), c((start[1]+end[1])//2 - 120)), (c(end[0]), c(end[1]))], width=2, alpha=125)
    glass_highlight(d)
    return composite_icon(img)


def option_b() -> Image.Image:
    img = gradient_bg((8, 20, 33), (2, 5, 11))
    d = ImageDraw.Draw(img)
    glow(d, c(512), c(512), c(420), (69, 212, 255), 64)
    for r, a in [(310, 42), (250, 64), (188, 90)]:
        d.ellipse((c(512-r), c(512-r), c(512+r), c(512+r)), outline=(105, 230, 255, a), width=c(5))
    d.arc((c(140), c(258), c(890), c(805)), 190, 348, fill=(255, 209, 124, 120), width=c(5))
    d.arc((c(180), c(210), c(860), c(822)), 188, 342, fill=(72, 222, 255, 190), width=c(7))
    for angle in [205, 232, 260, 292, 318, 342]:
        rad = math.radians(angle)
        x = c(512 + math.cos(rad) * 292)
        y = c(512 + math.sin(rad) * 214)
        node(d, x, y, 9, (82, 226, 255), hot=angle in [260, 318])
    moon(d, c(512), c(512), 105, alpha=230)
    d.rounded_rectangle((c(465), c(280), c(559), c(742)), radius=c(45), fill=(12, 34, 50, 190), outline=(158, 239, 255, 145), width=c(5))
    d.line((c(512), c(248), c(512), c(775)), fill=(138, 238, 255, 170), width=c(4))
    glass_highlight(d)
    return composite_icon(img)


def option_c() -> Image.Image:
    img = gradient_bg((15, 23, 35), (4, 7, 13))
    d = ImageDraw.Draw(img)
    glow(d, c(360), c(668), c(430), (78, 214, 255), 82)
    earth_arc(d, (-160, 630, 640, 1430))
    for i in range(6):
        y = 230 + i * 96
        line_glow(d, [(c(210), c(y)), (c(490), c(y - 70)), (c(880), c(y + 20))], width=2, alpha=95)
    for x, y, hot in [(210, 580, True), (372, 488, False), (550, 420, True), (700, 350, False), (840, 474, True), (678, 635, False)]:
        node(d, c(x), c(y), 10, (72, 224, 255), hot=hot)
    moon(d, c(232), c(226), 48)
    line_glow(d, [(c(235), c(274)), (c(350), c(414)), (c(560), c(590))], width=2, alpha=120)
    d.rounded_rectangle((c(610), c(170), c(850), c(410)), radius=c(58), fill=(8, 18, 29, 128), outline=(186, 232, 246, 65), width=c(3))
    glass_highlight(d)
    return composite_icon(img)


def option_d() -> Image.Image:
    img = gradient_bg((9, 17, 28), (1, 5, 10))
    d = ImageDraw.Draw(img)
    glow(d, c(540), c(475), c(470), (42, 195, 255), 60)
    moon(d, c(300), c(295), 128, alpha=238)
    for angle in range(0, 360, 36):
        rad = math.radians(angle)
        x = c(300 + math.cos(rad) * 220)
        y = c(295 + math.sin(rad) * 160)
        node(d, x, y, 6, (82, 222, 255), hot=False)
    for r, a in [(235, 62), (295, 36), (370, 26)]:
        d.ellipse((c(300-r), c(295-r), c(300+r), c(295+r)), outline=(80, 216, 255, a), width=c(3))
    for start, end in [((300, 295), (802, 304)), ((300, 295), (720, 676)), ((300, 295), (172, 768))]:
        line_glow(d, [(c(start[0]), c(start[1])), (c((start[0]+end[0])//2), c((start[1]+end[1])//2 - 72)), (c(end[0]), c(end[1]))], width=3, alpha=150)
    for x, y in [(802, 304), (720, 676), (172, 768)]:
        node(d, c(x), c(y), 12, (255, 210, 124), hot=True)
    glass_highlight(d)
    return composite_icon(img)


def option_e() -> Image.Image:
    img = gradient_bg((7, 20, 32), (1, 4, 10))
    d = ImageDraw.Draw(img)
    glow(d, c(512), c(512), c(420), (77, 221, 255), 76)
    d.rounded_rectangle((c(215), c(190), c(812), c(834)), radius=c(160), fill=(255, 255, 255, 16), outline=(172, 234, 250, 65), width=c(3))
    for i in range(7):
        x = 265 + i * 80
        node(d, c(x), c(512 + int(math.sin(i) * 80)), 9, (78, 224, 255), hot=i in [2, 5])
        if i:
            line_glow(d, [(c(x - 80), c(512 + int(math.sin(i-1) * 80))), (c(x), c(512 + int(math.sin(i) * 80)))], width=3, alpha=150)
    moon(d, c(512), c(350), 78)
    d.line((c(512), c(438), c(512), c(770)), fill=(145, 240, 255, 130), width=c(3))
    d.rounded_rectangle((c(470), c(555), c(554), c(674)), radius=c(32), fill=(7, 20, 30, 212), outline=(164, 240, 255, 140), width=c(4))
    glass_highlight(d)
    return composite_icon(img)


def option_f() -> Image.Image:
    img = gradient_bg((13, 19, 29), (4, 5, 9))
    d = ImageDraw.Draw(img)
    glow(d, c(512), c(512), c(420), (55, 190, 245), 66)
    for y in [300, 430, 560, 690]:
        d.line((c(218), c(y), c(806), c(y)), fill=(75, 210, 255, 42), width=c(2))
    for x in [260, 392, 524, 656, 788]:
        d.line((c(x), c(252), c(x), c(740)), fill=(75, 210, 255, 35), width=c(2))
    d.rounded_rectangle((c(300), c(250), c(724), c(744)), radius=c(92), fill=(7, 15, 25, 155), outline=(165, 229, 246, 92), width=c(4))
    for pts in [
        [(350, 640), (448, 520), (565, 576), (672, 420)],
        [(350, 390), (470, 466), (585, 360), (700, 478)],
    ]:
        line_glow(d, [(c(x), c(y)) for x, y in pts], width=4, alpha=160)
        for x, y in pts:
            node(d, c(x), c(y), 10, (84, 226, 255), hot=(x, y) in [(448, 520), (585, 360)])
    moon(d, c(512), c(512), 96, alpha=228)
    glass_highlight(d)
    return composite_icon(img)


def write_sheet(items: list[tuple[str, Image.Image]]) -> Image.Image:
    thumb = 260
    pad = 34
    label_h = 42
    sheet = Image.new("RGB", (pad + 3 * (thumb + pad), pad + 2 * (thumb + label_h + pad)), (238, 242, 246))
    d = ImageDraw.Draw(sheet)
    f = font(24)
    for idx, (label, img) in enumerate(items):
        col = idx % 3
        row = idx // 3
        x = pad + col * (thumb + pad)
        y = pad + row * (thumb + label_h + pad)
        sheet.paste(img.resize((thumb, thumb), Image.Resampling.LANCZOS), (x, y), img.resize((thumb, thumb), Image.Resampling.LANCZOS))
        tw = d.textlength(label, font=f)
        d.text((x + (thumb - tw) / 2, y + thumb + 10), label, font=f, fill=(30, 38, 48))
    return sheet


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    makers = [
        ("A  地月网络骨干", option_a),
        ("B  代理隧道环", option_b),
        ("C  全球路由流", option_c),
        ("D  月球中继徽章", option_d),
        ("E  电梯弱化符号", option_e),
        ("F  极简节点矩阵", option_f),
    ]
    items: list[tuple[str, Image.Image]] = []
    for idx, (label, make) in enumerate(makers, start=1):
        img = make()
        path = OUT / f"logo-{chr(64+idx).lower()}.png"
        img.save(path)
        print(path)
        items.append((label, img))
    sheet = write_sheet(items)
    sheet_path = OUT / "logo-contact-sheet.png"
    sheet.save(sheet_path, quality=96)
    print(sheet_path)


if __name__ == "__main__":
    main()
