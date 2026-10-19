# The vn-ranger mark

![vn-ranger brand sheet](contact-sheet.png)

A girdled crystal, shared with every application in the vecnode/vn suite. The lines
are vn-launcher's; the colour inside is ranger's.

The suite keeps one mark and changes one thing per application: the **inlay**, the
colour that fills the facets. vn-launcher leaves it empty. vn-ranger fills it with
ember. A new application gets the same crystal and a new inlay; it does not get a new
shape, a rotation, an outline variant or a different gradient direction.

This file is the design record. `MANIFEST.toml` is the machine-readable one: every
palette value, every proportion, and the SHA-256 of every file in this directory.

## Construction

The mark lives on the same 24-unit grid as vn-launcher, so the two cannot drift apart:

- hexagon vertices: `(12,2.8) (20.8,7.4) (20.8,16.6) (12,21.2) (3.2,16.6) (3.2,7.4)`;
- crown ridge: `(3.2,7.4) → (12,12) → (20.8,7.4)`;
- spine: `(12,2.8) → (12,21.2)`;
- girdle: `(12,15.4) → (3.2,16.6)` and `(12,15.4) → (20.8,16.6)`;
- stroke: `2.914` units, round caps, round joins;
- facets: six, separated by the crown ridge, the girdle and the spine.

Every endpoint sits on a hexagon vertex or on the spine. That is what keeps the
facets meeting cleanly instead of crossing. The inlay is one hexagon fill beneath the
linework, so the ridges stay crisp and the facets read as one crystal rather than six
coloured tiles.

The inlay is a vertical gradient: `#FFA45E` at the crown, `#F26A21` at 55%, `#D14A0C`
at the base. The crown catches the light; the base sits deeper.

## Colour

| Token | Value | Use |
|---|---|---|
| Ember highlight | `#FFA45E` | Top of the inlay gradient; links on dark |
| Ember | `#F26A21` | The suite colour; the catalogue, badges, emphasis |
| Ember deep | `#D14A0C` | Bottom of the inlay gradient |
| Ink | `#0B0D10` | Linework on light; the application tile |
| Paper | `#FFFFFF` | Linework on dark |
| Muted | `#9AA1AC` | Secondary text, never the mark |

Contrast, measured with the WCAG relative-luminance formula:

| Pair | Ratio | Verdict |
|---|---:|---|
| Ember `#F26A21` on Ink `#0B0D10` | 6.36:1 | AA for normal text |
| Ink on Ember | 6.36:1 | AA for normal text |
| White on Ember | 3.06:1 | Large text (24 px+), icons and non-text only |
| Ember on Paper | 3.06:1 | Large text, icons and non-text only |
| Highlight `#FFA45E` on Ink | 9.94:1 | AA for normal text |

**Ink on ember is the default for small labels.** White on ember is only for large
type or icons; a 13 px white label on ember is below AA and is not used.

Colour is identity, not status. The mark stays ember whether a scan is clean, busy or
alarming. Findings have their own semantic colours (green, amber, red) and never
recolour the mark.

## Clear space

Keep a margin of **6 units** on every side, one quarter of the mark's 24-unit height.
At 1024 px that is 256 px; at 24 px it is 6 px. Nothing enters that margin: no text, no
badge, no border, no other mark.

The application tile's own black square is the exception: the tile may touch the
margin of the surface it sits on, but the crystal inside it still keeps its clear
space within the tile.

## Minimum sizes

| Asset | Digital | Print |
|---|---:|---:|
| Bare mark (`vn-ranger.svg`, `vn-ranger-white.svg`) | 24 px | 10 mm |
| Application tile (`vn-ranger-app-*`) | 16 px | 6 mm |

Below 32 px the faceting costs legibility. At 16 px the bare mark reads as a dark
hexagonal blob with ember notches; use the application tile there, because the tile
gives the eye a solid silhouette and the ember gives it a colour to find.

## Which file to use

| Family | For |
|---|---|
| `vn-ranger.svg`, `vn-ranger-<size>.png` | Light backgrounds. Ink linework, ember inlay, transparent elsewhere. |
| `vn-ranger-white.svg`, `vn-ranger-white-<size>.png` | Dark backgrounds. White linework, ember inlay, transparent elsewhere. |
| `vn-ranger-app.svg`, `vn-ranger-app-<size>.png` | An application icon: the mark on the suite's black tile, with white ridges. |
| `vn-ranger-app.rgba` | 64×64 unmultiplied RGBA of the tile, for packaging, a store listing or a shortcut. |
| `vn-ranger-white.rgba` | 64×64 unmultiplied RGBA of the bare white mark, for the tray icon. |

If a target takes raw bytes rather than a file, it gets one of the two `.rgba` files and
not a PNG decoder: both are 16,384 bytes, exactly the three fields `egui::IconData` takes.

Sizes are 16, 24, 32, 48, 64, 128, 256, 512 and 1024 pixels square. Every PNG was
rendered at its exact size from the SVG, not downscaled from a master. Prefer the SVG
wherever the target accepts it.

## The application icon

- Tile: 1024 × 1024, corner radius **308** (30.1%), fill `#0B0D10`.
- Crystal: the same 24-unit geometry, scaled **22.73×** and translated **239.25 px**,
  so the visible mark is about 468 × 486 px and sits at the optical centre.
- Ridges: white; inlay: ember.
- The raw icon is 64 × 64 unmultiplied RGBA, 16,384 bytes, exactly the three fields
  `egui::IconData` takes.

The tile is black, not ember. An icon has to hold its own against whatever is behind
it: a bare black glyph disappears on a dark taskbar and a bare white one on a light
taskbar, whereas a black tile with a white crystal and an ember inlay reads on both.

**Where ranger itself uses which.** The application tile is the window icon and the mark
in the top bar, exactly as it always was: it reads on paper and on ink, so the interface
does not swap artwork when the theme changes. The **tray** is the one place the bare white
mark is used, because a status area asks for a glyph at 16–24 px rather than a tile, and a
tile there is a black square among the system's own icons.

## Using it

**Do**

- put the light mark on paper and the white mark on ink;
- use the application tile for a taskbar, a window, a store listing or a favicon;
- keep the clear space and the proportions;
- pair the mark with the name in text when the mark is small;
- use ink on ember for small labels and buttons.

**Do not**

- rotate, skew, stretch, crop, outline, bevel or add a shadow to the mark;
- recolour the inlay, or change its gradient direction;
- use the mark as a repeating pattern, a texture or a loading spinner;
- put the bare mark on a busy photograph or a low-contrast background;
- place white text on ember below 24 px;
- use the mark to imply a certification, a clean bill of health or a detection it did
  not make;
- redraw the facets. The geometry is the suite identifier; a new application changes
  the inlay, not the crystal.

## Type

The wordmark is not part of this asset set yet. If one is added, use **Inter** (SIL
Open Font License 1.1), set the name in title case, and keep the same clear space
around the lockup. Do not draw a custom wordmark in the crystal's style: the crystal
is the mark, and the name is the name.

## Accessibility

- The mark is decorative when the name is beside it; give the image an empty `alt` in
  that case. When it stands alone, `alt="vn-ranger"`.
- Colour is never the only signal. The inlay identifies the application; it does not
  report a state.
- The contrast pairs in the table above are the only ones approved for text.
- At small sizes, use the tile rather than a thin-stroked bare mark.

## Regenerating

The SVGs are the source of truth. To regenerate:

1. Render each SVG at the exact pixel size (a headless browser, `resvg`, or any SVG
   rasteriser) onto a transparent canvas.
2. For the application tile, keep the black rounded square; only the corners are
   transparent.
3. Decode `vn-ranger-app-64.png` to unmultiplied RGBA and write the 16,384 raw bytes to
   `vn-ranger-app.rgba`; decode `vn-ranger-white-64.png` the same way to
   `vn-ranger-white.rgba`.
4. Regenerate `contact-sheet.png` from the rendered set.
5. Regenerate `MANIFEST.toml` so every digest matches the files that shipped.

A future `cargo xtask logo` will own steps 1–5, so the set is reproducible rather than
hand-maintained. Until then, the geometry above and the SVGs are enough to regenerate
it exactly.

## Licence

AGPL-3.0-only, like the rest of the repository — see
[`../../LICENSE`](../../LICENSE). The mark is original vecnode work and contains no
third-party asset.
