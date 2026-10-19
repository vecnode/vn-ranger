# Third-party notices

vn-ranger is licensed **AGPL-3.0-only** — see [LICENSE](LICENSE). That licence covers the
code in this repository. It does not cover, and does not relicense, the third-party work
listed on this page: each item keeps the terms its authors chose, and this page is where
those terms are named.

Two words are used precisely below. **Vendored** means the source lives in this
repository. **Resolved** means the crate is fetched from crates.io at the version
`Cargo.lock` pins. Nothing in this tree is vendored.

## What travels with a release

| Component | Licence | Where it lives |
|---|---|---|
| The Rust crate tree | the expressions in the table further down | resolved from crates.io; `Cargo.lock` pins every version. No sanitised or patched copy of a crate is carried here |
| Inter (Regular, SemiBold) | SIL Open Font License 1.1 | `assets/fonts/Inter-*.ttf`, with the text in `assets/fonts/LICENSE-Inter.txt` |
| JetBrains Mono (Regular) | SIL Open Font License 1.1 | `assets/fonts/JetBrainsMono-Regular.ttf`, with the text in `assets/fonts/LICENSE-JetBrainsMono.txt` |
| egui's default font set — Ubuntu Light, Noto Emoji, Hack, emoji-icon-font and egui's own icons | Ubuntu Font Licence 1.0, SIL OFL 1.1, MIT and egui's own terms, file by file | embedded from `epaint_default_fonts` 0.37.0 through `eframe`'s `default_fonts` feature. Each licence text ships inside that crate |
| The ClamAV signature formats (`.hdb`, `.hsb`, `.ndb`) | a documented file format, not code | ranger reads and writes these files. **No ClamAV source is copied**, so ClamAV's GPL-2.0 does not reach this tree — and this tree's AGPL does not reach ClamAV |
| YARA-X | BSD-3-Clause | **not in the default build.** Only the optional `content-scan` feature adds it. A release that enables that feature must extend this page with the YARA-X tree, because the default page would then be incomplete |

The fonts are embedded with `include_bytes!`, so they are part of the binary in a release
archive. Their licences permit that; they do not make the binary AGPL-free, and the AGPL
does not relicense them.

## Copyleft inside the tree

Three crates deserve a sentence rather than a table row, because a reader scanning for
copyleft should find the answer without inferring it:

- **`option-ext` 0.2.0 is MPL-2.0** and offers no alternative. It is used unmodified.
  MPL-2.0 is file-level: it keeps those files under MPL-2.0 and asks nothing of the rest
  of the work, which is why `AGENTS.md` §8 permits it.
- **`r-efi` 5.3.0 and 6.0.0** are offered as `MIT OR Apache-2.0 OR LGPL-2.1-or-later`.
  Ranger relies on the **MIT** arm. **`self_cell` 1.3.0** is offered as
  `Apache-2.0 OR GPL-2.0-only`; ranger relies on the **Apache-2.0** arm. The choice is
  recorded here so that nobody has to infer which arm a build took.
- **No crate in either list is GPL, AGPL or LGPL in effect.** `AGENTS.md` §8 is the rule
  that keeps it that way: a GPL, AGPL or LGPL dependency is refused, and `cargo xtask ci`
  is what catches one. That rule governs dependencies. It says nothing about this
  project's own licence, which is AGPL-3.0-only, and the two are not in tension: a
  copyleft project may depend on permissively licensed work, and this one does.

## How this page is produced

The tables are generated from `Cargo.lock` with `cargo metadata --format-version 1`, not
typed by hand, so a version here is the version a build actually uses. Reproduction:

```bash
cargo metadata --format-version 1 --offline > metadata.json
```

and a script over `packages` and `resolve`. `Scope` is decided from the resolve graph:
`build` is a crate the default build of any platform reaches through a normal or build
dependency, and `test` is one only the test targets reach — so a crate marked `test` is
not in a release binary.

A stale copy of this page is a documentation defect, not a legal formality. It is
regenerated in the same change that adds, removes or upgrades a dependency, and
`docs/RELEASES.md` §7 has the checklist line that says so.

## Totals

544 crates are reached by the default build of a release binary — the graph for every
platform ranger is built for, Windows, macOS and Linux included — and a further 17 are
reached only by the test targets. The 561 rows in the table further down are the whole of
it; this table groups them by the expression each crate declares.

| Licence expression | Crates in the default build |
|---|---:|
| `MIT OR Apache-2.0` | 257 |
| `MIT` | 110 |
| `Apache-2.0 OR MIT` | 48 |
| `MIT/Apache-2.0` | 18 |
| `Unicode-3.0` | 18 |
| `Apache-2.0` | 15 |
| `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | 15 |
| `Zlib OR Apache-2.0 OR MIT` | 12 |
| `Unlicense OR MIT` | 9 |
| `MIT OR Apache-2.0 OR Zlib` | 6 |
| `Zlib` | 4 |
| `Apache-2.0/MIT` | 3 |
| `ISC` | 3 |
| `BSD-2-Clause OR Apache-2.0 OR MIT` | 2 |
| `BSD-3-Clause OR Apache-2.0` | 2 |
| `BSD-3-Clause OR MIT OR Apache-2.0` | 2 |
| `BSL-1.0` | 2 |
| `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | 2 |
| `MIT OR Zlib OR Apache-2.0` | 2 |
| `Unlicense/MIT` | 2 |
| `(MIT OR Apache-2.0) AND OFL-1.1 AND Ubuntu-font-1.0` | 1 |
| `(MIT OR Apache-2.0) AND Unicode-3.0` | 1 |
| `0BSD OR MIT OR Apache-2.0` | 1 |
| `Apache-2.0 / MIT` | 1 |
| `Apache-2.0 AND MIT` | 1 |
| `Apache-2.0 OR GPL-2.0-only` | 1 |
| `Apache-2.0 WITH LLVM-exception` | 1 |
| `BSD-3-Clause` | 1 |
| `CC0-1.0` | 1 |
| `MIT / Apache-2.0` | 1 |
| `MPL-2.0` | 1 |
| `Unlicense` | 1 |
| **Total** | **544** |

Expressions are reproduced as the crates declare them, `OR` included, because that is what
a reader has to weigh. Where an expression offers a choice, the arm ranger relies on is
named in the section above for the three crates where the choice is copyleft.

## Every crate

| Crate | Version | Licence | Scope |
|---|---|---|---|
| `accesskit` | 0.25.1 | MIT OR Apache-2.0 | build |
| `accesskit_atspi_common` | 0.21.0 | MIT OR Apache-2.0 | build |
| `accesskit_consumer` | 0.39.1 | MIT OR Apache-2.0 | build |
| `accesskit_ios` | 0.2.1 | MIT OR Apache-2.0 | build |
| `accesskit_macos` | 0.27.1 | MIT OR Apache-2.0 | build |
| `accesskit_unix` | 0.24.0 | MIT OR Apache-2.0 | build |
| `accesskit_windows` | 0.35.1 | MIT OR Apache-2.0 | build |
| `accesskit_winit` | 0.34.1 | Apache-2.0 | build |
| `adler2` | 2.0.1 | 0BSD OR MIT OR Apache-2.0 | build |
| `ahash` | 0.8.12 | MIT OR Apache-2.0 | build |
| `aho-corasick` | 1.1.5 | Unlicense OR MIT | build |
| `allocator-api2` | 0.2.21 | MIT OR Apache-2.0 | build |
| `ambient-authority` | 0.0.2 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | build |
| `android_system_properties` | 0.1.6 | MIT OR Apache-2.0 | build |
| `android-activity` | 0.6.1 | MIT OR Apache-2.0 | build |
| `android-properties` | 0.2.2 | MIT | build |
| `anstream` | 1.0.0 | MIT OR Apache-2.0 | build |
| `anstyle` | 1.0.14 | MIT OR Apache-2.0 | build |
| `anstyle-parse` | 1.0.0 | MIT OR Apache-2.0 | build |
| `anstyle-query` | 1.1.5 | MIT OR Apache-2.0 | build |
| `anstyle-wincon` | 3.0.11 | MIT OR Apache-2.0 | build |
| `anyhow` | 1.0.104 | MIT OR Apache-2.0 | build |
| `arboard` | 3.7.0 | MIT OR Apache-2.0 | build |
| `arrayvec` | 0.7.8 | MIT OR Apache-2.0 | build |
| `as-raw-xcb-connection` | 1.0.1 | MIT OR Apache-2.0 | build |
| `ash` | 0.38.0+1.3.281 | MIT OR Apache-2.0 | build |
| `async-broadcast` | 0.7.2 | MIT OR Apache-2.0 | build |
| `async-channel` | 2.5.0 | Apache-2.0 OR MIT | build |
| `async-executor` | 1.14.0 | Apache-2.0 OR MIT | build |
| `async-io` | 2.6.0 | Apache-2.0 OR MIT | build |
| `async-lock` | 3.4.2 | Apache-2.0 OR MIT | build |
| `async-process` | 2.5.0 | Apache-2.0 OR MIT | build |
| `async-recursion` | 1.2.0 | MIT OR Apache-2.0 | build |
| `async-signal` | 0.2.14 | Apache-2.0 OR MIT | build |
| `async-task` | 4.7.1 | Apache-2.0 OR MIT | build |
| `async-trait` | 0.1.92 | MIT OR Apache-2.0 | build |
| `atomic-waker` | 1.1.2 | Apache-2.0 OR MIT | build |
| `atspi` | 0.29.0 | Apache-2.0 OR MIT | build |
| `atspi-common` | 0.13.0 | Apache-2.0 OR MIT | build |
| `atspi-proxies` | 0.13.0 | Apache-2.0 OR MIT | build |
| `autocfg` | 1.5.1 | Apache-2.0 OR MIT | build |
| `base64` | 0.23.1 | MIT OR Apache-2.0 | build |
| `bindgen` | 0.72.1 | BSD-3-Clause | build |
| `bit-set` | 0.10.0 | Apache-2.0 OR MIT | build |
| `bit-vec` | 0.9.1 | Apache-2.0 OR MIT | build |
| `bitflags` | 1.3.2 | MIT/Apache-2.0 | build |
| `bitflags` | 2.13.2 | MIT OR Apache-2.0 | build |
| `block-buffer` | 0.10.4 | MIT OR Apache-2.0 | test |
| `block-buffer` | 0.12.1 | MIT OR Apache-2.0 | build |
| `block2` | 0.5.1 | MIT | build |
| `block2` | 0.6.2 | MIT | build |
| `blocking` | 1.7.0 | Apache-2.0 OR MIT | build |
| `bumpalo` | 3.20.3 | MIT OR Apache-2.0 | build |
| `bytemuck` | 1.25.2 | Zlib OR Apache-2.0 OR MIT | build |
| `bytemuck_derive` | 1.12.1 | Zlib OR Apache-2.0 OR MIT | build |
| `byteorder` | 1.5.0 | Unlicense OR MIT | build |
| `byteorder-lite` | 0.1.0 | Unlicense OR MIT | build |
| `bytes` | 1.12.1 | MIT | build |
| `calloop` | 0.13.0 | MIT | build |
| `calloop` | 0.14.5 | MIT | build |
| `calloop-wayland-source` | 0.3.0 | MIT | build |
| `calloop-wayland-source` | 0.4.1 | MIT | build |
| `cap-primitives` | 4.0.3 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | build |
| `cap-std` | 4.0.3 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | build |
| `cc` | 1.8.0 | MIT OR Apache-2.0 | build |
| `cexpr` | 0.6.0 | Apache-2.0/MIT | build |
| `cfb` | 0.15.0 | MIT | build |
| `cfg_aliases` | 0.2.2 | MIT | build |
| `cfg-if` | 1.0.5 | MIT OR Apache-2.0 | build |
| `cgl` | 0.3.2 | MIT / Apache-2.0 | build |
| `cipher` | 0.4.4 | MIT OR Apache-2.0 | test |
| `clang-sys` | 1.9.1 | Apache-2.0 | build |
| `clipboard-win` | 5.4.1 | BSL-1.0 | build |
| `codespan-reporting` | 0.13.1 | Apache-2.0 | build |
| `color` | 0.3.3 | Apache-2.0 OR MIT | build |
| `colorchoice` | 1.0.5 | MIT OR Apache-2.0 | build |
| `combine` | 4.6.9 | MIT | build |
| `concurrent-queue` | 2.5.0 | Apache-2.0 OR MIT | build |
| `const-oid` | 0.10.2 | Apache-2.0 OR MIT | build |
| `core-foundation` | 0.9.4 | MIT OR Apache-2.0 | build |
| `core-foundation-sys` | 0.8.7 | MIT OR Apache-2.0 | build |
| `core-graphics` | 0.23.2 | MIT OR Apache-2.0 | build |
| `core-graphics-types` | 0.1.3 | MIT OR Apache-2.0 | build |
| `cpufeatures` | 0.2.17 | MIT OR Apache-2.0 | test |
| `cpufeatures` | 0.3.1 | MIT OR Apache-2.0 | build |
| `crc32fast` | 1.5.2 | MIT OR Apache-2.0 | build |
| `crossbeam-channel` | 0.5.17 | MIT OR Apache-2.0 | build |
| `crossbeam-utils` | 0.8.23 | MIT OR Apache-2.0 | build |
| `crunchy` | 0.2.4 | MIT | build |
| `crypto-common` | 0.1.7 | MIT OR Apache-2.0 | test |
| `crypto-common` | 0.2.2 | MIT OR Apache-2.0 | build |
| `ct-codecs` | 1.1.8 | MIT | test |
| `cursor-icon` | 1.2.0 | MIT OR Apache-2.0 OR Zlib | build |
| `defmt` | 1.2.0 | MIT OR Apache-2.0 | build |
| `defmt-macros` | 1.2.0 | MIT OR Apache-2.0 | build |
| `defmt-parser` | 1.1.0 | MIT OR Apache-2.0 | build |
| `deranged` | 0.5.9 | MIT OR Apache-2.0 | build |
| `digest` | 0.10.7 | MIT OR Apache-2.0 | test |
| `digest` | 0.11.3 | MIT OR Apache-2.0 | build |
| `directories` | 6.0.0 | MIT OR Apache-2.0 | build |
| `dirs-sys` | 0.5.0 | MIT OR Apache-2.0 | build |
| `dispatch` | 0.2.0 | MIT | build |
| `dispatch2` | 0.3.1 | Zlib OR Apache-2.0 OR MIT | build |
| `displaydoc` | 0.2.7 | MIT OR Apache-2.0 | build |
| `dlib` | 0.5.3 | MIT | build |
| `document-features` | 0.2.12 | MIT OR Apache-2.0 | build |
| `downcast-rs` | 1.2.1 | MIT/Apache-2.0 | build |
| `dpi` | 0.1.2 | Apache-2.0 AND MIT | build |
| `ecolor` | 0.37.0 | MIT OR Apache-2.0 | build |
| `eframe` | 0.37.0 | MIT OR Apache-2.0 | build |
| `egui` | 0.37.0 | MIT OR Apache-2.0 | build |
| `egui_extras` | 0.37.0 | MIT OR Apache-2.0 | build |
| `egui_glow` | 0.37.0 | MIT OR Apache-2.0 | build |
| `egui-wgpu` | 0.37.0 | MIT OR Apache-2.0 | build |
| `egui-winit` | 0.37.0 | MIT OR Apache-2.0 | build |
| `either` | 1.19.0 | MIT OR Apache-2.0 | build |
| `emath` | 0.37.0 | MIT OR Apache-2.0 | build |
| `endi` | 1.1.1 | MIT | build |
| `enum-map` | 3.1.0 | MIT OR Apache-2.0 | build |
| `enum-map-derive` | 1.0.1 | MIT OR Apache-2.0 | build |
| `enumflags2` | 0.7.12 | MIT OR Apache-2.0 | build |
| `enumflags2_derive` | 0.7.12 | MIT OR Apache-2.0 | build |
| `env_filter` | 2.0.0 | MIT OR Apache-2.0 | build |
| `env_logger` | 0.11.11 | MIT OR Apache-2.0 | build |
| `epaint` | 0.37.0 | MIT OR Apache-2.0 | build |
| `epaint_default_fonts` | 0.37.0 | (MIT OR Apache-2.0) AND OFL-1.1 AND Ubuntu-font-1.0 | build |
| `equivalent` | 1.0.3 | Apache-2.0 OR MIT | build |
| `errno` | 0.3.14 | MIT OR Apache-2.0 | build |
| `error-code` | 3.4.0 | BSL-1.0 | build |
| `euclid` | 0.22.14 | MIT OR Apache-2.0 | build |
| `event-listener` | 5.4.2 | Apache-2.0 OR MIT | build |
| `event-listener-strategy` | 0.5.4 | Apache-2.0 OR MIT | build |
| `fastrand` | 2.5.0 | Apache-2.0 OR MIT | build |
| `fax` | 0.2.7 | MIT | build |
| `fdeflate` | 0.3.7 | MIT OR Apache-2.0 | build |
| `fearless_simd` | 0.4.1 | Apache-2.0 OR MIT | build |
| `find-msvc-tools` | 0.1.14 | MIT OR Apache-2.0 | build |
| `fixedbitset` | 0.5.7 | MIT OR Apache-2.0 | build |
| `flate2` | 1.1.10 | MIT OR Apache-2.0 | build |
| `fnv` | 1.0.7 | Apache-2.0 / MIT | build |
| `foldhash` | 0.1.5 | Zlib | build |
| `foldhash` | 0.2.0 | Zlib | build |
| `font-types` | 0.12.7 | MIT OR Apache-2.0 | build |
| `foreign-types` | 0.5.0 | MIT/Apache-2.0 | build |
| `foreign-types-macros` | 0.2.4 | MIT/Apache-2.0 | build |
| `foreign-types-shared` | 0.3.1 | MIT/Apache-2.0 | build |
| `form_urlencoded` | 1.2.2 | MIT OR Apache-2.0 | build |
| `fs-set-times` | 0.20.3 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | build |
| `futures-channel` | 0.3.34 | MIT OR Apache-2.0 | build |
| `futures-core` | 0.3.34 | MIT OR Apache-2.0 | build |
| `futures-io` | 0.3.34 | MIT OR Apache-2.0 | build |
| `futures-lite` | 2.6.1 | Apache-2.0 OR MIT | build |
| `futures-macro` | 0.3.34 | MIT OR Apache-2.0 | build |
| `futures-task` | 0.3.34 | MIT OR Apache-2.0 | build |
| `futures-util` | 0.3.34 | MIT OR Apache-2.0 | build |
| `generic-array` | 0.14.7 | MIT | test |
| `gethostname` | 1.1.0 | Apache-2.0 | build |
| `getrandom` | 0.3.4 | MIT OR Apache-2.0 | build |
| `getrandom` | 0.4.3 | MIT OR Apache-2.0 | build |
| `gl_generator` | 0.14.0 | Apache-2.0 | build |
| `glifo` | 0.3.0 | Apache-2.0 OR MIT | build |
| `glob` | 0.3.4 | MIT OR Apache-2.0 | build |
| `glow` | 0.17.0 | MIT OR Apache-2.0 OR Zlib | build |
| `glutin` | 0.32.3 | Apache-2.0 | build |
| `glutin_egl_sys` | 0.7.1 | Apache-2.0 | build |
| `glutin_glx_sys` | 0.6.1 | Apache-2.0 | build |
| `glutin_wgl_sys` | 0.6.1 | Apache-2.0 | build |
| `glutin-winit` | 0.5.0 | MIT | build |
| `gpu-allocator` | 0.28.0 | MIT OR Apache-2.0 | build |
| `guillotiere` | 0.7.0 | MIT/Apache-2.0 | build |
| `half` | 2.7.1 | MIT OR Apache-2.0 | build |
| `harfrust` | 0.12.0 | MIT | build |
| `hashbrown` | 0.15.5 | MIT OR Apache-2.0 | build |
| `hashbrown` | 0.16.1 | MIT OR Apache-2.0 | build |
| `hashbrown` | 0.17.1 | MIT OR Apache-2.0 | build |
| `hermit-abi` | 0.5.3 | MIT OR Apache-2.0 | build |
| `hex` | 0.4.3 | MIT OR Apache-2.0 | build |
| `hmac` | 0.12.1 | MIT OR Apache-2.0 | test |
| `home` | 0.5.12 | MIT OR Apache-2.0 | build |
| `hybrid-array` | 0.4.15 | MIT OR Apache-2.0 | build |
| `icu_collections` | 2.3.0 | Unicode-3.0 | build |
| `icu_locale_core` | 2.3.0 | Unicode-3.0 | build |
| `icu_normalizer` | 2.3.0 | Unicode-3.0 | build |
| `icu_normalizer_data` | 2.3.0 | Unicode-3.0 | build |
| `icu_properties` | 2.3.0 | Unicode-3.0 | build |
| `icu_properties_data` | 2.3.0 | Unicode-3.0 | build |
| `icu_provider` | 2.3.1 | Unicode-3.0 | build |
| `idna` | 1.1.0 | MIT OR Apache-2.0 | build |
| `idna_adapter` | 1.2.2 | Apache-2.0 OR MIT | build |
| `image` | 0.25.10 | MIT OR Apache-2.0 | build |
| `indexmap` | 2.14.2 | Apache-2.0 OR MIT | build |
| `inotify` | 0.11.5 | ISC | build |
| `inotify-sys` | 0.1.8 | ISC | build |
| `inout` | 0.1.4 | MIT OR Apache-2.0 | test |
| `io-extras` | 0.19.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | build |
| `io-lifetimes` | 2.0.4 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | build |
| `io-lifetimes` | 3.0.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | build |
| `ipnet` | 2.12.2 | MIT OR Apache-2.0 | build |
| `is_elevated` | 0.1.2 | MIT | build |
| `is_terminal_polyfill` | 1.70.2 | MIT OR Apache-2.0 | build |
| `itertools` | 0.13.0 | MIT OR Apache-2.0 | build |
| `itertools` | 0.15.0 | MIT OR Apache-2.0 | build |
| `itoa` | 1.0.18 | MIT OR Apache-2.0 | build |
| `jiff` | 0.2.38 | Unlicense OR MIT | build |
| `jiff-core` | 0.1.1 | Unlicense OR MIT | build |
| `jiff-static` | 0.2.38 | Unlicense OR MIT | build |
| `jni` | 0.22.4 | MIT OR Apache-2.0 | build |
| `jni-macros` | 0.22.4 | MIT OR Apache-2.0 | build |
| `jni-sys` | 0.3.1 | MIT OR Apache-2.0 | build |
| `jni-sys` | 0.4.1 | MIT OR Apache-2.0 | build |
| `jni-sys-macros` | 0.4.1 | MIT OR Apache-2.0 | build |
| `jobserver` | 0.1.35 | MIT OR Apache-2.0 | build |
| `js-sys` | 0.3.106 | MIT OR Apache-2.0 | build |
| `keyboard-types` | 0.8.3 | MIT OR Apache-2.0 | build |
| `khronos_api` | 3.1.0 | Apache-2.0 | build |
| `khronos-egl` | 6.0.0 | MIT/Apache-2.0 | build |
| `kqueue` | 1.2.1 | MIT | build |
| `kqueue-sys` | 1.1.2 | MIT | build |
| `ksni` | 0.3.6 | Unlicense | build |
| `kurbo` | 0.13.1 | Apache-2.0 OR MIT | build |
| `libc` | 0.2.191 | MIT OR Apache-2.0 | build |
| `libloading` | 0.8.9 | ISC | build |
| `libm` | 0.2.16 | MIT | build |
| `libredox` | 0.1.25 | MIT | build |
| `linebender_resource_handle` | 0.1.1 | Apache-2.0 OR MIT | build |
| `linux-raw-sys` | 0.12.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | build |
| `linux-raw-sys` | 0.4.15 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | build |
| `litemap` | 0.8.3 | Unicode-3.0 | build |
| `litrs` | 1.0.1 | MIT OR Apache-2.0 | build |
| `lock_api` | 0.4.14 | MIT OR Apache-2.0 | build |
| `log` | 0.4.34 | MIT OR Apache-2.0 | build |
| `maybe-owned` | 0.3.4 | MIT OR Apache-2.0 | build |
| `md-5` | 0.11.0 | MIT OR Apache-2.0 | build |
| `memchr` | 2.8.3 | Unlicense OR MIT | build |
| `memmap2` | 0.9.11 | MIT OR Apache-2.0 | build |
| `memoffset` | 0.9.1 | MIT | build |
| `minimal-lexical` | 0.2.1 | MIT/Apache-2.0 | build |
| `minisign` | 0.10.0 | MIT | test |
| `minisign-verify` | 0.3.0 | MIT | build |
| `miniz_oxide` | 0.8.9 | MIT OR Zlib OR Apache-2.0 | build |
| `miniz_oxide` | 0.9.1 | MIT OR Zlib OR Apache-2.0 | build |
| `mio` | 1.2.4 | MIT | build |
| `moxcms` | 0.8.1 | BSD-3-Clause OR Apache-2.0 | build |
| `muda` | 0.21.2 | Apache-2.0 OR MIT | build |
| `naga` | 30.0.1 | MIT OR Apache-2.0 | build |
| `naga-types` | 30.0.1 | MIT OR Apache-2.0 | build |
| `ndk` | 0.9.0 | MIT OR Apache-2.0 | build |
| `ndk-context` | 0.1.1 | MIT OR Apache-2.0 | build |
| `ndk-sys` | 0.6.0+11769913 | MIT OR Apache-2.0 | build |
| `netlink-packet-core` | 0.7.0 | MIT | build |
| `netlink-packet-sock-diag` | 0.4.2 | MIT | build |
| `netlink-packet-utils` | 0.5.2 | MIT | build |
| `netlink-sys` | 0.8.8 | MIT | build |
| `netstat2` | 0.11.2 | MIT OR Apache-2.0 | build |
| `nix` | 0.31.3 | MIT | build |
| `nohash-hasher` | 0.2.0 | Apache-2.0 OR MIT | build |
| `nom` | 7.1.3 | MIT | build |
| `nom` | 8.0.0 | MIT | build |
| `normpath` | 1.5.2 | MIT OR Apache-2.0 | build |
| `notify` | 8.2.0 | CC0-1.0 | build |
| `notify-types` | 2.1.0 | MIT OR Apache-2.0 | build |
| `ntapi` | 0.4.3 | Apache-2.0 OR MIT | build |
| `num_enum` | 0.7.6 | BSD-3-Clause OR MIT OR Apache-2.0 | build |
| `num_enum_derive` | 0.7.6 | BSD-3-Clause OR MIT OR Apache-2.0 | build |
| `num-conv` | 0.2.2 | MIT OR Apache-2.0 | build |
| `num-derive` | 0.3.3 | MIT OR Apache-2.0 | build |
| `num-traits` | 0.2.19 | MIT OR Apache-2.0 | build |
| `objc-sys` | 0.3.5 | MIT | build |
| `objc2` | 0.5.3 | MIT | build |
| `objc2` | 0.6.5 | MIT | build |
| `objc2-app-kit` | 0.2.2 | MIT | build |
| `objc2-app-kit` | 0.3.2 | Zlib OR Apache-2.0 OR MIT | build |
| `objc2-cloud-kit` | 0.2.2 | MIT | build |
| `objc2-contacts` | 0.2.2 | MIT | build |
| `objc2-core-data` | 0.2.2 | MIT | build |
| `objc2-core-foundation` | 0.3.2 | Zlib OR Apache-2.0 OR MIT | build |
| `objc2-core-graphics` | 0.3.2 | Zlib OR Apache-2.0 OR MIT | build |
| `objc2-core-image` | 0.2.2 | MIT | build |
| `objc2-core-location` | 0.2.2 | MIT | build |
| `objc2-encode` | 4.1.0 | MIT | build |
| `objc2-foundation` | 0.2.2 | MIT | build |
| `objc2-foundation` | 0.3.2 | MIT | build |
| `objc2-io-kit` | 0.3.2 | Zlib OR Apache-2.0 OR MIT | build |
| `objc2-io-surface` | 0.3.2 | Zlib OR Apache-2.0 OR MIT | build |
| `objc2-link-presentation` | 0.2.2 | MIT | build |
| `objc2-metal` | 0.2.2 | MIT | build |
| `objc2-metal` | 0.3.2 | Zlib OR Apache-2.0 OR MIT | build |
| `objc2-open-directory` | 0.3.2 | Zlib OR Apache-2.0 OR MIT | build |
| `objc2-quartz-core` | 0.2.2 | MIT | build |
| `objc2-quartz-core` | 0.3.2 | Zlib OR Apache-2.0 OR MIT | build |
| `objc2-symbols` | 0.2.2 | MIT | build |
| `objc2-ui-kit` | 0.2.2 | MIT | build |
| `objc2-ui-kit` | 0.3.2 | Zlib OR Apache-2.0 OR MIT | build |
| `objc2-uniform-type-identifiers` | 0.2.2 | MIT | build |
| `objc2-user-notifications` | 0.2.2 | MIT | build |
| `object` | 0.40.0 | Apache-2.0 OR MIT | build |
| `once_cell` | 1.21.4 | MIT OR Apache-2.0 | build |
| `once_cell_polyfill` | 1.70.2 | MIT OR Apache-2.0 | build |
| `opener` | 0.9.0 | MIT OR Apache-2.0 | build |
| `option-ext` | 0.2.0 | MPL-2.0 | build |
| `orbclient` | 0.3.55 | MIT | build |
| `ordered-float` | 5.5.0 | MIT | build |
| `ordered-stream` | 0.2.0 | MIT OR Apache-2.0 | build |
| `os_pipe` | 1.2.3 | MIT | build |
| `parking` | 2.2.1 | Apache-2.0 OR MIT | build |
| `parking_lot` | 0.12.5 | MIT OR Apache-2.0 | build |
| `parking_lot_core` | 0.9.12 | MIT OR Apache-2.0 | build |
| `paste` | 1.0.15 | MIT OR Apache-2.0 | build |
| `pastey` | 0.2.3 | MIT OR Apache-2.0 | build |
| `pbkdf2` | 0.12.2 | MIT OR Apache-2.0 | test |
| `peniko` | 0.6.1 | Apache-2.0 OR MIT | build |
| `percent-encoding` | 2.3.2 | MIT OR Apache-2.0 | build |
| `petgraph` | 0.8.3 | MIT OR Apache-2.0 | build |
| `phf` | 0.14.0 | MIT | build |
| `phf_generator` | 0.14.0 | MIT | build |
| `phf_macros` | 0.14.0 | MIT | build |
| `phf_shared` | 0.14.0 | MIT | build |
| `pin-project` | 1.1.13 | Apache-2.0 OR MIT | build |
| `pin-project-internal` | 1.1.13 | Apache-2.0 OR MIT | build |
| `pin-project-lite` | 0.2.17 | Apache-2.0 OR MIT | build |
| `piper` | 0.2.5 | MIT OR Apache-2.0 | build |
| `pkg-config` | 0.3.34 | MIT OR Apache-2.0 | build |
| `plain` | 0.2.3 | MIT/Apache-2.0 | build |
| `plist` | 1.10.1 | MIT | build |
| `png` | 0.18.1 | MIT OR Apache-2.0 | build |
| `polling` | 3.11.0 | Apache-2.0 OR MIT | build |
| `pollster` | 1.0.1 | Apache-2.0/MIT | build |
| `polycool` | 0.4.0 | MIT OR Apache-2.0 | build |
| `portable-atomic` | 1.15.0 | Apache-2.0 OR MIT | build |
| `portable-atomic-util` | 0.2.8 | Apache-2.0 OR MIT | build |
| `potential_utf` | 0.1.6 | Unicode-3.0 | build |
| `powerfmt` | 0.2.1 | MIT OR Apache-2.0 | build |
| `presser` | 0.3.1 | MIT OR Apache-2.0 | build |
| `prettyplease` | 0.2.37 | MIT OR Apache-2.0 | build |
| `proc-macro-crate` | 3.5.0 | MIT OR Apache-2.0 | build |
| `proc-macro2` | 1.0.107 | MIT OR Apache-2.0 | build |
| `profiling` | 1.0.18 | MIT OR Apache-2.0 | build |
| `pxfm` | 0.1.30 | BSD-3-Clause OR Apache-2.0 | build |
| `quick-error` | 2.0.1 | MIT/Apache-2.0 | build |
| `quick-xml` | 0.41.0 | MIT | build |
| `quick-xml` | 0.42.0 | MIT | build |
| `quote` | 1.0.47 | MIT OR Apache-2.0 | build |
| `r-efi` | 5.3.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later | build |
| `r-efi` | 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later | build |
| `range-alloc` | 0.1.5 | MIT OR Apache-2.0 | build |
| `raw-window-handle` | 0.6.2 | MIT OR Apache-2.0 OR Zlib | build |
| `raw-window-metal` | 1.1.0 | MIT OR Apache-2.0 | build |
| `read-fonts` | 0.41.0 | MIT OR Apache-2.0 | build |
| `redox_syscall` | 0.4.1 | MIT | build |
| `redox_syscall` | 0.5.18 | MIT | build |
| `redox_syscall` | 0.9.4 | MIT | build |
| `redox_users` | 0.5.3 | MIT | build |
| `regex` | 1.13.1 | MIT OR Apache-2.0 | build |
| `regex-automata` | 0.4.18 | MIT OR Apache-2.0 | build |
| `regex-syntax` | 0.8.11 | MIT OR Apache-2.0 | build |
| `renderdoc-sys` | 1.1.0 | MIT OR Apache-2.0 | build |
| `rpassword` | 7.5.4 | Apache-2.0 | test |
| `rtoolbox` | 0.0.6 | Apache-2.0 | test |
| `runas` | 1.2.0 | Apache-2.0 | build |
| `rustc_version` | 0.4.1 | MIT OR Apache-2.0 | build |
| `rustc-hash` | 1.1.0 | Apache-2.0/MIT | build |
| `rustc-hash` | 2.1.3 | Apache-2.0 OR MIT | build |
| `rustix` | 0.38.44 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | build |
| `rustix` | 1.1.5 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | build |
| `rustix-linux-procfs` | 0.1.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | build |
| `rustversion` | 1.0.23 | MIT OR Apache-2.0 | build |
| `salsa20` | 0.10.2 | MIT OR Apache-2.0 | test |
| `same-file` | 1.0.6 | Unlicense/MIT | build |
| `scoped-tls` | 1.0.1 | MIT/Apache-2.0 | build |
| `scopeguard` | 1.2.0 | MIT OR Apache-2.0 | build |
| `scrypt` | 0.11.0 | MIT OR Apache-2.0 | test |
| `security-framework-sys` | 2.17.0 | MIT OR Apache-2.0 | build |
| `self_cell` | 1.3.0 | Apache-2.0 OR GPL-2.0-only | build |
| `semver` | 1.0.28 | MIT OR Apache-2.0 | build |
| `send_wrapper` | 0.6.0 | MIT/Apache-2.0 | build |
| `serde` | 1.0.229 | MIT OR Apache-2.0 | build |
| `serde_core` | 1.0.229 | MIT OR Apache-2.0 | build |
| `serde_derive` | 1.0.229 | MIT OR Apache-2.0 | build |
| `serde_json` | 1.0.154 | MIT OR Apache-2.0 | build |
| `serde_repr` | 0.1.21 | MIT OR Apache-2.0 | build |
| `sha1` | 0.11.0 | MIT OR Apache-2.0 | build |
| `sha2` | 0.10.9 | MIT OR Apache-2.0 | test |
| `sha2` | 0.11.1 | MIT OR Apache-2.0 | build |
| `shlex` | 1.3.0 | MIT OR Apache-2.0 | build |
| `shlex` | 2.0.1 | MIT OR Apache-2.0 | build |
| `signal-hook-registry` | 1.4.8 | MIT OR Apache-2.0 | build |
| `simd_cesu8` | 1.2.0 | Apache-2.0 OR MIT | build |
| `simd-adler32` | 0.3.10 | MIT | build |
| `simdutf8` | 0.1.5 | MIT OR Apache-2.0 | build |
| `siphasher` | 1.0.4 | MIT OR Apache-2.0 | build |
| `skrifa` | 0.44.0 | MIT OR Apache-2.0 | build |
| `slab` | 0.4.12 | MIT | build |
| `slotmap` | 1.1.1 | Zlib | build |
| `smallvec` | 1.16.3 | MIT OR Apache-2.0 | build |
| `smithay-client-toolkit` | 0.19.2 | MIT | build |
| `smithay-client-toolkit` | 0.20.0 | MIT | build |
| `smithay-clipboard` | 0.7.3 | MIT | build |
| `smol_str` | 0.2.2 | MIT OR Apache-2.0 | build |
| `spirv` | 0.4.0+sdk-1.4.341.0 | Apache-2.0 | build |
| `stable_deref_trait` | 1.2.1 | MIT OR Apache-2.0 | build |
| `static_assertions` | 1.1.0 | MIT OR Apache-2.0 | build |
| `subtle` | 2.6.1 | BSD-3-Clause | test |
| `syn` | 1.0.109 | MIT OR Apache-2.0 | build |
| `syn` | 2.0.119 | MIT OR Apache-2.0 | build |
| `syn` | 3.0.9 | MIT OR Apache-2.0 | build |
| `synstructure` | 0.14.0 | MIT | build |
| `sysinfo` | 0.39.6 | MIT | build |
| `task-local` | 0.1.1 | MIT OR Apache-2.0 | build |
| `tempfile` | 3.27.0 | MIT OR Apache-2.0 | build |
| `termcolor` | 1.4.1 | Unlicense OR MIT | build |
| `thiserror` | 1.0.69 | MIT OR Apache-2.0 | build |
| `thiserror` | 2.0.21 | MIT OR Apache-2.0 | build |
| `thiserror-impl` | 1.0.69 | MIT OR Apache-2.0 | build |
| `thiserror-impl` | 2.0.21 | MIT OR Apache-2.0 | build |
| `tiff` | 0.11.3 | MIT | build |
| `time` | 0.3.55 | MIT OR Apache-2.0 | build |
| `time-core` | 0.1.9 | MIT OR Apache-2.0 | build |
| `time-macros` | 0.2.32 | MIT OR Apache-2.0 | build |
| `tinystr` | 0.8.4 | Unicode-3.0 | build |
| `tokio` | 1.53.3 | MIT | build |
| `toml_datetime` | 1.1.2+spec-1.1.0 | MIT OR Apache-2.0 | build |
| `toml_edit` | 0.25.17+spec-1.1.0 | MIT OR Apache-2.0 | build |
| `toml_parser` | 1.1.5+spec-1.1.0 | MIT OR Apache-2.0 | build |
| `tracing` | 0.1.44 | MIT | build |
| `tracing-attributes` | 0.1.31 | MIT | build |
| `tracing-core` | 0.1.36 | MIT | build |
| `tray-icon` | 0.26.1 | MIT OR Apache-2.0 | build |
| `tree_magic_mini` | 3.2.2 | MIT | build |
| `type-map` | 0.5.1 | MIT/Apache-2.0 | build |
| `typed-path` | 0.12.3 | MIT OR Apache-2.0 | build |
| `typenum` | 1.20.1 | MIT OR Apache-2.0 | build |
| `uds_windows` | 1.2.1 | MIT | build |
| `unicode-general-category` | 1.1.0 | Apache-2.0 | build |
| `unicode-ident` | 1.0.27 | (MIT OR Apache-2.0) AND Unicode-3.0 | build |
| `unicode-properties` | 0.1.4 | MIT/Apache-2.0 | build |
| `unicode-segmentation` | 1.13.3 | MIT OR Apache-2.0 | build |
| `unicode-width` | 0.2.2 | MIT OR Apache-2.0 | build |
| `url` | 2.5.8 | MIT OR Apache-2.0 | build |
| `utf8_iter` | 1.0.4 | Apache-2.0 OR MIT | build |
| `utf8parse` | 0.2.2 | Apache-2.0 OR MIT | build |
| `uuid` | 1.28.0 | Apache-2.0 OR MIT | build |
| `vello_common` | 0.2.0 | Apache-2.0 OR MIT | build |
| `vello_cpu` | 0.2.0 | Apache-2.0 OR MIT | build |
| `version_check` | 0.9.5 | MIT/Apache-2.0 | build |
| `walkdir` | 2.5.0 | Unlicense/MIT | build |
| `wasi` | 0.11.1+wasi-snapshot-preview1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | build |
| `wasip2` | 1.0.4+wasi-0.2.12 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | build |
| `wasm-bindgen` | 0.2.129 | MIT OR Apache-2.0 | build |
| `wasm-bindgen-futures` | 0.4.79 | MIT OR Apache-2.0 | build |
| `wasm-bindgen-macro` | 0.2.129 | MIT OR Apache-2.0 | build |
| `wasm-bindgen-macro-support` | 0.2.129 | MIT OR Apache-2.0 | build |
| `wasm-bindgen-shared` | 0.2.129 | MIT OR Apache-2.0 | build |
| `wayland-backend` | 0.3.17 | MIT | build |
| `wayland-client` | 0.31.15 | MIT | build |
| `wayland-csd-frame` | 0.3.0 | MIT | build |
| `wayland-cursor` | 0.31.14 | MIT | build |
| `wayland-protocols` | 0.32.13 | MIT | build |
| `wayland-protocols-experimental` | 20250721.0.1 | MIT | build |
| `wayland-protocols-misc` | 0.3.12 | MIT | build |
| `wayland-protocols-plasma` | 0.3.12 | MIT | build |
| `wayland-protocols-wlr` | 0.3.12 | MIT | build |
| `wayland-scanner` | 0.31.11 | MIT | build |
| `wayland-sys` | 0.31.11 | MIT | build |
| `web-sys` | 0.3.106 | MIT OR Apache-2.0 | build |
| `web-time` | 1.1.0 | MIT OR Apache-2.0 | build |
| `weezl` | 0.1.12 | MIT OR Apache-2.0 | build |
| `wgpu` | 30.0.1 | MIT OR Apache-2.0 | build |
| `wgpu-core` | 30.0.1 | MIT OR Apache-2.0 | build |
| `wgpu-core-deps-apple` | 30.0.1 | MIT OR Apache-2.0 | build |
| `wgpu-core-deps-emscripten` | 30.0.1 | MIT OR Apache-2.0 | build |
| `wgpu-core-deps-wasm` | 30.0.1 | MIT OR Apache-2.0 | build |
| `wgpu-core-deps-windows-linux-android` | 30.0.1 | MIT OR Apache-2.0 | build |
| `wgpu-hal` | 30.0.1 | MIT OR Apache-2.0 | build |
| `wgpu-naga-bridge` | 30.0.1 | MIT OR Apache-2.0 | build |
| `wgpu-types` | 30.0.1 | MIT OR Apache-2.0 | build |
| `which` | 4.4.2 | MIT | build |
| `winapi` | 0.3.9 | MIT/Apache-2.0 | build |
| `winapi-i686-pc-windows-gnu` | 0.4.0 | MIT/Apache-2.0 | build |
| `winapi-util` | 0.1.11 | Unlicense OR MIT | build |
| `winapi-x86_64-pc-windows-gnu` | 0.4.0 | MIT/Apache-2.0 | build |
| `windows` | 0.62.2 | MIT OR Apache-2.0 | build |
| `windows_aarch64_gnullvm` | 0.48.5 | MIT OR Apache-2.0 | build |
| `windows_aarch64_gnullvm` | 0.52.6 | MIT OR Apache-2.0 | build |
| `windows_aarch64_gnullvm` | 0.53.1 | MIT OR Apache-2.0 | build |
| `windows_aarch64_msvc` | 0.48.5 | MIT OR Apache-2.0 | build |
| `windows_aarch64_msvc` | 0.52.6 | MIT OR Apache-2.0 | build |
| `windows_aarch64_msvc` | 0.53.1 | MIT OR Apache-2.0 | build |
| `windows_i686_gnu` | 0.48.5 | MIT OR Apache-2.0 | build |
| `windows_i686_gnu` | 0.52.6 | MIT OR Apache-2.0 | build |
| `windows_i686_gnu` | 0.53.1 | MIT OR Apache-2.0 | build |
| `windows_i686_gnullvm` | 0.52.6 | MIT OR Apache-2.0 | build |
| `windows_i686_gnullvm` | 0.53.1 | MIT OR Apache-2.0 | build |
| `windows_i686_msvc` | 0.48.5 | MIT OR Apache-2.0 | build |
| `windows_i686_msvc` | 0.52.6 | MIT OR Apache-2.0 | build |
| `windows_i686_msvc` | 0.53.1 | MIT OR Apache-2.0 | build |
| `windows_x86_64_gnu` | 0.48.5 | MIT OR Apache-2.0 | build |
| `windows_x86_64_gnu` | 0.52.6 | MIT OR Apache-2.0 | build |
| `windows_x86_64_gnu` | 0.53.1 | MIT OR Apache-2.0 | build |
| `windows_x86_64_gnullvm` | 0.48.5 | MIT OR Apache-2.0 | build |
| `windows_x86_64_gnullvm` | 0.52.6 | MIT OR Apache-2.0 | build |
| `windows_x86_64_gnullvm` | 0.53.1 | MIT OR Apache-2.0 | build |
| `windows_x86_64_msvc` | 0.48.5 | MIT OR Apache-2.0 | build |
| `windows_x86_64_msvc` | 0.52.6 | MIT OR Apache-2.0 | build |
| `windows_x86_64_msvc` | 0.53.1 | MIT OR Apache-2.0 | build |
| `windows-collections` | 0.3.2 | MIT OR Apache-2.0 | build |
| `windows-core` | 0.62.2 | MIT OR Apache-2.0 | build |
| `windows-future` | 0.3.2 | MIT OR Apache-2.0 | build |
| `windows-implement` | 0.60.2 | MIT OR Apache-2.0 | build |
| `windows-interface` | 0.59.3 | MIT OR Apache-2.0 | build |
| `windows-link` | 0.2.1 | MIT OR Apache-2.0 | build |
| `windows-numerics` | 0.3.1 | MIT OR Apache-2.0 | build |
| `windows-result` | 0.4.1 | MIT OR Apache-2.0 | build |
| `windows-strings` | 0.5.1 | MIT OR Apache-2.0 | build |
| `windows-sys` | 0.48.0 | MIT OR Apache-2.0 | build |
| `windows-sys` | 0.52.0 | MIT OR Apache-2.0 | build |
| `windows-sys` | 0.59.0 | MIT OR Apache-2.0 | build |
| `windows-sys` | 0.60.2 | MIT OR Apache-2.0 | build |
| `windows-sys` | 0.61.2 | MIT OR Apache-2.0 | build |
| `windows-targets` | 0.48.5 | MIT OR Apache-2.0 | build |
| `windows-targets` | 0.52.6 | MIT OR Apache-2.0 | build |
| `windows-targets` | 0.53.5 | MIT OR Apache-2.0 | build |
| `windows-threading` | 0.2.1 | MIT OR Apache-2.0 | build |
| `winit` | 0.30.13 | Apache-2.0 | build |
| `winnow` | 1.0.4 | MIT | build |
| `winreg` | 0.56.0 | MIT | build |
| `winx` | 0.36.4 | Apache-2.0 WITH LLVM-exception | build |
| `wit-bindgen` | 0.57.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | build |
| `wl-clipboard-rs` | 0.9.4 | MIT OR Apache-2.0 | build |
| `writeable` | 0.6.4 | Unicode-3.0 | build |
| `x11-dl` | 2.21.0 | MIT | build |
| `x11rb` | 0.13.2 | MIT OR Apache-2.0 | build |
| `x11rb-protocol` | 0.13.2 | MIT OR Apache-2.0 | build |
| `xcursor` | 0.3.11 | MIT | build |
| `xkbcommon-dl` | 0.4.2 | MIT | build |
| `xkeysym` | 0.2.1 | MIT OR Apache-2.0 OR Zlib | build |
| `xml-rs` | 0.8.29 | MIT | build |
| `yoke` | 0.8.3 | Unicode-3.0 | build |
| `yoke-derive` | 0.8.4 | Unicode-3.0 | build |
| `zbus` | 5.19.0 | MIT | build |
| `zbus_macros` | 5.19.0 | MIT | build |
| `zbus_names` | 4.3.5 | MIT | build |
| `zbus_xml` | 5.2.1 | MIT | build |
| `zbus-lockstep` | 0.5.2 | MIT | build |
| `zbus-lockstep-macros` | 0.5.2 | MIT | build |
| `zcheapstr` | 1.1.0 | MIT | build |
| `zerocopy` | 0.8.63 | BSD-2-Clause OR Apache-2.0 OR MIT | build |
| `zerocopy-derive` | 0.8.63 | BSD-2-Clause OR Apache-2.0 OR MIT | build |
| `zerofrom` | 0.1.8 | Unicode-3.0 | build |
| `zerofrom-derive` | 0.1.8 | Unicode-3.0 | build |
| `zerotrie` | 0.2.5 | Unicode-3.0 | build |
| `zerovec` | 0.11.8 | Unicode-3.0 | build |
| `zerovec-derive` | 0.11.6 | Unicode-3.0 | build |
| `zip` | 9.0.5 | MIT | build |
| `zlib-rs` | 0.6.8 | Zlib | build |
| `zmij` | 1.0.23 | MIT | build |
| `zopfli` | 0.8.4 | Apache-2.0 | build |
| `zune-core` | 0.5.3 | MIT OR Apache-2.0 OR Zlib | build |
| `zune-jpeg` | 0.5.15 | MIT OR Apache-2.0 OR Zlib | build |
| `zvariant` | 5.15.1 | MIT | build |
| `zvariant_derive` | 5.15.1 | MIT | build |
| `zvariant_utils` | 4.2.0 | MIT | build |
