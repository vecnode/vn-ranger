# Typefaces

The application embeds two typefaces so it looks the same on every machine:

| Family | File | Role |
|---|---|---|
| Inter Regular | `Inter-Regular.ttf` | Body copy, labels, table text |
| Inter SemiBold | `Inter-SemiBold.ttf` | Headings, numbers, buttons, section titles |
| JetBrains Mono Regular | `JetBrainsMono-Regular.ttf` | Paths, commands, hashes, technical values |

Both are licensed under the **SIL Open Font License 1.1**:

- Inter — Copyright (c) 2016 The Inter Project Authors, <https://github.com/rsms/inter>
- JetBrains Mono — Copyright 2020 The JetBrains Mono Project Authors,
  <https://github.com/JetBrains/JetBrainsMono>

The full licence texts are [`LICENSE-Inter.txt`](LICENSE-Inter.txt) and
[`LICENSE-JetBrainsMono.txt`](LICENSE-JetBrainsMono.txt). The fonts are embedded by
`crates/ui/src/fonts.rs` with `include_bytes!`, so there is no font lookup at runtime
and no system-font dependency.

The type scale is defined in `crates/ui/src/theme.rs`; the mark's geometry and clear
space are in [`../logo/BRAND.md`](../logo/BRAND.md). Keep the body at 13 px and the
largest display number at 22 px; a security tool should read as a tool, not a
dashboard.
