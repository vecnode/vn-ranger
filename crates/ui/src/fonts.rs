//! The suite's typefaces, embedded so the application looks the same everywhere.
//!
//! Inter is the proportional face and JetBrains Mono the monospaced one. Both are
//! under the SIL Open Font License 1.1; the licence texts sit beside the files in
//! `assets/fonts/`. egui's own fallback fonts remain behind them for glyphs the two
//! families do not carry.

use std::sync::Arc;

use egui::{FontData, FontDefinitions, FontFamily};

/// The name of the semibold family used for headings, numbers and buttons.
pub const SEMIBOLD: &str = "inter-semibold";

/// Install Inter and JetBrains Mono.
///
/// `Context::set_fonts` takes effect on the next pass, so this must run before the
/// first frame; the shell calls it from `Ui::new`.
pub fn install(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();

    fonts.font_data.insert(
        "inter".to_owned(),
        Arc::new(FontData::from_static(include_bytes!(
            "../../../assets/fonts/Inter-Regular.ttf"
        ))),
    );
    fonts.font_data.insert(
        SEMIBOLD.to_owned(),
        Arc::new(FontData::from_static(include_bytes!(
            "../../../assets/fonts/Inter-SemiBold.ttf"
        ))),
    );
    fonts.font_data.insert(
        "jetbrains-mono".to_owned(),
        Arc::new(FontData::from_static(include_bytes!(
            "../../../assets/fonts/JetBrainsMono-Regular.ttf"
        ))),
    );

    if let Some(family) = fonts.families.get_mut(&FontFamily::Proportional) {
        family.insert(0, "inter".to_owned());
    }
    if let Some(family) = fonts.families.get_mut(&FontFamily::Monospace) {
        family.insert(0, "jetbrains-mono".to_owned());
    }
    fonts.families.insert(semibold(), vec![SEMIBOLD.to_owned()]);

    ctx.set_fonts(fonts);
}

/// The semibold family, for `RichText::family`.
#[must_use]
pub fn semibold() -> FontFamily {
    FontFamily::Name(Arc::from(SEMIBOLD))
}
