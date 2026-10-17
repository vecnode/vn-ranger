//! The colours, spacing and type ranger draws with.

use egui::{Color32, Context, FontFamily, FontId, Stroke, TextStyle, Visuals};

/// The suite's ember, the colour inside ranger's crystal.
pub const EMBER: Color32 = Color32::from_rgb(242, 106, 33);
/// A lighter ember for text and links on dark surfaces.
pub const EMBER_LIGHT: Color32 = Color32::from_rgb(255, 154, 90);
/// Text and icons placed on an ember fill.
///
/// White on ember is only 3.06:1 and fails WCAG AA for normal text; ink on ember is
/// 6.36:1 and is the only pair used for small labels.
pub const ON_EMBER: Color32 = INK;
/// Good news.
pub const OK: Color32 = Color32::from_rgb(63, 185, 80);
/// Something a person should look at.
pub const ATTENTION: Color32 = Color32::from_rgb(210, 153, 34);
/// Something is wrong, or a signature matched.
pub const BAD: Color32 = Color32::from_rgb(248, 81, 73);

const INK: Color32 = Color32::from_rgb(11, 13, 16);

/// Apply the palette for the chosen mode.
pub fn apply(ctx: &Context, dark: bool) {
    let mut visuals = if dark { Visuals::dark() } else { Visuals::light() };
    if dark {
        visuals.panel_fill = INK;
        visuals.window_fill = Color32::from_rgb(17, 21, 27);
        visuals.faint_bg_color = Color32::from_rgb(22, 27, 34);
        visuals.extreme_bg_color = Color32::from_rgb(15, 19, 24);
        visuals.override_text_color = Some(Color32::from_rgb(230, 232, 236));
        visuals.selection.bg_fill = EMBER.gamma_multiply(0.55);
        visuals.selection.stroke = Stroke::new(1.0, EMBER_LIGHT);
        visuals.hyperlink_color = EMBER_LIGHT;
        visuals.warn_fg_color = ATTENTION;
        visuals.error_fg_color = BAD;
        visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, Color32::from_rgb(38, 44, 53));
        visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, Color32::from_rgb(154, 161, 172));
        visuals.widgets.inactive.bg_fill = Color32::from_rgb(22, 27, 34);
        visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, Color32::from_rgb(214, 218, 224));
        visuals.widgets.hovered.bg_fill = Color32::from_rgb(32, 38, 48);
        visuals.widgets.active.bg_fill = Color32::from_rgb(42, 49, 60);
    } else {
        visuals.panel_fill = Color32::from_rgb(247, 248, 250);
        visuals.window_fill = Color32::WHITE;
        visuals.faint_bg_color = Color32::from_rgb(238, 241, 245);
        visuals.extreme_bg_color = Color32::WHITE;
        visuals.override_text_color = Some(INK);
        visuals.selection.bg_fill = EMBER.gamma_multiply(0.35);
        visuals.selection.stroke = Stroke::new(1.0, EMBER);
        visuals.hyperlink_color = Color32::from_rgb(196, 78, 12);
        visuals.warn_fg_color = Color32::from_rgb(158, 108, 10);
        visuals.error_fg_color = Color32::from_rgb(190, 30, 30);
        visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, Color32::from_rgb(216, 221, 229));
        visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, Color32::from_rgb(91, 100, 114));
        visuals.widgets.inactive.bg_fill = Color32::from_rgb(238, 241, 245);
        visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, Color32::from_rgb(31, 36, 44));
        visuals.widgets.hovered.bg_fill = Color32::from_rgb(228, 232, 238);
        visuals.widgets.active.bg_fill = Color32::from_rgb(216, 221, 229);
    }
    visuals.striped = true;
    ctx.set_visuals(visuals);

    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(12.0, 7.0);
        style.spacing.interact_size.y = 26.0;
        style.text_styles = [
            (TextStyle::Heading, FontId::new(24.0, FontFamily::Proportional)),
            (TextStyle::Body, FontId::new(14.0, FontFamily::Proportional)),
            (TextStyle::Button, FontId::new(14.0, FontFamily::Proportional)),
            (TextStyle::Small, FontId::new(12.0, FontFamily::Proportional)),
            (TextStyle::Monospace, FontId::new(12.0, FontFamily::Monospace)),
        ]
        .into();
    });
}

/// The page fill for the chosen mode.
#[must_use]
pub fn panel(dark: bool) -> Color32 {
    if dark {
        INK
    } else {
        Color32::from_rgb(247, 248, 250)
    }
}

/// The top bar and rail fill for the chosen mode.
#[must_use]
pub fn window(dark: bool) -> Color32 {
    if dark {
        Color32::from_rgb(17, 21, 27)
    } else {
        Color32::WHITE
    }
}

/// The surface colour for cards.
#[must_use]
pub fn surface(ui: &egui::Ui) -> Color32 {
    if ui.visuals().dark_mode {
        Color32::from_rgb(20, 25, 32)
    } else {
        Color32::WHITE
    }
}

/// The border colour for cards.
#[must_use]
pub fn border(ui: &egui::Ui) -> Color32 {
    if ui.visuals().dark_mode {
        Color32::from_rgb(38, 44, 53)
    } else {
        Color32::from_rgb(216, 221, 229)
    }
}

/// A muted colour for secondary text.
#[must_use]
pub fn muted(ui: &egui::Ui) -> Color32 {
    if ui.visuals().dark_mode {
        Color32::from_rgb(154, 161, 172)
    } else {
        Color32::from_rgb(91, 100, 114)
    }
}
