//! The small vocabulary every view is built from: cards, badges, statistics and the
//! empty state.

use egui::{Color32, CornerRadius, FontId, Margin, RichText, Sense, Stroke, vec2};

use crate::theme;

/// A bordered surface.
pub fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::new()
        .fill(theme::surface(ui))
        .stroke(Stroke::new(1.0, theme::border(ui)))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::same(14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// A bordered row inside a card, for a list of things a person can act on.
pub fn border<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::new()
        .fill(ui.visuals().faint_bg_color)
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::symmetric(10, 8))
        .outer_margin(Margin {
            bottom: 6,
            ..Margin::ZERO
        })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// A byte count in the units a person uses.
///
/// Bytes are rounded to one decimal above a kilobyte: the difference between 312.4 MB and
/// 312.44 MB is not a fact anyone acts on, and a long number invites comparison instead of
/// a decision.
pub fn bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// A small coloured label.
pub fn badge(ui: &mut egui::Ui, text: &str, color: Color32) {
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_owned(), FontId::proportional(10.0), color);
    let padding = vec2(6.0, 2.5);
    let (rect, _) = ui.allocate_exact_size(galley.size() + padding * 2.0, Sense::hover());
    ui.painter()
        .rect_filled(rect, CornerRadius::same(5), color.gamma_multiply(0.16));
    ui.painter().galley(rect.min + padding, galley, color);
}

/// A health badge for a collector state.
pub fn health(ui: &mut egui::Ui, state: vnr_core::CollectorState) {
    let color = match state {
        vnr_core::CollectorState::Ok => theme::OK,
        vnr_core::CollectorState::Partial => theme::ATTENTION,
        vnr_core::CollectorState::Unavailable => theme::muted(ui),
    };
    badge(ui, state.label(), color);
}

/// One number and its label, inline.
///
/// Inline rather than on its own card: an overview of four counts is a sentence about the
/// machine, and four boxes made it a dashboard. The number still leads, because it is what
/// the eye is looking for.
pub fn statistic(ui: &mut egui::Ui, value: usize, label: &str) {
    ui.vertical(|ui| {
        ui.label(
            RichText::new(value.to_string())
                .size(15.0)
                .family(theme::semibold()),
        );
        ui.label(RichText::new(label).size(10.0).color(theme::muted(ui)));
    });
}

/// A heading with a quiet subtitle.
pub fn section(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.label(RichText::new(title).size(13.5).family(theme::semibold()));
    if !subtitle.is_empty() {
        ui.label(RichText::new(subtitle).size(11.0).color(theme::muted(ui)));
    }
}

/// The state a table shows when it has nothing to show.
pub fn empty(ui: &mut egui::Ui, title: &str, body: &str) {
    ui.vertical_centered(|ui| {
        ui.add_space(36.0);
        ui.label(RichText::new(title).size(16.0).family(theme::semibold()));
        ui.add_space(4.0);
        ui.label(RichText::new(body).size(12.0).color(theme::muted(ui)));
        ui.add_space(24.0);
    });
}

/// A key and a value, with the value selectable and monospaced.
pub fn key_value(ui: &mut egui::Ui, key: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [100.0, 16.0],
            egui::Label::new(RichText::new(key).size(10.5).color(theme::muted(ui))),
        );
        ui.add(
            egui::Label::new(RichText::new(value).size(11.5).monospace())
                .truncate()
                .selectable(true),
        );
    });
}

/// A monospaced, selectable block for a path or a command.
pub fn path(ui: &mut egui::Ui, value: &str) {
    if value.is_empty() || value == "—" {
        ui.label(RichText::new("—").size(12.0).color(theme::muted(ui)));
        return;
    }
    ui.add(
        egui::Label::new(RichText::new(value).size(11.5).monospace())
            .wrap()
            .selectable(true),
    );
}

/// A full-width search field.
pub fn search(ui: &mut egui::Ui, text: &mut String, hint: &str) {
    ui.add(
        egui::TextEdit::singleline(text)
            .hint_text(hint)
            .desired_width(f32::INFINITY)
            .margin(Margin::symmetric(8, 6)),
    );
}

/// A quiet sentence with a coloured dot.
pub fn dot_line(ui: &mut egui::Ui, color: Color32, text: &str) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(vec2(10.0, 10.0), Sense::hover());
        ui.painter().circle_filled(rect.center(), 4.0, color);
        ui.label(RichText::new(text).size(11.5).color(theme::muted(ui)));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_read_in_the_units_a_person_uses() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(999), "999 B");
        assert_eq!(bytes(1024), "1.0 KB");
        assert_eq!(bytes(1024 * 1024 * 3 / 2), "1.5 MB");
        assert_eq!(bytes(1024 * 1024 * 1024 * 2), "2.0 GB");
        assert_eq!(
            bytes(1024 * 1024 * 1024 * 1024),
            "1024.0 GB",
            "the largest unit is the largest one shown"
        );
    }
}
