//! The interface's marks, drawn with the painter rather than shipped as images.
//!
//! A line icon is cheaper than a texture, scales with the display and cannot drift
//! from the theme.

use egui::{Color32, Painter, Pos2, Rect, Stroke, vec2};

/// One of the small navigation or status marks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icon {
    /// The overview grid.
    Overview,
    /// The process list.
    Processes,
    /// A power mark for startup items.
    Startup,
    /// A listening socket.
    Listeners,
    /// A clock for the change timeline.
    Changes,
    /// A report page.
    Report,
    /// Settings sliders.
    Settings,
    /// Rescan.
    Scan,
    /// A shield.
    Shield,
    /// A folder.
    Folder,
    /// A check.
    Check,
    /// A search lens.
    Search,
    /// An export arrow.
    Export,
}

/// Draw an icon inside `rect`.
pub fn paint(painter: &Painter, rect: Rect, icon: Icon, color: Color32) {
    let stroke = Stroke::new(1.6, color);
    let point = |x: f32, y: f32| pos(rect, x, y);
    match icon {
        Icon::Overview => {
            for (x, y) in [(0.14, 0.14), (0.56, 0.14), (0.14, 0.56), (0.56, 0.56)] {
                square(painter, point(x, y), 0.30 * rect.width(), stroke);
            }
        }
        Icon::Processes => {
            for y in [0.25, 0.50, 0.75] {
                painter.line_segment([point(0.34, y), point(0.86, y)], stroke);
                painter.circle_filled(point(0.18, y), 0.045 * rect.width(), color);
            }
        }
        Icon::Startup => {
            painter.circle_stroke(point(0.5, 0.53), 0.27 * rect.width(), stroke);
            painter.line_segment([point(0.5, 0.18), point(0.5, 0.5)], stroke);
        }
        Icon::Listeners => {
            painter.circle_stroke(point(0.5, 0.5), 0.12 * rect.width(), stroke);
            painter.circle_stroke(point(0.5, 0.5), 0.27 * rect.width(), stroke);
            painter.circle_filled(point(0.5, 0.5), 0.04 * rect.width(), color);
        }
        Icon::Changes => {
            painter.circle_stroke(point(0.5, 0.5), 0.30 * rect.width(), stroke);
            painter.line_segment([point(0.5, 0.5), point(0.5, 0.28)], stroke);
            painter.line_segment([point(0.5, 0.5), point(0.67, 0.57)], stroke);
        }
        Icon::Report => {
            square(painter, point(0.22, 0.12), 0.56, stroke);
            for y in [0.36, 0.52, 0.68] {
                painter.line_segment([point(0.34, y), point(0.66, y)], stroke);
            }
        }
        Icon::Settings => {
            for y in [0.28, 0.50, 0.72] {
                painter.line_segment([point(0.18, y), point(0.82, y)], stroke);
            }
            painter.circle_filled(point(0.38, 0.28), 0.055 * rect.width(), color);
            painter.circle_filled(point(0.64, 0.50), 0.055 * rect.width(), color);
            painter.circle_filled(point(0.44, 0.72), 0.055 * rect.width(), color);
        }
        Icon::Scan => {
            painter.circle_stroke(point(0.46, 0.46), 0.26 * rect.width(), stroke);
            painter.line_segment([point(0.66, 0.66), point(0.86, 0.86)], stroke);
        }
        Icon::Shield => {
            painter.add(egui::Shape::line(
                vec![
                    point(0.5, 0.10),
                    point(0.82, 0.26),
                    point(0.76, 0.66),
                    point(0.5, 0.88),
                    point(0.24, 0.66),
                    point(0.18, 0.26),
                    point(0.5, 0.10),
                ],
                stroke,
            ));
        }
        Icon::Folder => {
            painter.add(egui::Shape::line(
                vec![
                    point(0.12, 0.28),
                    point(0.42, 0.28),
                    point(0.50, 0.38),
                    point(0.88, 0.38),
                    point(0.88, 0.80),
                    point(0.12, 0.80),
                    point(0.12, 0.28),
                ],
                stroke,
            ));
        }
        Icon::Check => {
            painter.add(egui::Shape::line(
                vec![point(0.20, 0.52), point(0.42, 0.74), point(0.82, 0.28)],
                stroke,
            ));
        }
        Icon::Search => {
            painter.circle_stroke(point(0.44, 0.42), 0.24 * rect.width(), stroke);
            painter.line_segment([point(0.62, 0.62), point(0.84, 0.84)], stroke);
        }
        Icon::Export => {
            painter.line_segment([point(0.5, 0.16), point(0.5, 0.66)], stroke);
            painter.add(egui::Shape::line(
                vec![point(0.30, 0.44), point(0.5, 0.66), point(0.70, 0.44)],
                stroke,
            ));
            painter.line_segment([point(0.18, 0.84), point(0.82, 0.84)], stroke);
        }
    }
}

fn pos(rect: Rect, x: f32, y: f32) -> Pos2 {
    rect.min + vec2(rect.width() * x, rect.height() * y)
}

fn square(painter: &Painter, top_left: Pos2, side: f32, stroke: Stroke) {
    let rect = Rect::from_min_size(top_left, vec2(side, side));
    painter.add(egui::Shape::line(
        vec![
            rect.left_top(),
            rect.right_top(),
            rect.right_bottom(),
            rect.left_bottom(),
            rect.left_top(),
        ],
        stroke,
    ));
}
