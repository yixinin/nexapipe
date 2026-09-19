//! QR code rendering for the 2FA enrollment flow.
//!
//! The terminal renderer is the interesting one: what it prints has to survive
//! being photographed off a screen, so the module colors are forced with ANSI
//! escapes instead of being left to the terminal theme (a light-on-dark code is
//! not read by every scanner), and two module rows are packed into one text
//! line with half blocks so the modules come out roughly square.
//!
//! ```text
//! \x1b[30;47m█▀▀▀▀▀█ ▄▀ ▄▀█▀▀▄ \x1b[0m   <- fg=black, bg=white, then a
//! \x1b[30;47m█ ███ █ ▀▀█ █ █▄█ \x1b[0m      reset at the end of the line
//! ```

use anyhow::{Context, Result};
use qrcode::types::Color;
use qrcode::{EcLevel, QrCode};

/// Blank modules kept around the symbol, as the spec requires.
pub const QUIET_ZONE: usize = 4;

/// Error correction level. Medium leaves enough redundancy for a screenshot
/// while keeping the symbol small enough to fit in a terminal.
const EC_LEVEL: EcLevel = EcLevel::M;

/// Modules per side of the SVG output, so it opens at a reasonable size.
const SVG_MODULE_PX: usize = 8;

/// Resets the colors set by [`render_unicode`].
const RESET: &str = "\x1b[0m";

/// Black ink on white paper.
const INK_BLACK: &str = "\x1b[30;47m";

/// White ink on black paper.
const INK_WHITE: &str = "\x1b[37;40m";

/// Encodes `text` as a QR code.
fn encode(text: &str) -> Result<QrCode> {
    QrCode::with_error_correction_level(text.as_bytes(), EC_LEVEL).with_context(|| {
        format!(
            "failed to encode a QR code for {} bytes of data",
            text.len()
        )
    })
}

/// The module matrix including the quiet zone, top row first, where `true`
/// stands for a dark module.
fn matrix(code: &QrCode) -> Vec<Vec<bool>> {
    let width = code.width();
    let colors = code.to_colors();
    let full = width + 2 * QUIET_ZONE;

    (0..full)
        .map(|y| {
            (0..full)
                .map(|x| {
                    let inside = x >= QUIET_ZONE
                        && y >= QUIET_ZONE
                        && x < width + QUIET_ZONE
                        && y < width + QUIET_ZONE;
                    inside && colors[(y - QUIET_ZONE) * width + (x - QUIET_ZONE)] == Color::Dark
                })
                .collect()
        })
        .collect()
}

/// Number of dark and light modules, used by the tests.
#[cfg(test)]
fn dark_modules(code: &QrCode) -> usize {
    code.to_colors()
        .iter()
        .filter(|color| **color == Color::Dark)
        .count()
}

/// Renders `text` as a terminal QR code, two module rows per line.
///
/// The colors are set explicitly: ink and paper always end up as black and
/// white, whatever the terminal theme is, unless `invert` asks for the
/// light-on-dark variant.
pub fn render_unicode(text: &str, invert: bool) -> Result<String> {
    let code = encode(text)?;
    Ok(render_blocks(
        &matrix(&code),
        Some(if invert { INK_WHITE } else { INK_BLACK }),
        !invert,
    ))
}

/// Renders `text` with the same half blocks as [`render_unicode`] but without
/// any escape sequence, for terminals that ignore colors.
///
/// Whether this is readable therefore depends on the viewer's theme: `invert`
/// selects the variant to use on a dark background.
pub fn render_plain(text: &str, invert: bool) -> Result<String> {
    let code = encode(text)?;
    Ok(render_blocks(&matrix(&code), None, !invert))
}

/// Renders `text` as plain ASCII, two characters per module, without escapes.
pub fn render_ascii(text: &str, invert: bool) -> Result<String> {
    let code = encode(text)?;
    let (ink, paper) = if invert { (' ', '#') } else { ('#', ' ') };

    let mut out = String::new();
    for row in matrix(&code) {
        for dark in row {
            let ch = if dark { ink } else { paper };
            out.push(ch);
            out.push(ch);
        }
        out.push('\n');
    }
    Ok(out)
}

/// Renders `text` as a standalone SVG document.
pub fn render_svg(text: &str, invert: bool) -> Result<String> {
    let code = encode(text)?;
    let matrix = matrix(&code);
    let size = matrix.len();
    let (background, foreground) = if invert {
        ("#000000", "#ffffff")
    } else {
        ("#ffffff", "#000000")
    };

    let mut path = String::new();
    for (y, row) in matrix.iter().enumerate() {
        for (x, dark) in row.iter().enumerate() {
            if *dark {
                path.push_str(&format!("M{x} {y}h1v1h-1z"));
            }
        }
    }

    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{px}\" height=\"{px}\" \
         viewBox=\"0 0 {size} {size}\" shape-rendering=\"crispEdges\">\n\
         <rect width=\"{size}\" height=\"{size}\" fill=\"{background}\"/>\n\
         <path d=\"{path}\" fill=\"{foreground}\"/>\n\
         </svg>\n",
        px = size * SVG_MODULE_PX,
    ))
}

/// Draws a module matrix with half blocks. `ink` is the escape sequence that
/// paints the blocks, or `None` to inherit the terminal colors; `dark_is_ink`
/// decides whether dark modules are drawn as ink or as paper.
fn render_blocks(matrix: &[Vec<bool>], ink: Option<&str>, dark_is_ink: bool) -> String {
    let mut out = String::new();

    // Two module rows share a text line: the upper half of the block character
    // draws the first row and the lower half the second one.
    for rows in matrix.chunks(2) {
        let top = &rows[0];
        let bottom = rows.get(1);

        if let Some(ink) = ink {
            out.push_str(ink);
        }

        for (x, top_dark) in top.iter().enumerate() {
            let bottom_dark = bottom.is_some_and(|row| row[x]);
            let (top_ink, bottom_ink) = if dark_is_ink {
                (*top_dark, bottom_dark)
            } else {
                (!*top_dark, !bottom_dark)
            };
            out.push(match (top_ink, bottom_ink) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }

        if ink.is_some() {
            out.push_str(RESET);
        }
        out.push('\n');
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const URI: &str = "otpauth://totp/NexaPipe:client-001?secret=JBSWY3DPEHPK3PXP\
                       &issuer=NexaPipe&algorithm=SHA1&digits=6&period=30";

    /// The printable body of a rendering, with the per-line color escapes
    /// removed.
    fn strip(rendered: &str) -> String {
        rendered
            .lines()
            .map(|line| {
                line.trim_start_matches(INK_BLACK)
                    .trim_start_matches(INK_WHITE)
                    .trim_end_matches(RESET)
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The quiet zone is what makes a code readable at all; every edge of the
    /// symbol has to be blank.
    #[test]
    fn keeps_a_quiet_zone_around_the_symbol() {
        let code = encode(URI).unwrap();
        let matrix = matrix(&code);
        let full = matrix.len();
        assert_eq!(full, code.width() + 2 * QUIET_ZONE);

        // The vertical edges: the first and the last module column of every
        // row belong to the quiet zone.
        for row in &matrix {
            assert!(!row[QUIET_ZONE - 1], "left quiet zone is not blank");
            assert!(!row[full - 1], "right quiet zone is not blank");
        }

        // The horizontal edges, plus the row right above the symbol.
        for row in [&matrix[0], &matrix[full - 1], &matrix[QUIET_ZONE - 1]] {
            assert!(
                row.iter().all(|dark| !dark),
                "the symbol is not framed by a blank row"
            );
        }

        assert!(matrix[QUIET_ZONE][QUIET_ZONE], "finder pattern is missing");
        assert!(dark_modules(&code) > 0);
    }

    /// Each output line must both open and close its color state, otherwise the
    /// terminal keeps painting after the QR code.
    #[test]
    fn unicode_output_is_color_scoped_per_line() {
        let rendered = render_unicode(URI, false).unwrap();
        let lines: Vec<&str> = rendered.lines().collect();
        assert!(lines.len() >= 20, "only {} lines", lines.len());

        for line in &lines {
            assert!(
                line.starts_with(INK_BLACK),
                "line does not set ink: {line:?}"
            );
            assert!(line.ends_with(RESET), "line does not reset: {line:?}");
        }

        // Two module rows per line, so the half of the last line that has no
        // module row is drawn blank.
        let width = lines[0]
            .trim_start_matches(INK_BLACK)
            .trim_end_matches(RESET)
            .chars()
            .count();
        assert!(width >= 29, "symbol is suspiciously narrow: {width}");
    }

    #[test]
    fn invert_swaps_ink_and_paper() {
        let normal = render_unicode(URI, false).unwrap();
        let inverted = render_unicode(URI, true).unwrap();
        assert!(normal.starts_with(INK_BLACK));
        assert!(inverted.starts_with(INK_WHITE));

        // Inverted output is the complement of the normal one: the blocks are
        // cut out of white paper instead of being painted with black ink, so
        // every dark module becomes a hole.
        let complement = |s: &str| -> String {
            let body = strip(s);
            body.chars()
                .map(|ch| match ch {
                    '█' => ' ',
                    ' ' => '█',
                    '▀' => '▄',
                    '▄' => '▀',
                    other => other,
                })
                .collect()
        };
        let normal_body = strip(&normal);
        assert_eq!(complement(&inverted), normal_body);
        assert_ne!(inverted, render_unicode(URI, false).unwrap());

        // Plain output has no escape at all, the polarity is carried by the
        // characters instead.
        let plain = render_plain(URI, false).unwrap();
        assert!(!plain.contains('\x1b'));
        assert_eq!(complement(&render_plain(URI, true).unwrap()), strip(&plain));
    }

    #[test]
    fn ascii_output_is_rectangular() {
        let rendered = render_ascii(URI, false).unwrap();
        let lines: Vec<&str> = rendered.lines().collect();
        let width = lines[0].chars().count();
        assert!(
            width.is_multiple_of(2),
            "modules must be two characters wide: {width}"
        );
        for line in &lines {
            assert_eq!(line.chars().count(), width);
            assert!(line.chars().all(|c| c == '#' || c == ' '));
        }
    }

    /// A valid SVG: one background covering the symbol and a path holding every
    /// dark module, with no module outside the view box.
    #[test]
    fn svg_holds_every_dark_module() {
        let code = encode(URI).unwrap();
        let size = code.width() + 2 * QUIET_ZONE;
        let svg = render_svg(URI, false).unwrap();

        assert!(svg.contains(&format!("viewBox=\"0 0 {size} {size}\"")));
        assert!(svg.contains(&format!(
            "<rect width=\"{size}\" height=\"{size}\" fill=\"#ffffff\"/>"
        )));
        assert_eq!(svg.matches("<path").count(), 1);
        assert_eq!(svg.matches('M').count(), dark_modules(&code));
        assert!(svg.trim_end().ends_with("</svg>"));
        assert!(
            render_svg(URI, true)
                .unwrap()
                .contains("fill=\"#000000\"/>")
        );
    }

    #[test]
    fn reports_data_that_does_not_fit() {
        let huge = "otpauth://totp/NexaPipe:c?secret=".to_string() + &"A".repeat(5000);
        let error = render_unicode(&huge, false).unwrap_err();
        assert!(error.to_string().contains("failed to encode"), "{error}");
    }

    /// What a scanner finally sees: the text output is turned back into modules
    /// and handed to a real QR decoder, so a broken character mapping, a missing
    /// quiet zone or a wrong module order fails the test.
    #[test]
    fn every_text_rendering_decodes_back_to_the_uri() {
        assert_eq!(
            decode(modules_from_blocks(&render_unicode(URI, false).unwrap())),
            URI
        );
        assert_eq!(
            decode(modules_from_blocks(&render_plain(URI, false).unwrap())),
            URI
        );
        assert_eq!(
            decode(modules_from_ascii(&render_ascii(URI, false).unwrap())),
            URI
        );
    }

    /// The light-on-dark renderings carry the same symbol with every module
    /// flipped, since what a scanner reads there is our paper, not our ink.
    #[test]
    fn inverted_renderings_carry_the_same_symbol() {
        let flipped = |rows: Vec<Vec<bool>>| -> Vec<Vec<bool>> {
            rows.iter()
                .map(|row| row.iter().map(|dark| !dark).collect())
                .collect()
        };

        assert_eq!(
            decode(flipped(modules_from_blocks(
                &render_unicode(URI, true).unwrap()
            ))),
            URI
        );
        assert_eq!(
            decode(flipped(modules_from_ascii(
                &render_ascii(URI, true).unwrap()
            ))),
            URI
        );
    }

    /// Modules recovered from the half block output: the upper half of a block
    /// character is one module row and the lower half the next one.
    fn modules_from_blocks(rendered: &str) -> Vec<Vec<bool>> {
        let mut rows: Vec<Vec<bool>> = Vec::new();
        for line in rendered.lines() {
            let body = line
                .trim_start_matches(INK_BLACK)
                .trim_start_matches(INK_WHITE)
                .trim_end_matches(RESET);
            let (mut top, mut bottom) = (Vec::new(), Vec::new());
            for ch in body.chars() {
                let (upper, lower) = match ch {
                    '█' => (true, true),
                    '▀' => (true, false),
                    '▄' => (false, true),
                    ' ' => (false, false),
                    other => panic!("unexpected character {other:?} in the QR code"),
                };
                top.push(upper);
                bottom.push(lower);
            }
            rows.push(top);
            rows.push(bottom);
        }
        rows
    }

    /// Modules recovered from the ASCII output, where every module is two
    /// columns wide so that it looks square in a text file.
    fn modules_from_ascii(rendered: &str) -> Vec<Vec<bool>> {
        rendered
            .lines()
            .map(|line| line.chars().step_by(2).map(|ch| ch == '#').collect())
            .collect()
    }

    /// Hands the symbol itself to a real QR decoder. The renderings pad the
    /// bottom edge to fill the last half block and their height is not always
    /// even, so the crop is taken from the encoder's own module count rather
    /// than from the size of the recovered rows.
    fn decode(rows: Vec<Vec<bool>>) -> String {
        let size = encode(URI).unwrap().width();
        assert_eq!(size % 4, 1, "a QR symbol has 4n + 17 modules, got {size}");
        assert!(
            rows.len() >= size + 2 * QUIET_ZONE,
            "the rendering lost rows: {} < {}",
            rows.len(),
            size + 2 * QUIET_ZONE
        );
        assert!(
            rows.iter().all(|row| row.len() >= size + 2 * QUIET_ZONE),
            "the rendering lost columns"
        );

        let symbol: Vec<Vec<bool>> = rows[QUIET_ZONE..QUIET_ZONE + size]
            .iter()
            .map(|row| row[QUIET_ZONE..QUIET_ZONE + size].to_vec())
            .collect();

        let (_, content) = rqrr::Grid::new(Modules(symbol))
            .decode()
            .expect("the rendered QR code does not decode");
        content
    }

    /// Anything square of modules can be read as a QR code.
    struct Modules(Vec<Vec<bool>>);

    impl rqrr::BitGrid for Modules {
        fn size(&self) -> usize {
            self.0.len()
        }

        fn bit(&self, y: usize, x: usize) -> bool {
            self.0[y][x]
        }
    }
}
