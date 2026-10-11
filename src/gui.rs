//! Native desktop interface for BinaryInspector.

#![forbid(unsafe_code)]

use std::{
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver},
    time::Duration,
};

use binary_inspector::{
    error::AppError,
    inspect,
    model::{
        Binary, ElfNote, ExtractedString, Hardening, PieStatus, Relocation, Relro, Section,
        SecurityMitigations, Segment, StringCategory, StringEncoding, Symbol, SymbolBinding,
        SymbolTableKind, SymbolType,
    },
    report,
};
use eframe::egui;

fn main() -> eframe::Result {
    let initial_path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty());

    eframe::run_native(
        "BinaryInspector",
        eframe::NativeOptions {
            renderer: eframe::Renderer::Glow,
            viewport: egui::ViewportBuilder::default()
                .with_title("BinaryInspector — Safe Binary Analysis")
                .with_inner_size([1240.0, 820.0])
                .with_min_inner_size([760.0, 500.0]),
            ..Default::default()
        },
        Box::new(move |cc| {
            configure_theme(&cc.egui_ctx);
            let mut app = Box::<InspectorApp>::default();
            if let Some(path) = initial_path {
                app.inspect(path);
            }
            Ok(app)
        }),
    )
}

struct ThemeTokens;

impl ThemeTokens {
    pub const BG_CANVAS: egui::Color32 = egui::Color32::from_rgb(13, 16, 23); // #0d1017 Deep slate canvas
    pub const BG_PANEL: egui::Color32 = egui::Color32::from_rgb(19, 23, 34); // #131722 Sidebar / header
    pub const BG_SURFACE: egui::Color32 = egui::Color32::from_rgb(26, 32, 46); // #1a202e Elevated card
    pub const BG_SURFACE_HOVER: egui::Color32 = egui::Color32::from_rgb(34, 43, 62); // #222b3e Hover state
    pub const BG_INPUT: egui::Color32 = egui::Color32::from_rgb(16, 20, 28); // #10141c Code / input box

    pub const BORDER_SUBTLE: egui::Color32 = egui::Color32::from_rgb(38, 47, 68); // #262f44
    pub const BORDER_ACCENT: egui::Color32 = egui::Color32::from_rgb(79, 110, 247); // #4f6ef7
    pub const BORDER_ACTIVE: egui::Color32 = egui::Color32::from_rgb(102, 131, 255); // #6683ff

    pub const ACCENT_PRIMARY: egui::Color32 = egui::Color32::from_rgb(79, 110, 247); // #4f6ef7 Sapphire
    pub const ACCENT_HOVER: egui::Color32 = egui::Color32::from_rgb(102, 131, 255); // #6683ff

    pub const SUCCESS: egui::Color32 = egui::Color32::from_rgb(34, 197, 94); // #22c55e Emerald
    pub const WARNING: egui::Color32 = egui::Color32::from_rgb(245, 158, 11); // #f59e0b Amber
    pub const DANGER: egui::Color32 = egui::Color32::from_rgb(239, 68, 68); // #ef4444 Crimson
    pub const INFO: egui::Color32 = egui::Color32::from_rgb(56, 189, 248); // #38bdf8 Sky Blue

    pub const TEXT_PRIMARY: egui::Color32 = egui::Color32::from_rgb(241, 245, 249); // Slate-100
    pub const TEXT_SECONDARY: egui::Color32 = egui::Color32::from_rgb(148, 163, 184); // Slate-400
    pub const TEXT_MUTED: egui::Color32 = egui::Color32::from_rgb(100, 116, 139); // Slate-500
}

fn configure_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = ThemeTokens::BG_PANEL;
    visuals.window_fill = ThemeTokens::BG_CANVAS;
    visuals.faint_bg_color = ThemeTokens::BG_SURFACE;
    visuals.extreme_bg_color = ThemeTokens::BG_INPUT;
    visuals.code_bg_color = egui::Color32::from_rgb(20, 25, 36);
    visuals.override_text_color = Some(ThemeTokens::TEXT_PRIMARY);
    visuals.selection.bg_fill = ThemeTokens::ACCENT_PRIMARY.gamma_multiply(0.35);
    visuals.selection.stroke = egui::Stroke::new(1.0, ThemeTokens::ACCENT_HOVER);
    visuals.hyperlink_color = ThemeTokens::INFO;
    visuals.warn_fg_color = ThemeTokens::WARNING;
    visuals.error_fg_color = ThemeTokens::DANGER;

    visuals.widgets.noninteractive.bg_fill = ThemeTokens::BG_PANEL;
    visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, ThemeTokens::BORDER_SUBTLE);
    visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, ThemeTokens::TEXT_SECONDARY);
    visuals.widgets.noninteractive.corner_radius = egui::CornerRadius::same(6);

    visuals.widgets.inactive.bg_fill = ThemeTokens::BG_SURFACE;
    visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, ThemeTokens::BORDER_SUBTLE);
    visuals.widgets.inactive.fg_stroke =
        egui::Stroke::new(1.0, egui::Color32::from_rgb(226, 232, 240));
    visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(6);

    visuals.widgets.hovered.bg_fill = ThemeTokens::BG_SURFACE_HOVER;
    visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, ThemeTokens::ACCENT_PRIMARY);
    visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, egui::Color32::WHITE);
    visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(6);

    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(45, 57, 80);
    visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, ThemeTokens::ACCENT_HOVER);
    visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, egui::Color32::WHITE);
    visuals.widgets.active.corner_radius = egui::CornerRadius::same(6);

    visuals.widgets.open.bg_fill = ThemeTokens::BG_SURFACE_HOVER;
    visuals.widgets.open.bg_stroke = egui::Stroke::new(1.0, ThemeTokens::ACCENT_PRIMARY);
    visuals.widgets.open.corner_radius = egui::CornerRadius::same(6);

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style_of(egui::Theme::Dark)).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(10.0, 5.0);
    style.spacing.indent = 16.0;
    ctx.set_style_of(egui::Theme::Dark, style);
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum View {
    #[default]
    Overview,
    Mitigations,
    Symbols,
    Sections,
    Segments,
    Dependencies,
    Notes,
    Relocations,
    Strings,
}

impl View {
    fn label(&self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Mitigations => "Mitigations",
            Self::Symbols => "Symbols",
            Self::Sections => "Sections",
            Self::Segments => "Segments",
            Self::Dependencies => "Dynamic & Deps",
            Self::Notes => "Notes & Build",
            Self::Relocations => "Relocations",
            Self::Strings => "Strings & Secrets",
        }
    }

    fn icon(&self) -> &'static str {
        match self {
            Self::Overview => "📊",
            Self::Mitigations => "🛡️",
            Self::Symbols => "🏷️",
            Self::Sections => "📑",
            Self::Segments => "📦",
            Self::Dependencies => "🔗",
            Self::Notes => "📝",
            Self::Relocations => "🎯",
            Self::Strings => "🔤",
        }
    }

    fn shortcut_hint(&self) -> &'static str {
        match self {
            Self::Overview => "Alt+1",
            Self::Mitigations => "Alt+2",
            Self::Symbols => "Alt+3",
            Self::Sections => "Alt+4",
            Self::Segments => "Alt+5",
            Self::Dependencies => "Alt+6",
            Self::Notes => "Alt+7",
            Self::Relocations => "Alt+8",
            Self::Strings => "Alt+9",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum SymbolFilter {
    #[default]
    All,
    Functions,
    Objects,
    Imports,
    Exports,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum TableFilter {
    #[default]
    All,
    Dynamic,
    Static,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum SymbolSort {
    #[default]
    Index,
    Name,
    Type,
    Binding,
    Address,
    Size,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum SectionSort {
    #[default]
    Index,
    Name,
    Type,
    Address,
    Size,
    Entropy,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum SegmentSort {
    #[default]
    Index,
    Type,
    Offset,
    Address,
    Size,
    Flags,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum StringCategoryFilter {
    #[default]
    All,
    Url,
    Ip,
    FilePath,
    Crypto,
    Email,
    General,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum StringEncodingFilter {
    #[default]
    All,
    Ascii,
    Utf16Le,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum StringSort {
    #[default]
    Offset,
    Category,
    Encoding,
    Section,
    Length,
    Value,
}

#[derive(Default)]
enum Inspection {
    #[default]
    Empty,
    Loading(Receiver<(PathBuf, Result<Binary, AppError>)>),
    Ready {
        path: PathBuf,
        binary: Box<Binary>,
    },
    Failed {
        path: PathBuf,
        error: AppError,
    },
}

const DEFAULT_SIDEBAR_WIDTH: f32 = 220.0;
const DEFAULT_SECTION_COL_WIDTHS: [f32; 8] = [45.0, 160.0, 120.0, 80.0, 105.0, 85.0, 75.0, 80.0];
const DEFAULT_SEGMENT_COL_WIDTHS: [f32; 8] = [45.0, 140.0, 80.0, 95.0, 115.0, 95.0, 95.0, 80.0];
const DEFAULT_SYMBOL_COL_WIDTHS: [f32; 8] = [50.0, 220.0, 85.0, 80.0, 75.0, 105.0, 75.0, 70.0];
const DEFAULT_RELOC_COL_WIDTHS: [f32; 5] = [105.0, 65.0, 220.0, 120.0, 75.0];
const DEFAULT_STRING_COL_WIDTHS: [f32; 6] = [95.0, 90.0, 75.0, 110.0, 60.0, 320.0];

struct ViewState {
    view: View,
    search_query: String,
    section_sort: SectionSort,
    section_sort_asc: bool,
    segment_sort: SegmentSort,
    segment_sort_asc: bool,
    symbol_filter: SymbolFilter,
    symbol_table_filter: TableFilter,
    symbol_sort: SymbolSort,
    symbol_sort_asc: bool,
    selected_symbol: Option<usize>,
    symbol_detail_height: f32,
    symbol_col_widths: [f32; 8],
    reloc_col_widths: [f32; 5],
    status_message: Option<(String, std::time::Instant)>,
    sidebar_width: f32,
    section_col_widths: [f32; 8],
    selected_section: Option<u16>,
    section_detail_height: f32,
    segment_col_widths: [f32; 8],
    selected_segment: Option<u16>,
    segment_detail_height: f32,
    focus_search: bool,
    string_category_filter: StringCategoryFilter,
    string_encoding_filter: StringEncodingFilter,
    string_sort: StringSort,
    string_sort_asc: bool,
    selected_string: Option<usize>,
    string_detail_height: f32,
    string_col_widths: [f32; 6],
    string_min_len: usize,
}

impl Default for ViewState {
    fn default() -> Self {
        Self {
            view: View::Overview,
            search_query: String::new(),
            section_sort: SectionSort::Index,
            section_sort_asc: true,
            segment_sort: SegmentSort::Index,
            segment_sort_asc: true,
            symbol_filter: SymbolFilter::All,
            symbol_table_filter: TableFilter::All,
            symbol_sort: SymbolSort::Index,
            symbol_sort_asc: true,
            selected_symbol: None,
            symbol_detail_height: 180.0,
            symbol_col_widths: DEFAULT_SYMBOL_COL_WIDTHS,
            reloc_col_widths: DEFAULT_RELOC_COL_WIDTHS,
            status_message: None,
            sidebar_width: DEFAULT_SIDEBAR_WIDTH,
            section_col_widths: DEFAULT_SECTION_COL_WIDTHS,
            selected_section: None,
            section_detail_height: 180.0,
            segment_col_widths: DEFAULT_SEGMENT_COL_WIDTHS,
            selected_segment: None,
            segment_detail_height: 180.0,
            focus_search: false,
            string_category_filter: StringCategoryFilter::All,
            string_encoding_filter: StringEncodingFilter::All,
            string_sort: StringSort::Offset,
            string_sort_asc: true,
            selected_string: None,
            string_detail_height: 180.0,
            string_col_widths: DEFAULT_STRING_COL_WIDTHS,
            string_min_len: 4,
        }
    }
}

impl ViewState {
    fn set_status(&mut self, message: impl Into<String>) {
        self.status_message = Some((message.into(), std::time::Instant::now()));
    }
}

#[derive(Default)]
struct InspectorApp {
    inspection: Inspection,
    view_state: ViewState,
    recent_files: Vec<PathBuf>,
}

impl InspectorApp {
    fn inspect(&mut self, path: PathBuf) {
        if !self.recent_files.contains(&path) {
            self.recent_files.insert(0, path.clone());
            if self.recent_files.len() > 8 {
                self.recent_files.pop();
            }
        }

        let (sender, receiver) = mpsc::channel();
        std::thread::spawn({
            let path = path.clone();
            move || {
                let _ = sender.send((path.clone(), inspect(&path)));
            }
        });
        self.inspection = Inspection::Loading(receiver);
        self.view_state.view = View::Overview;
        self.view_state.search_query.clear();
        self.view_state.selected_symbol = None;
        self.view_state.selected_section = None;
        self.view_state.selected_segment = None;
    }

    fn reload_current(&mut self) {
        if let Inspection::Ready { path, .. } = &self.inspection {
            let p = path.clone();
            self.inspect(p);
            self.view_state.set_status("Re-inspected binary");
        }
    }

    fn export_json(&mut self) {
        let json_opt = match &self.inspection {
            Inspection::Ready { binary, .. } => report::report_json(binary).ok(),
            _ => None,
        };
        if let Some(json) = json_opt {
            let dialog = rfd::FileDialog::new()
                .set_title("Export Binary Inspection Report (JSON)")
                .set_file_name("binary-report.json");
            if let Some(path) = dialog.save_file() {
                match std::fs::write(&path, json) {
                    Ok(()) => self
                        .view_state
                        .set_status(format!("Exported to {}", path.display())),
                    Err(e) => self.view_state.set_status(format!("Export failed: {e}")),
                }
            }
        }
    }

    fn copy_json(&mut self, ctx: &egui::Context) {
        let json_opt = match &self.inspection {
            Inspection::Ready { binary, .. } => report::report_json(binary).ok(),
            _ => None,
        };
        if let Some(json) = json_opt {
            ctx.copy_text(json);
            self.view_state
                .set_status("JSON report copied to clipboard");
        }
    }

    fn clear_recents(&mut self) {
        self.recent_files.clear();
        self.view_state.set_status("Recent binary history cleared");
    }

    fn poll(&mut self, context: &egui::Context) {
        if matches!(&self.inspection, Inspection::Loading(_)) {
            context.request_repaint_after(Duration::from_millis(40));
        }

        let result = match &self.inspection {
            Inspection::Loading(receiver) => receiver.try_recv().ok(),
            _ => None,
        };

        if let Some((path, inspect_result)) = result {
            match inspect_result {
                Ok(binary) => {
                    let file_name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "Binary".to_string());
                    self.view_state.set_status(format!("Loaded {file_name}"));
                    self.inspection = Inspection::Ready {
                        path,
                        binary: Box::new(binary),
                    };
                }
                Err(error) => {
                    self.inspection = Inspection::Failed { path, error };
                }
            }
            context.request_repaint();
        }
    }

    fn choose_file(&mut self) {
        let dialog = rfd::FileDialog::new().set_title("Select ELF Binary to Inspect");
        if let Some(path) = dialog.pick_file() {
            self.inspect(path);
        }
    }
}

impl eframe::App for InspectorApp {
    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        let context = ui.ctx().clone();
        self.poll(&context);

        // Global shortcuts
        let (open_pressed, reload_pressed, esc_pressed, alt_view, ctrl_f) =
            context.input(|input| {
                let open = input.modifiers.command && input.key_pressed(egui::Key::O);
                let reload = input.key_pressed(egui::Key::F5)
                    || (input.modifiers.command && input.key_pressed(egui::Key::R));
                let esc = input.key_pressed(egui::Key::Escape);
                let ctrl_f = input.modifiers.command && input.key_pressed(egui::Key::F);

                let alt_view = if input.modifiers.alt {
                    if input.key_pressed(egui::Key::Num1) {
                        Some(View::Overview)
                    } else if input.key_pressed(egui::Key::Num2) {
                        Some(View::Mitigations)
                    } else if input.key_pressed(egui::Key::Num3) {
                        Some(View::Symbols)
                    } else if input.key_pressed(egui::Key::Num4) {
                        Some(View::Sections)
                    } else if input.key_pressed(egui::Key::Num5) {
                        Some(View::Segments)
                    } else if input.key_pressed(egui::Key::Num6) {
                        Some(View::Dependencies)
                    } else if input.key_pressed(egui::Key::Num7) {
                        Some(View::Notes)
                    } else if input.key_pressed(egui::Key::Num8) {
                        Some(View::Relocations)
                    } else if input.key_pressed(egui::Key::Num9) {
                        Some(View::Strings)
                    } else {
                        None
                    }
                } else {
                    None
                };

                (open, reload, esc, alt_view, ctrl_f)
            });

        if open_pressed {
            self.choose_file();
        }
        if reload_pressed {
            self.reload_current();
        }
        if ctrl_f {
            self.view_state.focus_search = true;
        }
        if let Some(view) = alt_view {
            self.view_state.view = view;
        }
        if esc_pressed {
            if self.view_state.selected_section.is_some() {
                self.view_state.selected_section = None;
            } else if self.view_state.selected_segment.is_some() {
                self.view_state.selected_segment = None;
            } else if self.view_state.selected_symbol.is_some() {
                self.view_state.selected_symbol = None;
            } else if !self.view_state.search_query.is_empty() {
                self.view_state.search_query.clear();
            } else if matches!(
                self.inspection,
                Inspection::Ready { .. } | Inspection::Failed { .. }
            ) {
                self.inspection = Inspection::Empty;
            }
        }

        // Handle Drag and Drop
        let is_hovering = context.input(|input| !input.raw.hovered_files.is_empty());
        let dropped_file = context.input(|input| {
            input
                .raw
                .dropped_files
                .first()
                .map(|file| file.path().to_path_buf())
                .filter(|path| !path.as_os_str().is_empty())
        });
        if let Some(path) = dropped_file {
            self.inspect(path);
        }

        self.render_main_ui(ui, is_hovering);
    }
}

impl InspectorApp {
    fn render_main_ui(&mut self, ui: &mut egui::Ui, is_hovering: bool) {
        let mut choose_file = false;
        let mut reload_file = false;
        let mut unload_file = false;
        let mut cancel_load = false;
        let mut export_json_req = false;
        let mut copy_json_req = false;

        // Top Control Bar
        let top_frame = egui::Frame::new()
            .fill(ThemeTokens::BG_PANEL)
            .inner_margin(egui::Margin::symmetric(14, 10));

        top_frame.show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 10.0;

                // Brand Mark
                ui.label(
                    egui::RichText::new("🔬")
                        .size(19.0)
                        .color(ThemeTokens::ACCENT_PRIMARY),
                );
                ui.label(
                    egui::RichText::new("BinaryInspector")
                        .strong()
                        .size(16.0)
                        .color(ThemeTokens::TEXT_PRIMARY),
                );

                badge(ui, "v0.3.0", ThemeTokens::TEXT_MUTED);

                ui.separator();

                match &self.inspection {
                    Inspection::Ready { path, binary } => {
                        let file_name = path
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| "Binary".to_string());

                        let pill = egui::Frame::new()
                            .fill(ThemeTokens::BG_SURFACE)
                            .corner_radius(egui::CornerRadius::same(5))
                            .stroke(egui::Stroke::new(1.0, ThemeTokens::BORDER_SUBTLE))
                            .inner_margin(egui::Margin::symmetric(8, 4));

                        pill.show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new(&file_name)
                                        .strong()
                                        .monospace()
                                        .size(13.0)
                                        .color(ThemeTokens::TEXT_PRIMARY),
                                );
                                ui.label(
                                    egui::RichText::new(format_bytes(binary.file.size_bytes))
                                        .size(11.5)
                                        .color(ThemeTokens::TEXT_MUTED),
                                );
                                if ui
                                    .small_button("✕")
                                    .on_hover_text("Close binary (Esc)")
                                    .clicked()
                                {
                                    unload_file = true;
                                }
                            });
                        });

                        if ui
                            .button(egui::RichText::new("↻ Reload").size(12.5))
                            .on_hover_text("Re-inspect binary from disk (F5 / Ctrl+R)")
                            .clicked()
                        {
                            reload_file = true;
                        }

                        if ui
                            .button(egui::RichText::new("📤 Export JSON").size(12.5))
                            .on_hover_text("Save full inspection report to a JSON file")
                            .clicked()
                        {
                            export_json_req = true;
                        }

                        if ui
                            .button(egui::RichText::new("📋 Copy JSON").size(12.5))
                            .on_hover_text("Copy report JSON to clipboard")
                            .clicked()
                        {
                            copy_json_req = true;
                        }
                    }
                    Inspection::Loading(_) => {
                        ui.spinner();
                        ui.label(
                            egui::RichText::new("Inspecting binary safely…")
                                .color(ThemeTokens::TEXT_SECONDARY),
                        );
                    }
                    _ => {}
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let open_btn = egui::Button::new(
                        egui::RichText::new("📂 Open Binary (Ctrl+O)")
                            .strong()
                            .size(13.0)
                            .color(egui::Color32::WHITE),
                    )
                    .fill(ThemeTokens::ACCENT_PRIMARY)
                    .corner_radius(egui::CornerRadius::same(6));

                    if ui.add(open_btn).clicked() {
                        choose_file = true;
                    }
                });
            });
        });

        if choose_file {
            self.choose_file();
        }
        if reload_file {
            self.reload_current();
        }
        if unload_file {
            self.inspection = Inspection::Empty;
            self.view_state.search_query.clear();
            self.view_state.set_status("Binary closed");
        }
        if export_json_req {
            self.export_json();
        }
        if copy_json_req {
            let ctx = ui.ctx().clone();
            self.copy_json(&ctx);
        }

        // Central Area
        if is_hovering {
            render_drop_overlay(ui);
            return;
        }

        let central_height = (ui.available_height() - 32.0).max(120.0);
        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width(), central_height),
            egui::Layout::top_down(egui::Align::LEFT),
            |ui| match &self.inspection {
                Inspection::Empty => {
                    let mut sample_to_load = None;
                    let mut clear_recents_req = false;
                    self.render_empty_state(
                        ui,
                        &mut sample_to_load,
                        &mut choose_file,
                        &mut clear_recents_req,
                    );
                    if let Some(path) = sample_to_load {
                        self.inspect(path);
                    }
                    if choose_file {
                        self.choose_file();
                    }
                    if clear_recents_req {
                        self.clear_recents();
                    }
                }
                Inspection::Loading(_) => {
                    ui.centered_and_justified(|ui| {
                        ui.vertical_centered(|ui| {
                            ui.spinner();
                            ui.add_space(14.0);
                            ui.label(
                                egui::RichText::new("Parsing Binary Structures Safely…")
                                    .size(17.0)
                                    .strong()
                                    .color(ThemeTokens::TEXT_PRIMARY),
                            );
                            ui.add_space(6.0);
                            ui.label(
                                egui::RichText::new(
                                    "Analyzing headers, symbols, notes, relocations, and security mitigations",
                                )
                                .size(13.0)
                                .color(ThemeTokens::TEXT_SECONDARY),
                            );
                            ui.add_space(16.0);
                            if ui.button("Cancel Inspection").clicked() {
                                cancel_load = true;
                            }
                        });
                    });
                }
                Inspection::Failed { path, error } => {
                    let mut pick = false;
                    render_failed_state(ui, path, error, &mut pick);
                    if pick {
                        self.choose_file();
                    }
                }
                Inspection::Ready { path, binary } => {
                    self.view_state.render_ready(ui, path, binary);
                }
            },
        );

        if cancel_load {
            self.inspection = Inspection::Empty;
            self.view_state.set_status("Inspection cancelled");
        }

        // Bottom Status Bar
        let status_frame = egui::Frame::new()
            .fill(ThemeTokens::BG_PANEL)
            .inner_margin(egui::Margin::symmetric(14, 6));

        status_frame.show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;

                if let Some((msg, time)) = &self.view_state.status_message
                    && time.elapsed() < Duration::from_secs(3)
                {
                    ui.label(
                        egui::RichText::new(format!("✓ {msg}"))
                            .color(ThemeTokens::SUCCESS)
                            .strong()
                            .size(12.0),
                    );
                    ui.separator();
                } else {
                    ui.label(
                        egui::RichText::new("Ready")
                            .color(ThemeTokens::TEXT_MUTED)
                            .size(12.0),
                    );
                    ui.separator();
                }

                if let Inspection::Ready { binary, .. } = &self.inspection {
                    if let Some(elf) = &binary.elf {
                        status_chip(ui, &format!("{}", elf.class));
                        status_chip(ui, &format!("{}", elf.machine));
                        status_chip(ui, &format!("{}", elf.endianness));
                        status_chip(ui, &format!("{}", elf.elf_type));
                    } else if let Some(pe) = &binary.pe {
                        status_chip(
                            ui,
                            if pe.is_pe32_plus {
                                "PE32+ (64-bit)"
                            } else {
                                "PE32 (32-bit)"
                            },
                        );
                        status_chip(ui, &format!("{}", pe.machine));
                        status_chip(ui, "little-endian");
                        status_chip(ui, &format!("{}", pe.subsystem));
                    } else if let Some(macho) = &binary.macho {
                        status_chip(
                            ui,
                            if macho.is_64_bit {
                                "Mach-O 64-bit"
                            } else {
                                "Mach-O 32-bit"
                            },
                        );
                        status_chip(ui, &macho.cpu_arch);
                        status_chip(
                            ui,
                            if macho.is_little_endian {
                                "little-endian"
                            } else {
                                "big-endian"
                            },
                        );
                        status_chip(ui, &macho.file_type);
                    }
                    ui.separator();
                    ui.small(format!("Sections: {}", binary.sections.len()));
                    ui.small(format!("Symbols: {}", binary.symbols.len()));
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new("🛡️ Local analysis only — binary never executed")
                            .size(11.5)
                            .color(ThemeTokens::TEXT_MUTED),
                    )
                    .on_hover_text(
                        "BinaryInspector parses binary headers and structures locally in safe memory without executing instructions.",
                    );
                });
            });
        });
    }
}

fn status_chip(ui: &mut egui::Ui, text: &str) {
    let frame = egui::Frame::new()
        .fill(ThemeTokens::BG_SURFACE)
        .corner_radius(egui::CornerRadius::same(4))
        .inner_margin(egui::Margin::symmetric(6, 2));

    frame.show(ui, |ui| {
        ui.label(
            egui::RichText::new(text)
                .size(11.5)
                .color(ThemeTokens::TEXT_SECONDARY),
        );
    });
}

impl InspectorApp {
    fn render_empty_state(
        &self,
        ui: &mut egui::Ui,
        sample_to_load: &mut Option<PathBuf>,
        choose_file: &mut bool,
        clear_recents: &mut bool,
    ) {
        ui.vertical_centered(|ui| {
            ui.add_space(48.0);

            let hero_frame = egui::Frame::new()
                .fill(ThemeTokens::BG_SURFACE)
                .corner_radius(egui::CornerRadius::same(12))
                .stroke(egui::Stroke::new(1.0, ThemeTokens::BORDER_SUBTLE))
                .inner_margin(egui::Margin::symmetric(40, 32));

            hero_frame.show(ui, |ui| {
                ui.set_max_width(560.0);

                ui.label(
                    egui::RichText::new("⚡")
                        .size(42.0)
                        .color(ThemeTokens::ACCENT_PRIMARY),
                );
                ui.add_space(8.0);
                ui.heading(
                    egui::RichText::new("Inspect an Executable Binary")
                        .size(23.0)
                        .color(ThemeTokens::TEXT_PRIMARY),
                );
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(
                        "Drag and drop any ELF (Linux) or PE/COFF (Windows .exe/.dll) binary file.\nBinaryInspector safely extracts header structure, security mitigations, symbols, and entropy.",
                    )
                    .color(ThemeTokens::TEXT_SECONDARY)
                    .size(13.5),
                );

                ui.add_space(20.0);

                let btn = egui::Button::new(
                    egui::RichText::new("  Choose Binary (Ctrl+O)  ")
                        .strong()
                        .size(14.5)
                        .color(egui::Color32::WHITE),
                )
                .fill(ThemeTokens::ACCENT_PRIMARY)
                .corner_radius(egui::CornerRadius::same(6));

                if ui.add(btn).clicked() {
                    *choose_file = true;
                }
            });

            // Quick Samples Section
            let mut sample_candidates: Vec<(&'static str, PathBuf)> = Vec::new();
            for (label, path_str) in [
                ("dynamic-c-binary", "samples/dynamic-c-binary"),
                ("minimal-static", "samples/minimal-static"),
                ("custom-sections", "samples/custom-sections"),
                ("with-rpath-runpath", "samples/with-rpath-runpath"),
            ] {
                let p = PathBuf::from(path_str);
                if p.exists() {
                    sample_candidates.push((label, p));
                }
            }

            #[cfg(unix)]
            {
                for (label, path_str) in [
                    ("/bin/ls", "/bin/ls"),
                    ("/bin/sh", "/bin/sh"),
                    ("/usr/bin/env", "/usr/bin/env"),
                ] {
                    let p = PathBuf::from(path_str);
                    if p.exists() && !sample_candidates.iter().any(|(_, sp)| sp == &p) {
                        sample_candidates.push((label, p));
                    }
                }
            }

            if !sample_candidates.is_empty() {
                ui.add_space(28.0);
                ui.label(
                    egui::RichText::new("OR TRY A SAMPLE BINARY")
                        .strong()
                        .size(11.0)
                        .color(ThemeTokens::TEXT_MUTED),
                );
                ui.add_space(8.0);

                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    for (label, path) in sample_candidates {
                        let btn = egui::Button::new(
                            egui::RichText::new(format!("📄 {label}"))
                                .monospace()
                                .size(12.5),
                        )
                        .fill(ThemeTokens::BG_SURFACE)
                        .stroke(egui::Stroke::new(1.0, ThemeTokens::BORDER_SUBTLE));

                        if ui.add(btn).clicked() {
                            *sample_to_load = Some(path);
                        }
                    }
                });
            }

            if !self.recent_files.is_empty() {
                ui.add_space(28.0);
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("RECENT BINARIES")
                            .strong()
                            .size(11.0)
                            .color(ThemeTokens::TEXT_MUTED),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .button(
                                egui::RichText::new("Clear History")
                                    .size(11.0)
                                    .color(ThemeTokens::TEXT_MUTED),
                            )
                            .clicked()
                        {
                            *clear_recents = true;
                        }
                    });
                });
                ui.add_space(6.0);

                let recent_box = egui::Frame::new()
                    .fill(ThemeTokens::BG_PANEL)
                    .corner_radius(egui::CornerRadius::same(8))
                    .stroke(egui::Stroke::new(1.0, ThemeTokens::BORDER_SUBTLE))
                    .inner_margin(egui::Margin::symmetric(16, 10));

                recent_box.show(ui, |ui| {
                    ui.set_max_width(560.0);
                    for path in &self.recent_files {
                        let name = path
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| path.display().to_string());
                        ui.horizontal(|ui| {
                            ui.label("🕒");
                            if ui
                                .link(
                                    egui::RichText::new(&name)
                                        .strong()
                                        .monospace()
                                        .color(ThemeTokens::ACCENT_HOVER),
                                )
                                .on_hover_text(path.display().to_string())
                                .clicked()
                            {
                                *sample_to_load = Some(path.clone());
                            }
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if let Ok(meta) = std::fs::metadata(path) {
                                        ui.small(format_bytes(meta.len()));
                                    }
                                },
                            );
                        });
                    }
                });
            }
        });
    }
}

fn render_failed_state(ui: &mut egui::Ui, path: &Path, error: &AppError, choose_file: &mut bool) {
    let (category, hint) = error.guidance();

    ui.centered_and_justified(|ui| {
        ui.vertical_centered(|ui| {
            ui.label(
                egui::RichText::new("⚠️")
                    .size(46.0)
                    .color(ThemeTokens::DANGER),
            );
            ui.add_space(8.0);
            ui.heading(
                egui::RichText::new("Inspection Failed")
                    .size(22.0)
                    .color(ThemeTokens::DANGER),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(path.display().to_string())
                    .monospace()
                    .color(ThemeTokens::TEXT_MUTED),
            );
            ui.add_space(16.0);

            let error_box = egui::Frame::new()
                .fill(ThemeTokens::BG_SURFACE)
                .corner_radius(egui::CornerRadius::same(8))
                .stroke(egui::Stroke::new(
                    1.0,
                    ThemeTokens::DANGER.gamma_multiply(0.5),
                ))
                .inner_margin(egui::Margin::symmetric(24, 18));

            error_box.show(ui, |ui| {
                ui.set_max_width(520.0);
                ui.label(
                    egui::RichText::new(category)
                        .strong()
                        .size(15.0)
                        .color(ThemeTokens::DANGER),
                );
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(hint)
                        .size(13.0)
                        .color(ThemeTokens::TEXT_SECONDARY),
                );
                ui.add_space(10.0);
                let err_pre = egui::Frame::new()
                    .fill(ThemeTokens::BG_INPUT)
                    .corner_radius(egui::CornerRadius::same(4))
                    .inner_margin(egui::Margin::symmetric(10, 8));
                err_pre.show(ui, |ui| {
                    ui.label(
                        egui::RichText::new(error.to_string())
                            .color(ThemeTokens::DANGER)
                            .monospace()
                            .size(12.0),
                    );
                });
            });

            ui.add_space(20.0);
            if ui
                .button(
                    egui::RichText::new("  Choose Another Binary  ")
                        .strong()
                        .size(13.5),
                )
                .clicked()
            {
                *choose_file = true;
            }
        });
    });
}

impl ViewState {
    fn render_ready(&mut self, ui: &mut egui::Ui, path: &Path, binary: &Binary) {
        ui.horizontal_top(|ui| {
            let avail_h = ui.available_height();

            // 1. Sidebar Navigation Rail
            ui.allocate_ui_with_layout(
                egui::vec2(self.sidebar_width, avail_h),
                egui::Layout::top_down(egui::Align::LEFT),
                |ui| {
                    ui.set_width(self.sidebar_width);
                    ui.add_space(8.0);

                    let nav_item = |ui: &mut egui::Ui,
                                    current_view: &mut View,
                                    target: View,
                                    badge_count: Option<usize>| {
                        let is_active = *current_view == target;
                        let item_w = ui.available_width();
                        let (rect, resp) =
                            ui.allocate_exact_size(egui::vec2(item_w, 36.0), egui::Sense::click());
                        let is_hovered = resp.hovered();

                        if is_hovered {
                            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                        }

                        let bg_color = if is_active {
                            ThemeTokens::BG_SURFACE_HOVER
                        } else if is_hovered {
                            ThemeTokens::BG_SURFACE
                        } else {
                            egui::Color32::TRANSPARENT
                        };

                        let border_stroke = if is_active {
                            egui::Stroke::new(1.0, ThemeTokens::BORDER_ACCENT)
                        } else if is_hovered {
                            egui::Stroke::new(1.0, ThemeTokens::BORDER_SUBTLE)
                        } else {
                            egui::Stroke::NONE
                        };

                        ui.painter().rect(
                            rect,
                            egui::CornerRadius::same(6),
                            bg_color,
                            border_stroke,
                            egui::StrokeKind::Inside,
                        );

                        let content_rect = rect.shrink2(egui::vec2(10.0, 4.0));
                        let mut content_ui = ui.new_child(
                            egui::UiBuilder::new()
                                .max_rect(content_rect)
                                .layout(egui::Layout::left_to_right(egui::Align::Center)),
                        );

                        content_ui.spacing_mut().item_spacing.x = 8.0;
                        content_ui.label(egui::RichText::new(target.icon()).size(14.0));
                        content_ui.label(
                            egui::RichText::new(target.label())
                                .size(13.0)
                                .strong()
                                .color(if is_active || is_hovered {
                                    ThemeTokens::TEXT_PRIMARY
                                } else {
                                    ThemeTokens::TEXT_SECONDARY
                                }),
                        );

                        if let Some(count) = badge_count {
                            content_ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    let count_str = if count > 999 {
                                        format!("{:.1}k", count as f64 / 1000.0)
                                    } else {
                                        count.to_string()
                                    };
                                    let badge_bg = if is_active {
                                        ThemeTokens::ACCENT_PRIMARY.gamma_multiply(0.25)
                                    } else if is_hovered {
                                        ThemeTokens::BG_PANEL
                                    } else {
                                        ThemeTokens::BG_SURFACE
                                    };
                                    let badge_txt = if is_active {
                                        ThemeTokens::ACCENT_HOVER
                                    } else {
                                        ThemeTokens::TEXT_MUTED
                                    };

                                    let pill = egui::Frame::new()
                                        .fill(badge_bg)
                                        .corner_radius(egui::CornerRadius::same(10))
                                        .inner_margin(egui::Margin::symmetric(6, 2));
                                    pill.show(ui, |ui| {
                                        ui.label(
                                            egui::RichText::new(count_str)
                                                .size(10.5)
                                                .monospace()
                                                .color(badge_txt),
                                        );
                                    });
                                },
                            );
                        }

                        if resp
                            .on_hover_text(format!(
                                "Switch to {} ({})",
                                target.label(),
                                target.shortcut_hint()
                            ))
                            .clicked()
                        {
                            *current_view = target;
                        }

                        ui.add_space(2.0);
                    };

                    nav_item(ui, &mut self.view, View::Overview, None);
                    nav_item(ui, &mut self.view, View::Mitigations, None);
                    nav_item(
                        ui,
                        &mut self.view,
                        View::Symbols,
                        Some(binary.symbols.len()),
                    );
                    nav_item(
                        ui,
                        &mut self.view,
                        View::Sections,
                        Some(binary.sections.len()),
                    );
                    nav_item(
                        ui,
                        &mut self.view,
                        View::Segments,
                        Some(binary.segments.len()),
                    );
                    nav_item(
                        ui,
                        &mut self.view,
                        View::Dependencies,
                        Some(binary.dynamic.needed.len()),
                    );
                    nav_item(ui, &mut self.view, View::Notes, Some(binary.notes.len()));
                    nav_item(
                        ui,
                        &mut self.view,
                        View::Relocations,
                        Some(binary.relocations.len()),
                    );
                    nav_item(
                        ui,
                        &mut self.view,
                        View::Strings,
                        Some(binary.strings.len()),
                    );

                    ui.add_space(16.0);
                    ui.separator();
                    ui.add_space(8.0);

                    // Target Card
                    let target_card = egui::Frame::new()
                        .fill(ThemeTokens::BG_SURFACE)
                        .corner_radius(egui::CornerRadius::same(8))
                        .stroke(egui::Stroke::new(1.0, ThemeTokens::BORDER_SUBTLE))
                        .inner_margin(egui::Margin::symmetric(10, 10));

                    target_card.show(ui, |ui| {
                        ui.label(
                            egui::RichText::new("ANALYSIS TARGET")
                                .strong()
                                .size(10.0)
                                .color(ThemeTokens::TEXT_MUTED),
                        );
                        let file_name = path
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| "Binary".to_string());
                        ui.label(
                            egui::RichText::new(file_name)
                                .strong()
                                .size(13.0)
                                .color(ThemeTokens::TEXT_PRIMARY),
                        );
                        ui.small(format_bytes(binary.file.size_bytes));
                        ui.add_space(4.0);
                        if ui.small_button("📋 Copy Path").clicked() {
                            ui.ctx().copy_text(path.display().to_string());
                            self.set_status("Path copied to clipboard");
                        }
                        if ui.small_button("📋 Copy Hash").clicked() {
                            ui.ctx().copy_text(binary.hashes.sha256.clone());
                            self.set_status("SHA-256 hash copied");
                        }
                    });
                },
            );

            // 2. High-performance draggable vertical separator handle
            let (splitter_rect, splitter_resp) =
                ui.allocate_exact_size(egui::vec2(6.0, avail_h), egui::Sense::click_and_drag());
            if splitter_resp.hovered() || splitter_resp.dragged() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeHorizontal);
            }
            if splitter_resp.dragged() {
                self.sidebar_width =
                    (self.sidebar_width + splitter_resp.drag_delta().x).clamp(160.0, 480.0);
            }
            if splitter_resp.double_clicked() {
                self.sidebar_width = DEFAULT_SIDEBAR_WIDTH;
            }
            let splitter_color = if splitter_resp.dragged() {
                ThemeTokens::BORDER_ACTIVE
            } else if splitter_resp.hovered() {
                ThemeTokens::ACCENT_HOVER
            } else {
                ThemeTokens::BORDER_SUBTLE
            };
            ui.painter().vline(
                splitter_rect.center().x,
                splitter_rect.y_range(),
                egui::Stroke::new(1.0, splitter_color),
            );

            // 3. Main Content Area
            ui.vertical(|ui| match self.view {
                View::Overview => self.render_overview(ui, path, binary),
                View::Mitigations => self.render_mitigations(ui, &binary.mitigations),
                View::Symbols => self.render_symbols(ui, binary),
                View::Sections => self.render_sections(ui, binary),
                View::Segments => self.render_segments(ui, binary),
                View::Dependencies => self.render_dependencies(ui, binary),
                View::Notes => self.render_notes(ui, &binary.notes),
                View::Relocations => self.render_relocations(ui, &binary.relocations),
                View::Strings => self.render_strings(ui, binary),
            });
        });
    }

    fn render_overview(&mut self, ui: &mut egui::Ui, path: &Path, binary: &Binary) {
        ui.horizontal(|ui| {
            ui.heading(
                egui::RichText::new("Binary Overview")
                    .size(20.0)
                    .strong()
                    .color(ThemeTokens::TEXT_PRIMARY),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .button(egui::RichText::new("🛡️ Mitigations Dashboard (Alt+2)").size(12.0))
                    .clicked()
                {
                    self.view = View::Mitigations;
                }
            });
        });

        ui.add_space(8.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            // Card 1: Executive Security Hardening Scorecard
            let score_frame = egui::Frame::new()
                .fill(ThemeTokens::BG_SURFACE)
                .corner_radius(egui::CornerRadius::same(8))
                .stroke(egui::Stroke::new(1.0, ThemeTokens::BORDER_SUBTLE))
                .inner_margin(egui::Margin::symmetric(18, 14));

            score_frame.show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.strong(
                        egui::RichText::new("🛡️ Security Protections Scorecard (checksec)")
                            .size(15.0),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if binary.mitigations.rwx_segments > 0 {
                            badge(ui, "⚠️ W^X VIOLATION", ThemeTokens::DANGER);
                        } else if binary.mitigations.relro == Relro::Full
                            && binary.mitigations.stack_canary == Hardening::Enabled
                            && binary.mitigations.nx == Hardening::Enabled
                            && binary.mitigations.pie == PieStatus::Pie
                        {
                            badge(ui, "✓ FULLY HARDENED", ThemeTokens::SUCCESS);
                        }
                    });
                });
                ui.add_space(8.0);

                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing = egui::vec2(10.0, 10.0);

                    // RELRO
                    let (relro_txt, relro_col) = match binary.mitigations.relro {
                        Relro::Full => ("Full RELRO", ThemeTokens::SUCCESS),
                        Relro::Partial => ("Partial RELRO", ThemeTokens::WARNING),
                        Relro::None => ("No RELRO", ThemeTokens::DANGER),
                        Relro::Unknown => ("Unknown", ThemeTokens::TEXT_MUTED),
                    };
                    if scorecard_item(ui, "RELRO", relro_txt, relro_col, "🔒", "Relocation Read-Only: protects Global Offset Table from tampering") {
                        self.view = View::Mitigations;
                    }

                    // Stack Canary
                    let (can_txt, can_col) = match binary.mitigations.stack_canary {
                        Hardening::Enabled => ("Canary Found", ThemeTokens::SUCCESS),
                        Hardening::Disabled => ("No Canary", ThemeTokens::DANGER),
                        Hardening::Unknown => ("Unknown", ThemeTokens::TEXT_MUTED),
                    };
                    if scorecard_item(ui, "Stack Canary", can_txt, can_col, "🐤", "Stack smashing protection: detects buffer overflows before return") {
                        self.view = View::Mitigations;
                    }

                    // NX
                    let (nx_txt, nx_col) = match binary.mitigations.nx {
                        Hardening::Enabled => ("NX Enabled", ThemeTokens::SUCCESS),
                        Hardening::Disabled => ("NX Disabled", ThemeTokens::DANGER),
                        Hardening::Unknown => ("Unknown", ThemeTokens::TEXT_MUTED),
                    };
                    if scorecard_item(ui, "NX / DEP", nx_txt, nx_col, "🚫", "Non-Executable Stack: prevents direct shellcode execution in data pages") {
                        self.view = View::Mitigations;
                    }

                    // PIE
                    let (pie_txt, pie_col) = match binary.mitigations.pie {
                        PieStatus::Pie => ("PIE Enabled", ThemeTokens::SUCCESS),
                        PieStatus::Dso => ("DSO / Shared", ThemeTokens::INFO),
                        PieStatus::NoPie => ("No PIE", ThemeTokens::WARNING),
                        PieStatus::Unknown => ("Unknown", ThemeTokens::TEXT_MUTED),
                    };
                    if scorecard_item(ui, "PIE / ASLR", pie_txt, pie_col, "🎲", "Position-Independent Executable: full address space layout randomization") {
                        self.view = View::Mitigations;
                    }

                    // Fortify
                    let (fort_txt, fort_col) = match binary.mitigations.fortify {
                        Hardening::Enabled => (
                            "Fortified",
                            ThemeTokens::SUCCESS,
                        ),
                        Hardening::Disabled => ("None Detected", ThemeTokens::TEXT_MUTED),
                        Hardening::Unknown => ("Unknown", ThemeTokens::TEXT_MUTED),
                    };
                    if scorecard_item(ui, "FORTIFY", fort_txt, fort_col, "🛡️", "Compile-time & run-time bounds checks on buffer/string libc calls") {
                        self.view = View::Mitigations;
                    }

                    // W^X Policy
                    let (wx_txt, wx_col) = if binary.mitigations.rwx_segments == 0 {
                        ("Enforced (0 RWX)", ThemeTokens::SUCCESS)
                    } else {
                        ("VIOLATION", ThemeTokens::DANGER)
                    };
                    if scorecard_item(ui, "W^X Memory", wx_txt, wx_col, "⚡", "Write XOR Execute: guarantees memory is never simultaneously writable and executable") {
                        self.view = View::Mitigations;
                    }

                    // RPATH
                    let (rpath_txt, rpath_col) = if binary.mitigations.has_insecure_rpath {
                        ("Insecure Paths", ThemeTokens::WARNING)
                    } else {
                        ("Clean", ThemeTokens::SUCCESS)
                    };
                    if scorecard_item(ui, "RPATH Clean", rpath_txt, rpath_col, "🔍", "Validates library search paths against insecure relative or world-writable paths") {
                        self.view = View::Mitigations;
                    }
                });
            });

            ui.add_space(10.0);

            // Card 2: Binary Architecture & ABI
            egui::CollapsingHeader::new(
                egui::RichText::new("⚙️ Architecture & File Profile")
                    .heading()
                    .size(15.0),
            )
            .default_open(true)
            .show(ui, |ui| {
                let card = egui::Frame::new()
                    .fill(ThemeTokens::BG_SURFACE)
                    .corner_radius(egui::CornerRadius::same(8))
                    .stroke(egui::Stroke::new(1.0, ThemeTokens::BORDER_SUBTLE))
                    .inner_margin(egui::Margin::symmetric(18, 14));

                card.show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    egui::Grid::new("elf_grid")
                        .num_columns(2)
                        .spacing([24.0, 8.0])
                        .show(ui, |ui| {
                            if let Some(elf) = &binary.elf {
                                row(ui, "Bitness / Class", &elf.class.to_string());
                                row(ui, "ISA / Architecture", &elf.machine.to_string());
                                row(ui, "Byte Ordering", &elf.endianness.to_string());
                                row(ui, "Binary Type", &elf.elf_type.to_string());
                                row(ui, "Operating System ABI", &elf.os_abi.to_string());
                                row(ui, "ABI Version", &elf.abi_version.to_string());
                                row(
                                    ui,
                                    "Processor Flags (e_flags)",
                                    &format!("{:#x}", elf.flags),
                                );

                                ui.strong("Entry Point (Virtual Address)");
                                ui.horizontal(|ui| {
                                    let ep_str = format!("{:#010x}", elf.entry_point);
                                    ui.monospace(&ep_str);
                                    if ui.small_button("📋 Copy").clicked() {
                                        ui.ctx().copy_text(ep_str);
                                        self.set_status("Entry point copied");
                                    }
                                });
                                ui.end_row();
                            } else if let Some(pe) = &binary.pe {
                                row(
                                    ui,
                                    "Bitness / Class",
                                    if pe.is_pe32_plus {
                                        "PE32+ (64-bit)"
                                    } else {
                                        "PE32 (32-bit)"
                                    },
                                );
                                row(ui, "ISA / Architecture", &pe.machine.to_string());
                                row(ui, "Byte Ordering", "Little-Endian");
                                row(ui, "Subsystem", &pe.subsystem.to_string());
                                row(
                                    ui,
                                    "Linker Version",
                                    &format!("{}.{}", pe.linker_version.0, pe.linker_version.1),
                                );
                                row(ui, "Image Base", &format!("{:#010x}", pe.image_base));
                                row(
                                    ui,
                                    "Characteristics",
                                    &format!("{:#06x}", pe.characteristics),
                                );
                                row(
                                    ui,
                                    "DLL Characteristics",
                                    &format!("{:#06x}", pe.dll_characteristics),
                                );

                                ui.strong("Entry Point (RVA)");
                                ui.horizontal(|ui| {
                                    let ep_str = format!("{:#010x}", pe.entry_point);
                                    ui.monospace(&ep_str);
                                    if ui.small_button("📋 Copy").clicked() {
                                        ui.ctx().copy_text(ep_str);
                                        self.set_status("Entry point copied");
                                    }
                                });
                                ui.end_row();
                            } else if let Some(macho) = &binary.macho {
                                row(
                                    ui,
                                    "Bitness / Class",
                                    if macho.is_64_bit {
                                        "Mach-O 64-bit"
                                    } else {
                                        "Mach-O 32-bit"
                                    },
                                );
                                row(ui, "ISA / Architecture", &macho.cpu_arch);
                                row(
                                    ui,
                                    "Byte Ordering",
                                    if macho.is_little_endian {
                                        "Little-Endian"
                                    } else {
                                        "Big-Endian"
                                    },
                                );
                                row(ui, "Mach-O File Type", &macho.file_type);
                                if let Some(os) = &macho.min_os {
                                    row(ui, "Target Platform / OS", os);
                                }
                                if let Some(u) = &macho.uuid {
                                    row(ui, "Build UUID", u);
                                }
                                if macho.is_fat_universal {
                                    row(
                                        ui,
                                        "Universal Slices",
                                        &macho.fat_architectures.join(", "),
                                    );
                                }
                                row(ui, "Load Commands", &macho.ncmds.to_string());
                                row(ui, "Header Flags", &format!("{:#010x}", macho.flags));

                                if let Some(ep) = macho.entry_point {
                                    ui.strong("Entry Point");
                                    ui.horizontal(|ui| {
                                        let ep_str = format!("{:#010x}", ep);
                                        ui.monospace(&ep_str);
                                        if ui.small_button("📋 Copy").clicked() {
                                            ui.ctx().copy_text(ep_str);
                                            self.set_status("Entry point copied");
                                        }
                                    });
                                    ui.end_row();
                                }
                            }
                        });
                });
            });

            ui.add_space(10.0);

            // Card 3: File Identity & Hashes
            egui::CollapsingHeader::new(
                egui::RichText::new("📁 File Identity & Hashes")
                    .heading()
                    .size(15.0),
            )
            .default_open(true)
            .show(ui, |ui| {
                let card = egui::Frame::new()
                    .fill(ThemeTokens::BG_SURFACE)
                    .corner_radius(egui::CornerRadius::same(8))
                    .stroke(egui::Stroke::new(1.0, ThemeTokens::BORDER_SUBTLE))
                    .inner_margin(egui::Margin::symmetric(18, 14));

                card.show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    egui::Grid::new("file_grid")
                        .num_columns(2)
                        .spacing([24.0, 8.0])
                        .show(ui, |ui| {
                            ui.strong("Target Path");
                            ui.horizontal(|ui| {
                                ui.label(path.display().to_string());
                                if ui.small_button("📋 Copy").clicked() {
                                    ui.ctx().copy_text(path.display().to_string());
                                    self.set_status("Path copied");
                                }
                            });
                            ui.end_row();

                            row(
                                ui,
                                "File Size",
                                &format!(
                                    "{} ({} bytes)",
                                    format_bytes(binary.file.size_bytes),
                                    format_number(binary.file.size_bytes)
                                ),
                            );

                            ui.strong("SHA-256 Digest");
                            ui.horizontal(|ui| {
                                ui.monospace(&binary.hashes.sha256);
                                if ui.small_button("📋 Copy").clicked() {
                                    ui.ctx().copy_text(binary.hashes.sha256.clone());
                                    self.set_status("SHA-256 copied to clipboard");
                                }
                            });
                            ui.end_row();
                        });
                });
            });

            ui.add_space(10.0);

            // Card 4: Header Tables & Navigation Hub
            egui::CollapsingHeader::new(
                egui::RichText::new("📑 Structural Tables & Navigation")
                    .heading()
                    .size(15.0),
            )
            .default_open(true)
            .show(ui, |ui| {
                let card = egui::Frame::new()
                    .fill(ThemeTokens::BG_SURFACE)
                    .corner_radius(egui::CornerRadius::same(8))
                    .stroke(egui::Stroke::new(1.0, ThemeTokens::BORDER_SUBTLE))
                    .inner_margin(egui::Margin::symmetric(18, 14));

                card.show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    egui::Grid::new("table_layout_grid")
                        .num_columns(3)
                        .spacing([24.0, 8.0])
                        .show(ui, |ui| {
                            ui.strong("Sections");
                            ui.label(format!("{} sections", binary.sections.len()));
                            if ui.button("Inspect Sections (Alt+4)").clicked() {
                                self.view = View::Sections;
                            }
                            ui.end_row();

                            ui.strong("Symbols");
                            ui.label(format!("{} symbols", binary.symbols.len()));
                            if ui.button("Inspect Symbols (Alt+3)").clicked() {
                                self.view = View::Symbols;
                            }
                            ui.end_row();

                            ui.strong("Program Segments");
                            ui.label(format!("{} segments", binary.segments.len()));
                            if ui.button("Inspect Segments (Alt+5)").clicked() {
                                self.view = View::Segments;
                            }
                            ui.end_row();

                            ui.strong("Dynamic Libraries");
                            ui.label(format!("{} required libraries", binary.dynamic.needed.len()));
                            if ui.button("Inspect Dependencies (Alt+6)").clicked() {
                                self.view = View::Dependencies;
                            }
                            ui.end_row();

                            ui.strong("ELF Notes");
                            ui.label(format!("{} note records", binary.notes.len()));
                            if ui.button("Inspect Notes (Alt+7)").clicked() {
                                self.view = View::Notes;
                            }
                            ui.end_row();

                            ui.strong("Relocations");
                            ui.label(format!("{} relocation records", binary.relocations.len()));
                            if ui.button("Inspect Relocations (Alt+8)").clicked() {
                                self.view = View::Relocations;
                            }
                            ui.end_row();

                            ui.strong("Strings & Secrets");
                            ui.label(format!("{} extracted strings", binary.strings.len()));
                            if ui.button("Inspect Strings (Alt+9)").clicked() {
                                self.view = View::Strings;
                            }
                            ui.end_row();
                        });
                });
            });
        });
    }

    fn render_mitigations(&mut self, ui: &mut egui::Ui, mit: &SecurityMitigations) {
        ui.horizontal(|ui| {
            ui.heading(
                egui::RichText::new("🛡️ Security Mitigations & Hardening (checksec)")
                    .size(20.0)
                    .strong()
                    .color(ThemeTokens::TEXT_PRIMARY),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if mit.rwx_segments > 0 {
                    badge(ui, "⚠️ W^X VIOLATION", ThemeTokens::DANGER);
                } else {
                    badge(ui, "AUDIT READY", ThemeTokens::INFO);
                }
            });
        });

        ui.label(
            egui::RichText::new(
                "Automated checksec inspection analyzing exploit protections, binary hardening, and memory execution safety.",
            )
            .color(ThemeTokens::TEXT_SECONDARY),
        );
        ui.add_space(10.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            let card = |ui: &mut egui::Ui,
                        title: &str,
                        status: &str,
                        color: egui::Color32,
                        desc: &str,
                        remediation: &str| {
                let frame = egui::Frame::new()
                    .fill(ThemeTokens::BG_SURFACE)
                    .corner_radius(egui::CornerRadius::same(8))
                    .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.45)))
                    .inner_margin(egui::Margin::symmetric(18, 14));

                frame.show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.strong(
                            egui::RichText::new(title)
                                .size(15.5)
                                .color(ThemeTokens::TEXT_PRIMARY),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            badge(ui, status, color);
                        });
                    });
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(desc)
                            .size(13.0)
                            .color(ThemeTokens::TEXT_SECONDARY),
                    );

                    ui.add_space(6.0);
                    let rem_box = egui::Frame::new()
                        .fill(ThemeTokens::BG_INPUT)
                        .corner_radius(egui::CornerRadius::same(4))
                        .inner_margin(egui::Margin::symmetric(8, 4));
                    rem_box.show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new("Remediation / Flag:")
                                    .size(11.0)
                                    .color(ThemeTokens::TEXT_MUTED),
                            );
                            ui.label(
                                egui::RichText::new(remediation)
                                    .monospace()
                                    .size(11.5)
                                    .color(ThemeTokens::INFO),
                            );
                        });
                    });
                });
                ui.add_space(8.0);
            };

            // 1. RELRO
            let (relro_status, relro_color, relro_desc, relro_rem) = match mit.relro {
                Relro::Full => ("Full RELRO", ThemeTokens::SUCCESS, "The Global Offset Table (GOT) is completely read-only and immediate symbol binding is enforced, eliminating GOT overwrite hijacking.", "Protected: -Wl,-z,relro,-z,now active"),
                Relro::Partial => ("Partial RELRO", ThemeTokens::WARNING, "Internal data sections are read-only after relocation, but the GOT remains writable for lazy symbol resolution.", "Upgrade to Full RELRO: gcc -Wl,-z,relro,-z,now"),
                Relro::None => ("No RELRO", ThemeTokens::DANGER, "No relocation read-only protection found. The Global Offset Table is fully writable, allowing function pointer tampering.", "Enable RELRO: gcc -Wl,-z,relro,-z,now"),
                Relro::Unknown => ("Unknown", ThemeTokens::TEXT_MUTED, "The file has no program headers, so relocation protection cannot be evaluated.", "Compile with standard program headers"),
            };
            card(ui, "RELRO (Relocation Read-Only)", relro_status, relro_color, relro_desc, relro_rem);

            // 2. Stack Canary
            let (canary_status, canary_color, canary_desc, canary_rem) = match mit.stack_canary {
                Hardening::Enabled => ("Enabled", ThemeTokens::SUCCESS, "Stack canary symbols (__stack_chk_fail) detected. Stack-based buffer overflows will trigger immediate process abort.", "Protected: -fstack-protector-strong active"),
                Hardening::Disabled => ("Disabled (Vulnerable)", ThemeTokens::DANGER, "The symbol table contains no stack canary references. Stack-based buffer overflows may overwrite return addresses.", "Enable Canaries: gcc -fstack-protector-strong"),
                Hardening::Unknown => ("Unknown", ThemeTokens::TEXT_MUTED, "No symbol table is present, so canary symbols cannot be verified in this stripped binary.", "Inspect unstripped binary or runtime hooks"),
            };
            card(ui, "Stack Canary Protection", canary_status, canary_color, canary_desc, canary_rem);

            // 3. NX / DEP
            let (nx_status, nx_color, nx_desc, nx_rem) = match mit.nx {
                Hardening::Enabled => ("Enabled", ThemeTokens::SUCCESS, "The stack segment is marked non-executable (PT_GNU_STACK without PF_X). Direct shellcode injection on the stack is blocked.", "Protected: -Wl,-z,noexecstack active"),
                Hardening::Disabled => ("Disabled (RWX Stack)", ThemeTokens::DANGER, "The stack segment allows execution (PF_X). An attacker can inject and execute native shellcode directly on the stack.", "Disable Executable Stack: gcc -Wl,-z,noexecstack"),
                Hardening::Unknown => ("Unknown", ThemeTokens::TEXT_MUTED, "No PT_GNU_STACK segment is present; stack permissions are subject to kernel default behavior.", "Specify stack permissions: gcc -Wl,-z,noexecstack"),
            };
            card(ui, "NX / DEP (Non-Executable Stack)", nx_status, nx_color, nx_desc, nx_rem);

            // 4. PIE
            let (pie_status, pie_color, pie_desc, pie_rem) = match mit.pie {
                PieStatus::Pie => ("PIE Enabled", ThemeTokens::SUCCESS, "Position-Independent Executable loaded at randomized base address via ASLR, obstructing ROP chain attacks.", "Protected: -fPIE -pie active"),
                PieStatus::Dso => ("Dynamic Shared Object (DSO)", ThemeTokens::INFO, "Shared library with relocatable code, natively suitable for ASLR address randomization.", "Shared library with relocatable base"),
                PieStatus::NoPie => ("No PIE (Fixed Base)", ThemeTokens::WARNING, "Executable has a fixed virtual base address. Static code addresses make return-oriented programming (ROP) easier.", "Enable PIE: gcc -fPIE -pie"),
                PieStatus::Unknown => ("Unknown", ThemeTokens::TEXT_MUTED, "The file type is neither an executable nor a shared object; PIE status is not applicable.", "N/A"),
            };
            card(ui, "PIE (Position Independent Executable)", pie_status, pie_color, pie_desc, pie_rem);

            // 5. Fortify Source
            let (fort_status, fort_color, fort_desc, fort_rem) = match mit.fortify {
                Hardening::Enabled => (
                    format!("{} Functions", mit.fortified_functions.len()),
                    ThemeTokens::SUCCESS,
                    "Fortified library calls detected, performing compile-time and run-time bounds checks on memory/string operations.",
                    "Protected: -D_FORTIFY_SOURCE=2 or =3 active",
                ),
                Hardening::Disabled => (
                    "None Detected".to_string(),
                    ThemeTokens::TEXT_MUTED,
                    "No fortified libc wrapper symbols (e.g. __printf_chk, __memcpy_chk) found in symbol table.",
                    "Enable Fortify: gcc -O2 -D_FORTIFY_SOURCE=3",
                ),
                Hardening::Unknown => (
                    "Unknown".to_string(),
                    ThemeTokens::TEXT_MUTED,
                    "No symbol table available to inspect fortified function calls.",
                    "Inspect unstripped binary for _chk symbols",
                ),
            };
            card(ui, "FORTIFY_SOURCE", &fort_status, fort_color, fort_desc, fort_rem);

            if !mit.fortified_functions.is_empty() {
                ui.collapsing(
                    egui::RichText::new(format!(
                        "View Fortified Functions ({})",
                        mit.fortified_functions.len()
                    ))
                    .color(ThemeTokens::ACCENT_HOVER),
                    |ui| {
                        let f_box = egui::Frame::new()
                            .fill(ThemeTokens::BG_INPUT)
                            .corner_radius(egui::CornerRadius::same(6))
                            .inner_margin(egui::Margin::symmetric(14, 10));
                        f_box.show(ui, |ui| {
                            for f in &mit.fortified_functions {
                                ui.monospace(format!("  • {f}"));
                            }
                        });
                    },
                );
                ui.add_space(8.0);
            }

            // 6. W^X Policy
            let (wx_status, wx_color, wx_desc, wx_rem) = if mit.rwx_segments == 0 {
                (
                    "Enforced (0 RWX)",
                    ThemeTokens::SUCCESS,
                    "No segments have both Write and Execute permissions. Memory is either writable or executable, but never both.",
                    "Protected: Write XOR Execute policy intact",
                )
            } else {
                (
                    "VIOLATION",
                    ThemeTokens::DANGER,
                    "CRITICAL: Memory segments have both Write and Execute permissions, allowing code injection and runtime modification.",
                    "Remove RWX segments: check linker script and avoid PF_W + PF_X on same segment",
                )
            };
            card(ui, "W^X Memory Policy", wx_status, wx_color, wx_desc, wx_rem);

            // 7. Insecure RPATH
            let (rpath_status, rpath_color, rpath_desc, rpath_rem) = if mit.has_insecure_rpath {
                (
                    "Insecure Paths Detected",
                    ThemeTokens::WARNING,
                    "RPATH/RUNPATH contains relative (e.g. '.', '..') or world-writable paths (/tmp, /dev/shm), permitting local library injection.",
                    "Use relative origin paths: -Wl,-rpath,'$ORIGIN/../lib' or remove relative RPATH entries",
                )
            } else {
                (
                    "Clean",
                    ThemeTokens::SUCCESS,
                    "No insecure relative or world-writable directories detected in dynamic library search paths.",
                    "Protected: Search paths are securely anchored",
                )
            };
            card(ui, "Runtime Search Paths (RPATH)", rpath_status, rpath_color, rpath_desc, rpath_rem);
        });
    }

    fn render_symbols(&mut self, ui: &mut egui::Ui, binary: &Binary) {
        ui.horizontal(|ui| {
            ui.heading(
                egui::RichText::new(format!("🏷️ Symbols ({})", binary.symbols.len()))
                    .size(20.0)
                    .strong()
                    .color(ThemeTokens::TEXT_PRIMARY),
            );

            ui.add_space(14.0);
            ui.label("🔍");
            let search_edit = egui::TextEdit::singleline(&mut self.search_query)
                .hint_text("Search symbol names (Ctrl+F)…")
                .desired_width(220.0);

            let resp = ui.add(search_edit);
            if self.focus_search {
                resp.request_focus();
                self.focus_search = false;
            }

            if !self.search_query.is_empty() && ui.small_button("✕").clicked() {
                self.search_query.clear();
            }

            ui.separator();

            // Type filter pills
            let filter_btn = |ui: &mut egui::Ui,
                              current: &mut SymbolFilter,
                              target: SymbolFilter,
                              label: &str| {
                let is_sel = *current == target;
                if ui.selectable_label(is_sel, label).clicked() {
                    *current = target;
                }
            };
            filter_btn(ui, &mut self.symbol_filter, SymbolFilter::All, "All Types");
            filter_btn(
                ui,
                &mut self.symbol_filter,
                SymbolFilter::Functions,
                "Functions",
            );
            filter_btn(
                ui,
                &mut self.symbol_filter,
                SymbolFilter::Objects,
                "Objects",
            );
            filter_btn(
                ui,
                &mut self.symbol_filter,
                SymbolFilter::Imports,
                "Imports",
            );
            filter_btn(
                ui,
                &mut self.symbol_filter,
                SymbolFilter::Exports,
                "Exports",
            );

            ui.separator();

            // Table filter pills
            let table_btn =
                |ui: &mut egui::Ui, current: &mut TableFilter, target: TableFilter, label: &str| {
                    let is_sel = *current == target;
                    if ui.selectable_label(is_sel, label).clicked() {
                        *current = target;
                    }
                };
            table_btn(
                ui,
                &mut self.symbol_table_filter,
                TableFilter::All,
                "All Tables",
            );
            table_btn(
                ui,
                &mut self.symbol_table_filter,
                TableFilter::Dynamic,
                ".dynsym",
            );
            table_btn(
                ui,
                &mut self.symbol_table_filter,
                TableFilter::Static,
                ".symtab",
            );

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("↺ Reset Widths").clicked() {
                    self.symbol_col_widths = DEFAULT_SYMBOL_COL_WIDTHS;
                }
            });
        });

        ui.add_space(6.0);

        // Filter and sort symbols
        let q = self.search_query.to_lowercase();
        let mut visible: Vec<&Symbol> = binary
            .symbols
            .iter()
            .filter(|s| {
                if !q.is_empty() && !s.name.to_lowercase().contains(&q) {
                    return false;
                }
                match self.symbol_filter {
                    SymbolFilter::All => {}
                    SymbolFilter::Functions => {
                        if s.sym_type != SymbolType::Func {
                            return false;
                        }
                    }
                    SymbolFilter::Objects => {
                        if s.sym_type != SymbolType::Object {
                            return false;
                        }
                    }
                    SymbolFilter::Imports => {
                        if !s.is_import {
                            return false;
                        }
                    }
                    SymbolFilter::Exports => {
                        if !s.is_export {
                            return false;
                        }
                    }
                }
                match self.symbol_table_filter {
                    TableFilter::All => true,
                    TableFilter::Dynamic => s.table == SymbolTableKind::Dynamic,
                    TableFilter::Static => s.table == SymbolTableKind::Static,
                }
            })
            .collect();

        match self.symbol_sort {
            SymbolSort::Index => visible.sort_by_key(|s| s.index),
            SymbolSort::Name => visible.sort_by_key(|s| &s.name),
            SymbolSort::Type => visible.sort_by_key(|s| match &s.sym_type {
                SymbolType::NoType => 0,
                SymbolType::Object => 1,
                SymbolType::Func => 2,
                SymbolType::Section => 3,
                SymbolType::File => 4,
                SymbolType::Common => 5,
                SymbolType::Tls => 6,
                SymbolType::GnuIfunc => 7,
                SymbolType::Other(v) => 8 + *v as u16,
            }),
            SymbolSort::Binding => visible.sort_by_key(|s| match &s.binding {
                SymbolBinding::Local => 0,
                SymbolBinding::Global => 1,
                SymbolBinding::Weak => 2,
                SymbolBinding::GnuUnique => 3,
                SymbolBinding::Other(v) => 4 + *v as u16,
            }),
            SymbolSort::Address => visible.sort_by_key(|s| s.value),
            SymbolSort::Size => visible.sort_by_key(|s| s.size),
        }
        if !self.symbol_sort_asc {
            visible.reverse();
        }

        ui.small(
            egui::RichText::new(format!(
                "Showing {} matching symbols (of {} total)",
                visible.len(),
                binary.symbols.len()
            ))
            .color(ThemeTokens::TEXT_MUTED),
        );
        ui.add_space(4.0);

        let has_selection = self.selected_symbol.is_some();
        let table_avail_height = if has_selection {
            (ui.available_height() - self.symbol_detail_height - 12.0).max(100.0)
        } else {
            ui.available_height()
        };

        // Sticky Table Header
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;

            let sort_field = self.symbol_sort;
            let sort_asc = self.symbol_sort_asc;

            render_col_header(
                ui,
                &mut self.symbol_col_widths[0],
                DEFAULT_SYMBOL_COL_WIDTHS[0],
                35.0,
                "Idx",
                sort_arrow(sort_field == SymbolSort::Index, sort_asc),
                || {
                    toggle_sort(
                        &mut self.symbol_sort,
                        SymbolSort::Index,
                        &mut self.symbol_sort_asc,
                    )
                },
            );
            render_col_header(
                ui,
                &mut self.symbol_col_widths[1],
                DEFAULT_SYMBOL_COL_WIDTHS[1],
                100.0,
                "Name",
                sort_arrow(sort_field == SymbolSort::Name, sort_asc),
                || {
                    toggle_sort(
                        &mut self.symbol_sort,
                        SymbolSort::Name,
                        &mut self.symbol_sort_asc,
                    )
                },
            );
            render_col_header(
                ui,
                &mut self.symbol_col_widths[2],
                DEFAULT_SYMBOL_COL_WIDTHS[2],
                60.0,
                "Type",
                sort_arrow(sort_field == SymbolSort::Type, sort_asc),
                || {
                    toggle_sort(
                        &mut self.symbol_sort,
                        SymbolSort::Type,
                        &mut self.symbol_sort_asc,
                    )
                },
            );
            render_col_header(
                ui,
                &mut self.symbol_col_widths[3],
                DEFAULT_SYMBOL_COL_WIDTHS[3],
                60.0,
                "Binding",
                sort_arrow(sort_field == SymbolSort::Binding, sort_asc),
                || {
                    toggle_sort(
                        &mut self.symbol_sort,
                        SymbolSort::Binding,
                        &mut self.symbol_sort_asc,
                    )
                },
            );
            render_col_header(
                ui,
                &mut self.symbol_col_widths[4],
                DEFAULT_SYMBOL_COL_WIDTHS[4],
                60.0,
                "Visibility",
                None,
                || {},
            );
            render_col_header(
                ui,
                &mut self.symbol_col_widths[5],
                DEFAULT_SYMBOL_COL_WIDTHS[5],
                80.0,
                "Address",
                sort_arrow(sort_field == SymbolSort::Address, sort_asc),
                || {
                    toggle_sort(
                        &mut self.symbol_sort,
                        SymbolSort::Address,
                        &mut self.symbol_sort_asc,
                    )
                },
            );
            render_col_header(
                ui,
                &mut self.symbol_col_widths[6],
                DEFAULT_SYMBOL_COL_WIDTHS[6],
                50.0,
                "Size",
                sort_arrow(sort_field == SymbolSort::Size, sort_asc),
                || {
                    toggle_sort(
                        &mut self.symbol_sort,
                        SymbolSort::Size,
                        &mut self.symbol_sort_asc,
                    )
                },
            );
            render_col_header(
                ui,
                &mut self.symbol_col_widths[7],
                DEFAULT_SYMBOL_COL_WIDTHS[7],
                50.0,
                "Table",
                None,
                || {},
            );
        });

        ui.separator();

        let num_rows = visible.len();
        let row_height = 24.0;
        egui::ScrollArea::both()
            .max_height(table_avail_height)
            .show_rows(ui, row_height, num_rows, |ui, row_range| {
                for idx in row_range {
                    let sym = visible[idx];
                    let is_selected = self.selected_symbol == Some(sym.index);
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 6.0;

                        // Index
                        cell_label(
                            ui,
                            self.symbol_col_widths[0],
                            sym.index.to_string(),
                            true,
                            None,
                        );

                        // Name
                        let name_display = if sym.name.is_empty() {
                            "<unnamed>"
                        } else {
                            &sym.name
                        };
                        let name_col = if sym.is_import {
                            ThemeTokens::INFO
                        } else if sym.is_export {
                            ThemeTokens::SUCCESS
                        } else {
                            ThemeTokens::TEXT_PRIMARY
                        };

                        let btn = egui::Button::new(
                            egui::RichText::new(name_display).color(name_col).strong(),
                        )
                        .min_size(egui::vec2(self.symbol_col_widths[1], 20.0))
                        .selected(is_selected)
                        .truncate();
                        if ui.add(btn).clicked() {
                            if is_selected {
                                self.selected_symbol = None;
                            } else {
                                self.selected_symbol = Some(sym.index);
                            }
                        }

                        // Type
                        cell_label(
                            ui,
                            self.symbol_col_widths[2],
                            sym.sym_type.to_string(),
                            false,
                            None,
                        );

                        // Binding
                        cell_label(
                            ui,
                            self.symbol_col_widths[3],
                            sym.binding.to_string(),
                            false,
                            None,
                        );

                        // Visibility
                        cell_label(
                            ui,
                            self.symbol_col_widths[4],
                            sym.visibility.to_string(),
                            false,
                            None,
                        );

                        // Address
                        let addr_str = if sym.value == 0 {
                            "-".to_string()
                        } else {
                            format!("{:#010x}", sym.value)
                        };
                        cell_label(
                            ui,
                            self.symbol_col_widths[5],
                            &addr_str,
                            true,
                            Some(&addr_str),
                        );

                        // Size
                        let sz_str = if sym.size == 0 {
                            "-".to_string()
                        } else {
                            format!("{} B", sym.size)
                        };
                        cell_label(ui, self.symbol_col_widths[6], sz_str, true, None);

                        // Table
                        cell_label(
                            ui,
                            self.symbol_col_widths[7],
                            sym.table.to_string(),
                            true,
                            None,
                        );
                    });
                }
            });

        // Bottom Detail Panel
        if let Some(idx) = self.selected_symbol
            && let Some(sym) = binary.symbols.get(idx)
        {
            ui.separator();

            let (splitter_rect, splitter_resp) = ui.allocate_exact_size(
                egui::vec2(ui.available_width(), 6.0),
                egui::Sense::click_and_drag(),
            );
            if splitter_resp.hovered() || splitter_resp.dragged() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeVertical);
            }
            if splitter_resp.dragged() {
                self.symbol_detail_height =
                    (self.symbol_detail_height - splitter_resp.drag_delta().y).clamp(90.0, 360.0);
            }

            let fill = if splitter_resp.dragged() {
                ThemeTokens::BORDER_ACTIVE
            } else {
                ThemeTokens::BORDER_SUBTLE
            };
            ui.painter()
                .rect_filled(splitter_rect, egui::CornerRadius::same(2), fill);

            let detail_frame = egui::Frame::new()
                .fill(ThemeTokens::BG_SURFACE)
                .inner_margin(egui::Margin::symmetric(14, 10));

            detail_frame.show(ui, |ui| {
                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), self.symbol_detail_height),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.horizontal(|ui| {
                            ui.strong(
                                egui::RichText::new(format!("Symbol Details: {}", sym.name))
                                    .size(14.0)
                                    .color(ThemeTokens::TEXT_PRIMARY),
                            );
                            if ui.small_button("📋 Copy Name").clicked() {
                                ui.ctx().copy_text(sym.name.clone());
                                self.set_status("Symbol name copied");
                            }
                            if sym.value != 0 && ui.small_button("📋 Copy Address").clicked() {
                                ui.ctx().copy_text(format!("{:#010x}", sym.value));
                                self.set_status("Symbol address copied");
                            }

                            if let Some(sec_idx) = sym.section_index
                                && (sec_idx as usize) < binary.sections.len()
                            {
                                let sec_name = &binary.sections[sec_idx as usize].name;
                                if ui
                                    .button(
                                        egui::RichText::new(format!(
                                            "📑 Jump to Section #{sec_idx} ({sec_name})"
                                        ))
                                        .size(11.5)
                                        .color(ThemeTokens::ACCENT_HOVER),
                                    )
                                    .clicked()
                                {
                                    self.view = View::Sections;
                                    self.selected_section = Some(sec_idx);
                                }
                            }

                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui.small_button("✕ Close").clicked() {
                                        self.selected_symbol = None;
                                    }
                                },
                            );
                        });
                        ui.add_space(4.0);

                        egui::Grid::new("sym_detail_grid")
                            .num_columns(4)
                            .spacing([28.0, 6.0])
                            .show(ui, |ui| {
                                row(ui, "Value / Address", &format!("{:#010x}", sym.value));
                                row(ui, "Size", &format!("{} bytes", sym.size));
                                row(ui, "Type", &sym.sym_type.to_string());
                                row(ui, "Binding", &sym.binding.to_string());
                                row(ui, "Visibility", &sym.visibility.to_string());
                                row(ui, "Origin Table", &sym.table.to_string());
                                row(
                                    ui,
                                    "Role",
                                    if sym.is_import {
                                        "Imported symbol [UNDEF]"
                                    } else if sym.is_export {
                                        "Exported symbol [DEFINED]"
                                    } else {
                                        "Internal symbol"
                                    },
                                );
                                row(
                                    ui,
                                    "Section Index",
                                    &sym.section_index
                                        .map(|i| format!("#{i}"))
                                        .unwrap_or_else(|| "UNDEF (0)".to_string()),
                                );
                            });
                    },
                );
            });
        }
    }

    fn render_sections(&mut self, ui: &mut egui::Ui, binary: &Binary) {
        ui.horizontal(|ui| {
            ui.heading(
                egui::RichText::new(format!("📑 Sections ({})", binary.sections.len()))
                    .size(20.0)
                    .strong()
                    .color(ThemeTokens::TEXT_PRIMARY),
            );

            ui.add_space(14.0);
            ui.label("🔍");
            ui.add(
                egui::TextEdit::singleline(&mut self.search_query)
                    .hint_text("Filter by name or type…")
                    .desired_width(220.0),
            );

            if !self.search_query.is_empty() && ui.small_button("✕").clicked() {
                self.search_query.clear();
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("↺ Reset Widths").clicked() {
                    self.section_col_widths = DEFAULT_SECTION_COL_WIDTHS;
                }
            });
        });

        ui.add_space(6.0);

        let query = self.search_query.to_lowercase();
        let mut visible: Vec<&Section> = binary
            .sections
            .iter()
            .filter(|s| {
                if query.is_empty() {
                    true
                } else {
                    s.name.to_lowercase().contains(&query)
                        || section_type_name(s.section_type)
                            .to_lowercase()
                            .contains(&query)
                }
            })
            .collect();

        match self.section_sort {
            SectionSort::Index => visible.sort_by_key(|s| s.index),
            SectionSort::Name => visible.sort_by_key(|s| &s.name),
            SectionSort::Type => visible.sort_by_key(|s| s.section_type),
            SectionSort::Address => visible.sort_by_key(|s| s.address),
            SectionSort::Size => visible.sort_by_key(|s| s.size),
            SectionSort::Entropy => visible.sort_by(|a, b| {
                a.entropy
                    .unwrap_or(f64::NEG_INFINITY)
                    .total_cmp(&b.entropy.unwrap_or(f64::NEG_INFINITY))
            }),
        }
        if !self.section_sort_asc {
            visible.reverse();
        }

        ui.small(
            egui::RichText::new(format!(
                "Showing {} sections (Entropy indicates code density or packing)",
                visible.len()
            ))
            .color(ThemeTokens::TEXT_MUTED),
        );
        ui.add_space(4.0);

        let has_selection = self.selected_section.is_some();
        let table_avail_height = if has_selection {
            (ui.available_height() - self.section_detail_height - 12.0).max(100.0)
        } else {
            ui.available_height()
        };

        egui::ScrollArea::both()
            .max_height(table_avail_height)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;

                    let sort_field = self.section_sort;
                    let sort_asc = self.section_sort_asc;

                    render_col_header(
                        ui,
                        &mut self.section_col_widths[0],
                        DEFAULT_SECTION_COL_WIDTHS[0],
                        35.0,
                        "Idx",
                        sort_arrow(sort_field == SectionSort::Index, sort_asc),
                        || {
                            toggle_sort(
                                &mut self.section_sort,
                                SectionSort::Index,
                                &mut self.section_sort_asc,
                            )
                        },
                    );
                    render_col_header(
                        ui,
                        &mut self.section_col_widths[1],
                        DEFAULT_SECTION_COL_WIDTHS[1],
                        90.0,
                        "Name",
                        sort_arrow(sort_field == SectionSort::Name, sort_asc),
                        || {
                            toggle_sort(
                                &mut self.section_sort,
                                SectionSort::Name,
                                &mut self.section_sort_asc,
                            )
                        },
                    );
                    render_col_header(
                        ui,
                        &mut self.section_col_widths[2],
                        DEFAULT_SECTION_COL_WIDTHS[2],
                        70.0,
                        "Type",
                        sort_arrow(sort_field == SectionSort::Type, sort_asc),
                        || {
                            toggle_sort(
                                &mut self.section_sort,
                                SectionSort::Type,
                                &mut self.section_sort_asc,
                            )
                        },
                    );
                    render_col_header(
                        ui,
                        &mut self.section_col_widths[3],
                        DEFAULT_SECTION_COL_WIDTHS[3],
                        50.0,
                        "Flags",
                        None,
                        || {},
                    );
                    render_col_header(
                        ui,
                        &mut self.section_col_widths[4],
                        DEFAULT_SECTION_COL_WIDTHS[4],
                        80.0,
                        "Address",
                        sort_arrow(sort_field == SectionSort::Address, sort_asc),
                        || {
                            toggle_sort(
                                &mut self.section_sort,
                                SectionSort::Address,
                                &mut self.section_sort_asc,
                            )
                        },
                    );
                    render_col_header(
                        ui,
                        &mut self.section_col_widths[5],
                        DEFAULT_SECTION_COL_WIDTHS[5],
                        60.0,
                        "Size",
                        sort_arrow(sort_field == SectionSort::Size, sort_asc),
                        || {
                            toggle_sort(
                                &mut self.section_sort,
                                SectionSort::Size,
                                &mut self.section_sort_asc,
                            )
                        },
                    );
                    render_col_header(
                        ui,
                        &mut self.section_col_widths[6],
                        DEFAULT_SECTION_COL_WIDTHS[6],
                        60.0,
                        "Offset",
                        None,
                        || {},
                    );
                    render_col_header(
                        ui,
                        &mut self.section_col_widths[7],
                        DEFAULT_SECTION_COL_WIDTHS[7],
                        65.0,
                        "Entropy",
                        sort_arrow(sort_field == SectionSort::Entropy, sort_asc),
                        || {
                            toggle_sort(
                                &mut self.section_sort,
                                SectionSort::Entropy,
                                &mut self.section_sort_asc,
                            )
                        },
                    );
                });

                ui.separator();

                for section in visible {
                    let is_selected = self.selected_section == Some(section.index);
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 6.0;

                        cell_label(
                            ui,
                            self.section_col_widths[0],
                            section.index.to_string(),
                            true,
                            None,
                        );

                        let name_btn = egui::Button::new(
                            egui::RichText::new(&section.name)
                                .strong()
                                .color(ThemeTokens::TEXT_PRIMARY),
                        )
                        .min_size(egui::vec2(self.section_col_widths[1], 20.0))
                        .selected(is_selected)
                        .truncate();
                        if ui.add(name_btn).clicked() {
                            if is_selected {
                                self.selected_section = None;
                            } else {
                                self.selected_section = Some(section.index);
                            }
                        }

                        let type_str = format!(
                            "{:#x} ({})",
                            section.section_type,
                            section_type_name(section.section_type)
                        );
                        cell_label(
                            ui,
                            self.section_col_widths[2],
                            &type_str,
                            true,
                            Some(&type_str),
                        );

                        let flags_str = section_flags_str(section.flags);
                        let is_rwx = (section.flags & 1 != 0) && (section.flags & 4 != 0);
                        let flag_col = if is_rwx {
                            ThemeTokens::DANGER
                        } else {
                            ThemeTokens::TEXT_SECONDARY
                        };

                        cell_label(
                            ui,
                            self.section_col_widths[3],
                            egui::RichText::new(&flags_str).color(flag_col).strong(),
                            false,
                            if is_rwx {
                                Some("⚠️ W+X: Section is both Writable and Executable!")
                            } else {
                                None
                            },
                        );

                        let addr_str = format!("{:#010x}", section.address);
                        cell_label(
                            ui,
                            self.section_col_widths[4],
                            &addr_str,
                            true,
                            Some(&addr_str),
                        );

                        let size_str = format_bytes(section.size);
                        cell_label(ui, self.section_col_widths[5], &size_str, true, None);

                        let offset_str = format!("{:#x}", section.offset);
                        cell_label(
                            ui,
                            self.section_col_widths[6],
                            &offset_str,
                            true,
                            Some(&offset_str),
                        );

                        entropy_badge(ui, section.entropy);
                    });
                }
            });

        // Bottom Detail Panel
        if let Some(idx) = self.selected_section
            && let Some(section) = binary.sections.iter().find(|s| s.index == idx)
        {
            ui.separator();

            let (splitter_rect, splitter_resp) = ui.allocate_exact_size(
                egui::vec2(ui.available_width(), 6.0),
                egui::Sense::click_and_drag(),
            );
            if splitter_resp.hovered() || splitter_resp.dragged() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeVertical);
            }
            if splitter_resp.dragged() {
                self.section_detail_height =
                    (self.section_detail_height - splitter_resp.drag_delta().y).clamp(90.0, 360.0);
            }

            let fill = if splitter_resp.dragged() {
                ThemeTokens::BORDER_ACTIVE
            } else {
                ThemeTokens::BORDER_SUBTLE
            };
            ui.painter()
                .rect_filled(splitter_rect, egui::CornerRadius::same(2), fill);

            let detail_frame = egui::Frame::new()
                .fill(ThemeTokens::BG_SURFACE)
                .inner_margin(egui::Margin::symmetric(14, 10));

            detail_frame.show(ui, |ui| {
                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), self.section_detail_height),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.horizontal(|ui| {
                            ui.strong(
                                egui::RichText::new(format!(
                                    "Section #{}: {}",
                                    section.index, section.name
                                ))
                                .size(14.0)
                                .color(ThemeTokens::TEXT_PRIMARY),
                            );

                            if ui.small_button("📋 Copy Name").clicked() {
                                ui.ctx().copy_text(section.name.clone());
                                self.set_status("Section name copied");
                            }
                            if section.address != 0 && ui.small_button("📋 Copy Address").clicked()
                            {
                                ui.ctx().copy_text(format!("{:#010x}", section.address));
                                self.set_status("Section address copied");
                            }

                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui.small_button("✕ Close").clicked() {
                                        self.selected_section = None;
                                    }
                                },
                            );
                        });
                        ui.add_space(4.0);

                        egui::Grid::new("sec_detail_grid")
                            .num_columns(4)
                            .spacing([28.0, 6.0])
                            .show(ui, |ui| {
                                row(ui, "Virtual Address", &format!("{:#010x}", section.address));
                                row(ui, "File Offset", &format!("{:#x}", section.offset));
                                row(
                                    ui,
                                    "Size",
                                    &format!(
                                        "{} bytes ({})",
                                        section.size,
                                        format_bytes(section.size)
                                    ),
                                );
                                row(
                                    ui,
                                    "Shannon Entropy",
                                    &section.entropy.map_or_else(
                                        || "n/a (empty or out-of-bounds)".to_string(),
                                        |entropy| format!("{entropy:.3} bits/byte"),
                                    ),
                                );
                                row(
                                    ui,
                                    "Address Alignment",
                                    &format!("{:#x}", section.alignment),
                                );
                                row(
                                    ui,
                                    "Entry Size (sh_entsize)",
                                    &format!("{:#x}", section.entry_size),
                                );
                                row(ui, "Flags Decoded", &section_flags_str(section.flags));
                                row(
                                    ui,
                                    "Linked Section (sh_link)",
                                    &format!("#{}", section.link),
                                );
                            });
                    },
                );
            });
        }
    }

    fn render_segments(&mut self, ui: &mut egui::Ui, binary: &Binary) {
        ui.horizontal(|ui| {
            ui.heading(
                egui::RichText::new(format!("📦 Segments ({})", binary.segments.len()))
                    .size(20.0)
                    .strong()
                    .color(ThemeTokens::TEXT_PRIMARY),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("↺ Reset Widths").clicked() {
                    self.segment_col_widths = DEFAULT_SEGMENT_COL_WIDTHS;
                }
            });
        });

        ui.add_space(6.0);

        let mut visible: Vec<&Segment> = binary.segments.iter().collect();
        match self.segment_sort {
            SegmentSort::Index => visible.sort_by_key(|s| s.index),
            SegmentSort::Type => visible.sort_by_key(|s| s.segment_type),
            SegmentSort::Offset => visible.sort_by_key(|s| s.offset),
            SegmentSort::Address => visible.sort_by_key(|s| s.virtual_address),
            SegmentSort::Size => visible.sort_by_key(|s| s.file_size),
            SegmentSort::Flags => visible.sort_by_key(|s| s.flags),
        }
        if !self.segment_sort_asc {
            visible.reverse();
        }

        let has_selection = self.selected_segment.is_some();
        let table_avail_height = if has_selection {
            (ui.available_height() - self.segment_detail_height - 12.0).max(100.0)
        } else {
            ui.available_height()
        };

        egui::ScrollArea::both()
            .max_height(table_avail_height)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;

                    let sort_field = self.segment_sort;
                    let sort_asc = self.segment_sort_asc;

                    render_col_header(
                        ui,
                        &mut self.segment_col_widths[0],
                        DEFAULT_SEGMENT_COL_WIDTHS[0],
                        35.0,
                        "Idx",
                        sort_arrow(sort_field == SegmentSort::Index, sort_asc),
                        || {
                            toggle_sort(
                                &mut self.segment_sort,
                                SegmentSort::Index,
                                &mut self.segment_sort_asc,
                            )
                        },
                    );
                    render_col_header(
                        ui,
                        &mut self.segment_col_widths[1],
                        DEFAULT_SEGMENT_COL_WIDTHS[1],
                        100.0,
                        "Type",
                        sort_arrow(sort_field == SegmentSort::Type, sort_asc),
                        || {
                            toggle_sort(
                                &mut self.segment_sort,
                                SegmentSort::Type,
                                &mut self.segment_sort_asc,
                            )
                        },
                    );
                    render_col_header(
                        ui,
                        &mut self.segment_col_widths[2],
                        DEFAULT_SEGMENT_COL_WIDTHS[2],
                        60.0,
                        "Flags",
                        sort_arrow(sort_field == SegmentSort::Flags, sort_asc),
                        || {
                            toggle_sort(
                                &mut self.segment_sort,
                                SegmentSort::Flags,
                                &mut self.segment_sort_asc,
                            )
                        },
                    );
                    render_col_header(
                        ui,
                        &mut self.segment_col_widths[3],
                        DEFAULT_SEGMENT_COL_WIDTHS[3],
                        75.0,
                        "Offset",
                        sort_arrow(sort_field == SegmentSort::Offset, sort_asc),
                        || {
                            toggle_sort(
                                &mut self.segment_sort,
                                SegmentSort::Offset,
                                &mut self.segment_sort_asc,
                            )
                        },
                    );
                    render_col_header(
                        ui,
                        &mut self.segment_col_widths[4],
                        DEFAULT_SEGMENT_COL_WIDTHS[4],
                        85.0,
                        "VirtAddr",
                        sort_arrow(sort_field == SegmentSort::Address, sort_asc),
                        || {
                            toggle_sort(
                                &mut self.segment_sort,
                                SegmentSort::Address,
                                &mut self.segment_sort_asc,
                            )
                        },
                    );
                    render_col_header(
                        ui,
                        &mut self.segment_col_widths[5],
                        DEFAULT_SEGMENT_COL_WIDTHS[5],
                        70.0,
                        "FileSize",
                        sort_arrow(sort_field == SegmentSort::Size, sort_asc),
                        || {
                            toggle_sort(
                                &mut self.segment_sort,
                                SegmentSort::Size,
                                &mut self.segment_sort_asc,
                            )
                        },
                    );
                    render_col_header(
                        ui,
                        &mut self.segment_col_widths[6],
                        DEFAULT_SEGMENT_COL_WIDTHS[6],
                        70.0,
                        "MemSize",
                        None,
                        || {},
                    );
                    render_col_header(
                        ui,
                        &mut self.segment_col_widths[7],
                        DEFAULT_SEGMENT_COL_WIDTHS[7],
                        60.0,
                        "Align",
                        None,
                        || {},
                    );
                });

                ui.separator();

                for segment in visible {
                    let is_selected = self.selected_segment == Some(segment.index);
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 6.0;

                        cell_label(
                            ui,
                            self.segment_col_widths[0],
                            segment.index.to_string(),
                            true,
                            None,
                        );

                        let type_str = format!(
                            "{:#x} ({})",
                            segment.segment_type,
                            segment_type_name(segment.segment_type)
                        );
                        let type_btn = egui::Button::new(
                            egui::RichText::new(&type_str)
                                .strong()
                                .color(ThemeTokens::TEXT_PRIMARY),
                        )
                        .min_size(egui::vec2(self.segment_col_widths[1], 20.0))
                        .selected(is_selected)
                        .truncate();
                        if ui.add(type_btn).clicked() {
                            if is_selected {
                                self.selected_segment = None;
                            } else {
                                self.selected_segment = Some(segment.index);
                            }
                        }

                        let flags_str = segment_flags_str(segment.flags);
                        let is_rwx = (segment.flags & 2 != 0) && (segment.flags & 1 != 0);
                        let flags_color = if is_rwx {
                            ThemeTokens::DANGER
                        } else {
                            ThemeTokens::TEXT_SECONDARY
                        };
                        cell_label(
                            ui,
                            self.segment_col_widths[2],
                            egui::RichText::new(flags_str).color(flags_color).strong(),
                            false,
                            if is_rwx {
                                Some("⚠️ W^X violation: Write and Execute permissions!")
                            } else {
                                None
                            },
                        );

                        let offset_str = format!("{:#x}", segment.offset);
                        cell_label(
                            ui,
                            self.segment_col_widths[3],
                            &offset_str,
                            true,
                            Some(&offset_str),
                        );

                        let addr_str = format!("{:#010x}", segment.virtual_address);
                        cell_label(
                            ui,
                            self.segment_col_widths[4],
                            &addr_str,
                            true,
                            Some(&addr_str),
                        );

                        let file_size_str = format_bytes(segment.file_size);
                        cell_label(ui, self.segment_col_widths[5], &file_size_str, true, None);

                        let mem_size_str = format_bytes(segment.memory_size);
                        cell_label(ui, self.segment_col_widths[6], &mem_size_str, true, None);

                        let align_str = format!("{:#x}", segment.alignment);
                        cell_label(
                            ui,
                            self.segment_col_widths[7],
                            &align_str,
                            true,
                            Some(&align_str),
                        );
                    });
                }
            });

        // Bottom Detail Panel
        if let Some(idx) = self.selected_segment
            && let Some(segment) = binary.segments.iter().find(|s| s.index == idx)
        {
            ui.separator();

            let (splitter_rect, splitter_resp) = ui.allocate_exact_size(
                egui::vec2(ui.available_width(), 6.0),
                egui::Sense::click_and_drag(),
            );
            if splitter_resp.hovered() || splitter_resp.dragged() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeVertical);
            }
            if splitter_resp.dragged() {
                self.segment_detail_height =
                    (self.segment_detail_height - splitter_resp.drag_delta().y).clamp(90.0, 360.0);
            }

            let fill = if splitter_resp.dragged() {
                ThemeTokens::BORDER_ACTIVE
            } else {
                ThemeTokens::BORDER_SUBTLE
            };
            ui.painter()
                .rect_filled(splitter_rect, egui::CornerRadius::same(2), fill);

            let detail_frame = egui::Frame::new()
                .fill(ThemeTokens::BG_SURFACE)
                .inner_margin(egui::Margin::symmetric(14, 10));

            detail_frame.show(ui, |ui| {
                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), self.segment_detail_height),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.horizontal(|ui| {
                            ui.strong(
                                egui::RichText::new(format!(
                                    "Segment #{}: {}",
                                    segment.index,
                                    segment_type_name(segment.segment_type)
                                ))
                                .size(14.0)
                                .color(ThemeTokens::TEXT_PRIMARY),
                            );

                            if segment.virtual_address != 0
                                && ui.small_button("📋 Copy Address").clicked()
                            {
                                ui.ctx()
                                    .copy_text(format!("{:#010x}", segment.virtual_address));
                                self.set_status("Segment address copied");
                            }

                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui.small_button("✕ Close").clicked() {
                                        self.selected_segment = None;
                                    }
                                },
                            );
                        });
                        ui.add_space(4.0);

                        egui::Grid::new("seg_detail_grid")
                            .num_columns(4)
                            .spacing([28.0, 6.0])
                            .show(ui, |ui| {
                                row(
                                    ui,
                                    "Virtual Address",
                                    &format!("{:#010x}", segment.virtual_address),
                                );
                                row(ui, "File Offset", &format!("{:#x}", segment.offset));
                                row(ui, "File Size", &format_bytes(segment.file_size));
                                row(ui, "Memory Size", &format_bytes(segment.memory_size));
                                row(ui, "Alignment", &format!("{:#x}", segment.alignment));
                                row(ui, "Flags", &segment_flags_str(segment.flags));
                            });
                    },
                );
            });
        }
    }

    fn render_dependencies(&mut self, ui: &mut egui::Ui, binary: &Binary) {
        ui.horizontal(|ui| {
            ui.heading(
                egui::RichText::new("🔗 Dynamic Loader & Dependencies")
                    .size(20.0)
                    .strong()
                    .color(ThemeTokens::TEXT_PRIMARY),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if !binary.dynamic.needed.is_empty()
                    && ui
                        .button(egui::RichText::new("📋 Copy All Dependencies").size(12.0))
                        .clicked()
                {
                    ui.ctx().copy_text(binary.dynamic.needed.join("\n"));
                    self.set_status("All dependency names copied");
                }
            });
        });

        ui.add_space(8.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            // Loader paths
            egui::CollapsingHeader::new(
                egui::RichText::new("🚀 Interpreter & Search Paths")
                    .heading()
                    .size(15.0),
            )
            .default_open(true)
            .show(ui, |ui| {
                let card = egui::Frame::new()
                    .fill(ThemeTokens::BG_SURFACE)
                    .corner_radius(egui::CornerRadius::same(8))
                    .stroke(egui::Stroke::new(1.0, ThemeTokens::BORDER_SUBTLE))
                    .inner_margin(egui::Margin::symmetric(18, 14));

                card.show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    egui::Grid::new("loader_grid")
                        .num_columns(2)
                        .spacing([24.0, 8.0])
                        .show(ui, |ui| {
                            ui.strong("ELF Interpreter (PT_INTERP)");
                            ui.horizontal(|ui| {
                                let interp = binary
                                    .dynamic
                                    .interpreter
                                    .as_deref()
                                    .unwrap_or("None (Statically Linked)");
                                ui.label(interp);
                                if binary.dynamic.interpreter.is_some()
                                    && ui.small_button("📋 Copy").clicked()
                                {
                                    ui.ctx().copy_text(interp.to_string());
                                    self.set_status("Interpreter path copied");
                                }
                            });
                            ui.end_row();

                            row(
                                ui,
                                "RPATH",
                                binary.dynamic.rpath.as_deref().unwrap_or("None"),
                            );
                            row(
                                ui,
                                "RUNPATH",
                                binary.dynamic.runpath.as_deref().unwrap_or("None"),
                            );
                            row(
                                ui,
                                "Binding Mode",
                                if binary.dynamic.bind_now {
                                    "Immediate Binding (BIND_NOW)"
                                } else {
                                    "Lazy Binding (DF_BIND_NOW not set)"
                                },
                            );
                        });
                });
            });

            ui.add_space(10.0);

            // Needed libraries
            egui::CollapsingHeader::new(
                egui::RichText::new(format!(
                    "📚 Required Dynamic Libraries ({})",
                    binary.dynamic.needed.len()
                ))
                .heading()
                .size(15.0),
            )
            .default_open(true)
            .show(ui, |ui| {
                let card = egui::Frame::new()
                    .fill(ThemeTokens::BG_SURFACE)
                    .corner_radius(egui::CornerRadius::same(8))
                    .stroke(egui::Stroke::new(1.0, ThemeTokens::BORDER_SUBTLE))
                    .inner_margin(egui::Margin::symmetric(18, 14));

                card.show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    if binary.dynamic.needed.is_empty() {
                        ui.label(
                            egui::RichText::new("No DT_NEEDED dependencies found (statically linked or self-contained).")
                                .color(ThemeTokens::TEXT_MUTED),
                        );
                    } else {
                        for lib in &binary.dynamic.needed {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new("•").color(ThemeTokens::ACCENT_PRIMARY));
                                ui.monospace(
                                    egui::RichText::new(lib)
                                        .strong()
                                        .color(ThemeTokens::TEXT_PRIMARY),
                                );
                                if ui.small_button("📋 Copy").clicked() {
                                    ui.ctx().copy_text(lib.clone());
                                    self.set_status(format!("Copied {lib}"));
                                }
                            });
                        }
                    }
                });
            });

            ui.add_space(10.0);

            // Dynamic tags table
            if !binary.dynamic.entries.is_empty() {
                egui::CollapsingHeader::new(
                    egui::RichText::new(format!(
                        "📋 Dynamic Table Entries ({})",
                        binary.dynamic.entries.len()
                    ))
                    .heading()
                    .size(15.0),
                )
                .default_open(false)
                .show(ui, |ui| {
                    let card = egui::Frame::new()
                        .fill(ThemeTokens::BG_SURFACE)
                        .corner_radius(egui::CornerRadius::same(8))
                        .stroke(egui::Stroke::new(1.0, ThemeTokens::BORDER_SUBTLE))
                        .inner_margin(egui::Margin::symmetric(18, 14));

                    card.show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        egui::Grid::new("dyn_entries_grid")
                            .num_columns(3)
                            .spacing([24.0, 6.0])
                            .striped(true)
                            .show(ui, |ui| {
                                ui.strong("Tag Name");
                                ui.strong("Value / Offset");
                                ui.strong("Decoded String / Info");
                                ui.end_row();

                                for entry in &binary.dynamic.entries {
                                    ui.monospace(
                                        egui::RichText::new(&entry.tag_name)
                                            .color(ThemeTokens::INFO),
                                    );
                                    ui.monospace(format!("{:#x}", entry.value));
                                    ui.label(entry.string_value.as_deref().unwrap_or("-"));
                                    ui.end_row();
                                }
                            });
                    });
                });
            }
        });
    }

    fn render_notes(&mut self, ui: &mut egui::Ui, notes: &[ElfNote]) {
        ui.heading(
            egui::RichText::new(format!("📝 ELF Notes & Build Attributes ({})", notes.len()))
                .size(20.0)
                .strong()
                .color(ThemeTokens::TEXT_PRIMARY),
        );
        ui.label(
            egui::RichText::new(
                "Embedded descriptors declaring build identifiers, ABI constraints, and processor capabilities.",
            )
            .color(ThemeTokens::TEXT_SECONDARY),
        );
        ui.add_space(10.0);

        if notes.is_empty() {
            ui.label(
                egui::RichText::new("No note segments or sections found in this binary.")
                    .color(ThemeTokens::TEXT_MUTED),
            );
            return;
        }

        egui::ScrollArea::vertical().show(ui, |ui| {
            for (idx, note) in notes.iter().enumerate() {
                let frame = egui::Frame::new()
                    .fill(ThemeTokens::BG_SURFACE)
                    .corner_radius(egui::CornerRadius::same(8))
                    .stroke(egui::Stroke::new(1.0, ThemeTokens::BORDER_SUBTLE))
                    .inner_margin(egui::Margin::symmetric(18, 14));

                frame.show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.strong(
                            egui::RichText::new(format!("Note #{}: [{}]", idx + 1, note.name))
                                .size(14.5)
                                .color(ThemeTokens::TEXT_PRIMARY),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            badge(
                                ui,
                                &format!("Type {:#x}", note.note_type),
                                ThemeTokens::ACCENT_HOVER,
                            );
                        });
                    });
                    ui.add_space(4.0);
                    ui.label(&note.description);

                    if let Some(bid) = &note.build_id {
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.strong("Build ID:");
                            ui.monospace(
                                egui::RichText::new(bid).color(ThemeTokens::INFO).strong(),
                            );
                            if ui.small_button("📋 Copy").clicked() {
                                ui.ctx().copy_text(bid.clone());
                                self.set_status("Build ID copied");
                            }
                        });
                    }

                    if !note.properties.is_empty() {
                        ui.add_space(6.0);
                        ui.strong("GNU Processor Properties:");
                        for prop in &note.properties {
                            ui.monospace(format!("  • {prop}"));
                        }
                    }
                });
                ui.add_space(8.0);
            }
        });
    }

    fn render_relocations(&mut self, ui: &mut egui::Ui, relocations: &[Relocation]) {
        ui.horizontal(|ui| {
            ui.heading(
                egui::RichText::new(format!("🎯 Relocations ({})", relocations.len()))
                    .size(20.0)
                    .strong()
                    .color(ThemeTokens::TEXT_PRIMARY),
            );

            ui.add_space(14.0);
            ui.label("🔍");
            ui.add(
                egui::TextEdit::singleline(&mut self.search_query)
                    .hint_text("Filter by symbol or section…")
                    .desired_width(220.0),
            );

            if !self.search_query.is_empty() && ui.small_button("✕").clicked() {
                self.search_query.clear();
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("↺ Reset Widths").clicked() {
                    self.reloc_col_widths = DEFAULT_RELOC_COL_WIDTHS;
                }
            });
        });

        ui.add_space(6.0);

        let query = self.search_query.to_lowercase();
        let visible: Vec<&Relocation> = relocations
            .iter()
            .filter(|r| {
                if query.is_empty() {
                    true
                } else {
                    r.section_name.to_lowercase().contains(&query)
                        || r.symbol_name
                            .as_deref()
                            .unwrap_or("")
                            .to_lowercase()
                            .contains(&query)
                }
            })
            .collect();

        ui.small(
            egui::RichText::new(format!("Showing {} relocations", visible.len()))
                .color(ThemeTokens::TEXT_MUTED),
        );
        ui.add_space(4.0);

        // Sticky Table Header
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;

            render_col_header(
                ui,
                &mut self.reloc_col_widths[0],
                DEFAULT_RELOC_COL_WIDTHS[0],
                80.0,
                "Offset",
                None,
                || {},
            );
            render_col_header(
                ui,
                &mut self.reloc_col_widths[1],
                DEFAULT_RELOC_COL_WIDTHS[1],
                50.0,
                "Type",
                None,
                || {},
            );
            render_col_header(
                ui,
                &mut self.reloc_col_widths[2],
                DEFAULT_RELOC_COL_WIDTHS[2],
                100.0,
                "Target Symbol",
                None,
                || {},
            );
            render_col_header(
                ui,
                &mut self.reloc_col_widths[3],
                DEFAULT_RELOC_COL_WIDTHS[3],
                70.0,
                "Section",
                None,
                || {},
            );
            render_col_header(
                ui,
                &mut self.reloc_col_widths[4],
                DEFAULT_RELOC_COL_WIDTHS[4],
                60.0,
                "Addend",
                None,
                || {},
            );
        });

        ui.separator();

        let num_rows = visible.len();
        let row_height = 24.0;
        egui::ScrollArea::both().show_rows(ui, row_height, num_rows, |ui, row_range| {
            for idx in row_range {
                let r = visible[idx];
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;

                    let off_str = format!("{:#010x}", r.offset);
                    cell_label(ui, self.reloc_col_widths[0], &off_str, true, Some(&off_str));

                    cell_label(
                        ui,
                        self.reloc_col_widths[1],
                        r.rel_type.to_string(),
                        true,
                        None,
                    );

                    let sym_name = r.symbol_name.as_deref().unwrap_or("<none>");
                    let sym_color = if r.symbol_name.is_some() {
                        ThemeTokens::INFO
                    } else {
                        ThemeTokens::TEXT_MUTED
                    };

                    cell_label(
                        ui,
                        self.reloc_col_widths[2],
                        egui::RichText::new(sym_name).color(sym_color).strong(),
                        true,
                        Some(sym_name),
                    );

                    cell_label(ui, self.reloc_col_widths[3], &r.section_name, true, None);

                    let add_str = r
                        .addend
                        .map(|a| format!("{a:#x}"))
                        .unwrap_or_else(|| "-".to_string());
                    cell_label(ui, self.reloc_col_widths[4], add_str, true, None);
                });
            }
        });
    }

    fn render_strings(&mut self, ui: &mut egui::Ui, binary: &Binary) {
        let total_strings = binary.strings.len();

        // 1. Top Header & Search Bar
        ui.horizontal(|ui| {
            ui.heading(
                egui::RichText::new(format!("🔤 Strings & Secrets ({total_strings})"))
                    .size(20.0)
                    .strong()
                    .color(ThemeTokens::TEXT_PRIMARY),
            );

            ui.add_space(14.0);
            ui.label("🔍");
            let search_edit = egui::TextEdit::singleline(&mut self.search_query)
                .hint_text("Search strings, URLs, paths (Ctrl+F)…")
                .desired_width(220.0);

            let resp = ui.add(search_edit);
            if self.focus_search {
                resp.request_focus();
                self.focus_search = false;
            }

            if !self.search_query.is_empty() && ui.small_button("✕").clicked() {
                self.search_query.clear();
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("↺ Reset Widths").clicked() {
                    self.string_col_widths = DEFAULT_STRING_COL_WIDTHS;
                }
            });
        });

        ui.add_space(6.0);

        // 2. Filter Pills Row
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;

            let url_cnt = binary
                .strings
                .iter()
                .filter(|s| s.category == StringCategory::Url)
                .count();
            let ip_cnt = binary
                .strings
                .iter()
                .filter(|s| s.category == StringCategory::Ip)
                .count();
            let path_cnt = binary
                .strings
                .iter()
                .filter(|s| s.category == StringCategory::FilePath)
                .count();
            let crypto_cnt = binary
                .strings
                .iter()
                .filter(|s| s.category == StringCategory::Crypto)
                .count();
            let email_cnt = binary
                .strings
                .iter()
                .filter(|s| s.category == StringCategory::Email)
                .count();
            let gen_cnt = binary
                .strings
                .iter()
                .filter(|s| s.category == StringCategory::General)
                .count();

            let filter_pill = |ui: &mut egui::Ui,
                               curr: &mut StringCategoryFilter,
                               target: StringCategoryFilter,
                               label: &str| {
                let is_sel = *curr == target;
                if ui.selectable_label(is_sel, label).clicked() {
                    *curr = target;
                }
            };

            filter_pill(
                ui,
                &mut self.string_category_filter,
                StringCategoryFilter::All,
                &format!("All ({total_strings})"),
            );
            filter_pill(
                ui,
                &mut self.string_category_filter,
                StringCategoryFilter::Url,
                &format!("🌐 URLs ({url_cnt})"),
            );
            filter_pill(
                ui,
                &mut self.string_category_filter,
                StringCategoryFilter::Ip,
                &format!("📍 IPs ({ip_cnt})"),
            );
            filter_pill(
                ui,
                &mut self.string_category_filter,
                StringCategoryFilter::FilePath,
                &format!("📁 Paths ({path_cnt})"),
            );
            filter_pill(
                ui,
                &mut self.string_category_filter,
                StringCategoryFilter::Crypto,
                &format!("🔑 Secrets ({crypto_cnt})"),
            );
            filter_pill(
                ui,
                &mut self.string_category_filter,
                StringCategoryFilter::Email,
                &format!("✉️ Emails ({email_cnt})"),
            );
            filter_pill(
                ui,
                &mut self.string_category_filter,
                StringCategoryFilter::General,
                &format!("📄 General ({gen_cnt})"),
            );

            ui.separator();

            let enc_pill = |ui: &mut egui::Ui,
                            curr: &mut StringEncodingFilter,
                            target: StringEncodingFilter,
                            label: &str| {
                let is_sel = *curr == target;
                if ui.selectable_label(is_sel, label).clicked() {
                    *curr = target;
                }
            };

            enc_pill(
                ui,
                &mut self.string_encoding_filter,
                StringEncodingFilter::All,
                "All Encodings",
            );
            enc_pill(
                ui,
                &mut self.string_encoding_filter,
                StringEncodingFilter::Ascii,
                "ASCII",
            );
            enc_pill(
                ui,
                &mut self.string_encoding_filter,
                StringEncodingFilter::Utf16Le,
                "UTF-16LE",
            );

            ui.separator();

            ui.label(
                egui::RichText::new("Min Len:")
                    .size(11.5)
                    .color(ThemeTokens::TEXT_SECONDARY),
            );
            ui.add(egui::DragValue::new(&mut self.string_min_len).range(1..=128));
        });

        ui.add_space(4.0);

        // 3. Filter and Sort
        let q = self.search_query.to_lowercase();
        let mut visible: Vec<(usize, &ExtractedString)> = binary
            .strings
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                if s.value.len() < self.string_min_len {
                    return false;
                }
                if !q.is_empty() {
                    let in_val = s.value.to_lowercase().contains(&q);
                    let in_sec = s
                        .section
                        .as_deref()
                        .map(|sec| sec.to_lowercase().contains(&q))
                        .unwrap_or(false);
                    let in_cat = s.category.as_str().contains(&q);
                    if !in_val && !in_sec && !in_cat {
                        return false;
                    }
                }
                match self.string_category_filter {
                    StringCategoryFilter::All => {}
                    StringCategoryFilter::Url => {
                        if s.category != StringCategory::Url {
                            return false;
                        }
                    }
                    StringCategoryFilter::Ip => {
                        if s.category != StringCategory::Ip {
                            return false;
                        }
                    }
                    StringCategoryFilter::FilePath => {
                        if s.category != StringCategory::FilePath {
                            return false;
                        }
                    }
                    StringCategoryFilter::Crypto => {
                        if s.category != StringCategory::Crypto {
                            return false;
                        }
                    }
                    StringCategoryFilter::Email => {
                        if s.category != StringCategory::Email {
                            return false;
                        }
                    }
                    StringCategoryFilter::General => {
                        if s.category != StringCategory::General {
                            return false;
                        }
                    }
                }
                match self.string_encoding_filter {
                    StringEncodingFilter::All => true,
                    StringEncodingFilter::Ascii => s.encoding == StringEncoding::Ascii,
                    StringEncodingFilter::Utf16Le => s.encoding == StringEncoding::Utf16Le,
                }
            })
            .collect();

        match self.string_sort {
            StringSort::Offset => visible.sort_by_key(|(_, s)| s.offset),
            StringSort::Category => visible.sort_by_key(|(_, s)| s.category.as_str()),
            StringSort::Encoding => visible.sort_by_key(|(_, s)| s.encoding.as_str()),
            StringSort::Section => visible.sort_by_key(|(_, s)| s.section.as_deref().unwrap_or("")),
            StringSort::Length => visible.sort_by_key(|(_, s)| s.length),
            StringSort::Value => visible.sort_by_key(|(_, s)| &s.value),
        }

        if !self.string_sort_asc {
            visible.reverse();
        }

        ui.small(
            egui::RichText::new(format!(
                "Showing {} matching strings (of {} total)",
                visible.len(),
                total_strings
            ))
            .color(ThemeTokens::TEXT_MUTED),
        );
        ui.add_space(4.0);

        let has_selection = self.selected_string.is_some();
        let table_avail_height = if has_selection {
            (ui.available_height() - self.string_detail_height - 12.0).max(100.0)
        } else {
            ui.available_height()
        };

        // 4. Sticky Table Header
        let sort_field = self.string_sort;
        let sort_asc = self.string_sort_asc;
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;

            render_col_header(
                ui,
                &mut self.string_col_widths[0],
                DEFAULT_STRING_COL_WIDTHS[0],
                70.0,
                "Offset",
                sort_arrow(sort_field == StringSort::Offset, sort_asc),
                || {
                    toggle_sort(
                        &mut self.string_sort,
                        StringSort::Offset,
                        &mut self.string_sort_asc,
                    )
                },
            );
            render_col_header(
                ui,
                &mut self.string_col_widths[1],
                DEFAULT_STRING_COL_WIDTHS[1],
                60.0,
                "Category",
                sort_arrow(sort_field == StringSort::Category, sort_asc),
                || {
                    toggle_sort(
                        &mut self.string_sort,
                        StringSort::Category,
                        &mut self.string_sort_asc,
                    )
                },
            );
            render_col_header(
                ui,
                &mut self.string_col_widths[2],
                DEFAULT_STRING_COL_WIDTHS[2],
                55.0,
                "Encoding",
                sort_arrow(sort_field == StringSort::Encoding, sort_asc),
                || {
                    toggle_sort(
                        &mut self.string_sort,
                        StringSort::Encoding,
                        &mut self.string_sort_asc,
                    )
                },
            );
            render_col_header(
                ui,
                &mut self.string_col_widths[3],
                DEFAULT_STRING_COL_WIDTHS[3],
                70.0,
                "Section",
                sort_arrow(sort_field == StringSort::Section, sort_asc),
                || {
                    toggle_sort(
                        &mut self.string_sort,
                        StringSort::Section,
                        &mut self.string_sort_asc,
                    )
                },
            );
            render_col_header(
                ui,
                &mut self.string_col_widths[4],
                DEFAULT_STRING_COL_WIDTHS[4],
                45.0,
                "Len",
                sort_arrow(sort_field == StringSort::Length, sort_asc),
                || {
                    toggle_sort(
                        &mut self.string_sort,
                        StringSort::Length,
                        &mut self.string_sort_asc,
                    )
                },
            );
            render_col_header(
                ui,
                &mut self.string_col_widths[5],
                DEFAULT_STRING_COL_WIDTHS[5],
                120.0,
                "String Content",
                sort_arrow(sort_field == StringSort::Value, sort_asc),
                || {
                    toggle_sort(
                        &mut self.string_sort,
                        StringSort::Value,
                        &mut self.string_sort_asc,
                    )
                },
            );
        });

        ui.separator();

        // 5. Virtualized Table Rows
        let num_rows = visible.len();
        let row_height = 24.0;
        egui::ScrollArea::both()
            .max_height(table_avail_height)
            .show_rows(ui, row_height, num_rows, |ui, row_range| {
                for idx in row_range {
                    let (orig_idx, s) = visible[idx];
                    let is_selected = self.selected_string == Some(orig_idx);

                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 6.0;

                        // Offset
                        let off_str = format!("{:#010x}", s.offset);
                        cell_label(
                            ui,
                            self.string_col_widths[0],
                            &off_str,
                            true,
                            Some(&off_str),
                        );

                        // Category
                        let (cat_text, cat_color) = match s.category {
                            StringCategory::Url => ("URL", ThemeTokens::INFO),
                            StringCategory::Ip => ("IP", ThemeTokens::INFO),
                            StringCategory::FilePath => ("PATH", ThemeTokens::WARNING),
                            StringCategory::Crypto => ("SECRET", ThemeTokens::DANGER),
                            StringCategory::Email => ("EMAIL", ThemeTokens::ACCENT_HOVER),
                            StringCategory::General => ("GENERAL", ThemeTokens::TEXT_MUTED),
                        };
                        cell_label(
                            ui,
                            self.string_col_widths[1],
                            egui::RichText::new(cat_text).color(cat_color).strong(),
                            true,
                            Some(cat_text),
                        );

                        // Encoding
                        let enc_str = s.encoding.to_string();
                        cell_label(ui, self.string_col_widths[2], &enc_str, true, None);

                        // Section
                        let sec_str = s.section.as_deref().unwrap_or("-");
                        cell_label(ui, self.string_col_widths[3], sec_str, true, Some(sec_str));

                        // Length
                        cell_label(
                            ui,
                            self.string_col_widths[4],
                            s.length.to_string(),
                            true,
                            None,
                        );

                        // Value (Clickable to select/inspect)
                        let val_color = match s.category {
                            StringCategory::Crypto => ThemeTokens::DANGER,
                            StringCategory::Url => ThemeTokens::INFO,
                            StringCategory::Ip => ThemeTokens::INFO,
                            StringCategory::FilePath => ThemeTokens::WARNING,
                            StringCategory::Email => ThemeTokens::ACCENT_HOVER,
                            StringCategory::General => ThemeTokens::TEXT_PRIMARY,
                        };

                        let val_btn = egui::Button::new(
                            egui::RichText::new(&s.value).color(val_color).monospace(),
                        )
                        .min_size(egui::vec2(self.string_col_widths[5], 20.0))
                        .selected(is_selected)
                        .truncate();

                        let resp = ui.add(val_btn);
                        if resp.clicked() {
                            if is_selected {
                                self.selected_string = None;
                            } else {
                                self.selected_string = Some(orig_idx);
                            }
                        }
                        resp.on_hover_text(&s.value);

                        // Row quick-copy button
                        if ui
                            .small_button("📋")
                            .on_hover_text("Copy string to clipboard")
                            .clicked()
                        {
                            ui.ctx().copy_text(s.value.clone());
                            self.set_status("String copied to clipboard");
                        }
                    });
                }
            });

        // 6. Bottom Detail Panel
        if let Some(idx) = self.selected_string
            && let Some(s) = binary.strings.get(idx)
        {
            ui.separator();

            let (splitter_rect, splitter_resp) = ui.allocate_exact_size(
                egui::vec2(ui.available_width(), 6.0),
                egui::Sense::click_and_drag(),
            );
            if splitter_resp.hovered() || splitter_resp.dragged() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeVertical);
            }
            if splitter_resp.dragged() {
                self.string_detail_height =
                    (self.string_detail_height - splitter_resp.drag_delta().y).clamp(90.0, 360.0);
            }

            let fill = if splitter_resp.dragged() {
                ThemeTokens::BORDER_ACTIVE
            } else {
                ThemeTokens::BORDER_SUBTLE
            };
            ui.painter()
                .rect_filled(splitter_rect, egui::CornerRadius::ZERO, fill);

            egui::Frame::new()
                .fill(ThemeTokens::BG_SURFACE)
                .stroke(egui::Stroke::new(1.0, ThemeTokens::BORDER_SUBTLE))
                .corner_radius(egui::CornerRadius::same(6))
                .inner_margin(egui::Margin::symmetric(12, 10))
                .show(ui, |ui| {
                    ui.set_height(self.string_detail_height);

                    ui.horizontal(|ui| {
                        let (cat_str, cat_color) = match s.category {
                            StringCategory::Url => ("🌐 URL", ThemeTokens::INFO),
                            StringCategory::Ip => ("📍 IP Address", ThemeTokens::INFO),
                            StringCategory::FilePath => ("📁 File Path", ThemeTokens::WARNING),
                            StringCategory::Crypto => {
                                ("🔑 Cryptographic Secret / Key", ThemeTokens::DANGER)
                            }
                            StringCategory::Email => {
                                ("✉️ Email Address", ThemeTokens::ACCENT_HOVER)
                            }
                            StringCategory::General => {
                                ("📄 String Record", ThemeTokens::TEXT_MUTED)
                            }
                        };
                        badge(ui, cat_str, cat_color);

                        ui.add_space(8.0);
                        ui.label(
                            egui::RichText::new(format!("Offset: {:#010x}", s.offset))
                                .monospace()
                                .color(ThemeTokens::TEXT_SECONDARY),
                        );
                        if let Some(sec) = &s.section {
                            ui.label(
                                egui::RichText::new(format!("Section: {sec}"))
                                    .monospace()
                                    .color(ThemeTokens::TEXT_SECONDARY),
                            );
                        }
                        ui.label(
                            egui::RichText::new(format!("Length: {} chars", s.length))
                                .color(ThemeTokens::TEXT_MUTED),
                        );
                        ui.label(
                            egui::RichText::new(format!("Encoding: {}", s.encoding))
                                .color(ThemeTokens::TEXT_MUTED),
                        );

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("✕ Close").clicked() {
                                self.selected_string = None;
                            }
                            if ui.button("📋 Copy Value").clicked() {
                                ui.ctx().copy_text(s.value.clone());
                                self.set_status("String copied to clipboard");
                            }
                            if ui.button("📋 Copy Offset").clicked() {
                                ui.ctx().copy_text(format!("{:#010x}", s.offset));
                                self.set_status("Offset copied to clipboard");
                            }
                        });
                    });

                    ui.add_space(6.0);
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        let mut text = s.value.clone();
                        ui.add(
                            egui::TextEdit::multiline(&mut text)
                                .font(egui::TextStyle::Monospace)
                                .desired_width(f32::INFINITY)
                                .lock_focus(false),
                        );
                    });
                });
        }
    }
}

fn scorecard_item(
    ui: &mut egui::Ui,
    title: &str,
    status: &str,
    color: egui::Color32,
    icon: &str,
    hint: &str,
) -> bool {
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(138.0, 58.0), egui::Sense::click());
    let is_hovered = resp.hovered();

    if is_hovered {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }

    let bg_color = if is_hovered {
        ThemeTokens::BG_SURFACE_HOVER
    } else {
        ThemeTokens::BG_SURFACE
    };

    let border_stroke = if is_hovered {
        egui::Stroke::new(1.2, color)
    } else {
        egui::Stroke::new(1.0, color.gamma_multiply(0.45))
    };

    ui.painter().rect(
        rect,
        egui::CornerRadius::same(6),
        bg_color,
        border_stroke,
        egui::StrokeKind::Inside,
    );

    let content_rect = rect.shrink2(egui::vec2(10.0, 8.0));
    let mut content_ui = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(content_rect)
            .layout(egui::Layout::top_down(egui::Align::LEFT)),
    );

    content_ui.horizontal(|ui| {
        ui.label(egui::RichText::new(icon).size(14.0));
        ui.strong(
            egui::RichText::new(title)
                .size(12.0)
                .color(ThemeTokens::TEXT_PRIMARY),
        );
    });
    content_ui.add_space(4.0);
    badge(&mut content_ui, status, color);

    resp.on_hover_text(format!("{hint}\nClick to inspect in Mitigations view"))
        .clicked()
}

fn badge(ui: &mut egui::Ui, text: &str, color: egui::Color32) {
    let frame = egui::Frame::new()
        .fill(color.gamma_multiply(0.14))
        .corner_radius(egui::CornerRadius::same(4))
        .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.5)))
        .inner_margin(egui::Margin::symmetric(7, 3));

    frame.show(ui, |ui| {
        ui.label(egui::RichText::new(text).color(color).strong().size(11.5));
    });
}

fn entropy_badge(ui: &mut egui::Ui, entropy: Option<f64>) {
    let (val_str, desc, col) = match entropy {
        Some(e) if e >= 7.2 => (format!("{e:.2}"), "Packed / Encrypted", ThemeTokens::DANGER),
        Some(e) if e >= 6.0 => (format!("{e:.2}"), "Code density", ThemeTokens::WARNING),
        Some(e) if e >= 2.0 => (format!("{e:.2}"), "Data density", ThemeTokens::INFO),
        Some(e) => (format!("{e:.2}"), "Sparse / Zeros", ThemeTokens::SUCCESS),
        None => ("n/a".to_string(), "Unscanned", ThemeTokens::TEXT_MUTED),
    };

    let frame = egui::Frame::new()
        .fill(col.gamma_multiply(0.12))
        .corner_radius(egui::CornerRadius::same(4))
        .stroke(egui::Stroke::new(1.0, col.gamma_multiply(0.4)))
        .inner_margin(egui::Margin::symmetric(5, 2));

    let resp = frame.show(ui, |ui| {
        ui.label(
            egui::RichText::new(val_str)
                .color(col)
                .monospace()
                .strong()
                .size(11.5),
        );
    });
    resp.response
        .on_hover_text(format!("Shannon Entropy: {desc} (0.00-8.00 bits/byte)"));
}

fn sort_arrow(is_active: bool, is_asc: bool) -> Option<&'static str> {
    if is_active {
        if is_asc { Some(" ▲") } else { Some(" ▼") }
    } else {
        None
    }
}

fn toggle_sort<T: PartialEq + Copy>(current: &mut T, target: T, is_asc: &mut bool) {
    if *current == target {
        *is_asc = !*is_asc;
    } else {
        *current = target;
        *is_asc = true;
    }
}

fn render_col_header(
    ui: &mut egui::Ui,
    col_width: &mut f32,
    default_width: f32,
    min_width: f32,
    label: &str,
    sort_arrow: Option<&str>,
    mut on_click: impl FnMut(),
) {
    let handle_w = 6.0;
    let label_w = (*col_width - handle_w).max(16.0);

    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;

        let btn_text = if let Some(arrow) = sort_arrow {
            format!("{label}{arrow}")
        } else {
            label.to_string()
        };

        let btn = egui::Button::new(egui::RichText::new(btn_text).strong())
            .min_size(egui::vec2(label_w, 22.0))
            .truncate();
        if ui.add(btn).clicked() {
            on_click();
        }

        let (handle_rect, handle_resp) =
            ui.allocate_exact_size(egui::vec2(handle_w, 22.0), egui::Sense::click_and_drag());
        if handle_resp.hovered() || handle_resp.dragged() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeColumn);
        }
        if handle_resp.dragged() {
            *col_width = (*col_width + handle_resp.drag_delta().x).clamp(min_width, 600.0);
        }
        if handle_resp.double_clicked() {
            *col_width = default_width;
        }

        let stroke_color = if handle_resp.dragged() {
            ThemeTokens::BORDER_ACTIVE
        } else if handle_resp.hovered() {
            ThemeTokens::ACCENT_HOVER
        } else {
            ThemeTokens::BORDER_SUBTLE
        };
        ui.painter().vline(
            handle_rect.center().x,
            handle_rect.y_range(),
            egui::Stroke::new(1.0, stroke_color),
        );
    });
}

fn cell_label(
    ui: &mut egui::Ui,
    width: f32,
    text: impl Into<egui::WidgetText>,
    is_monospace: bool,
    hover: Option<&str>,
) -> egui::Response {
    let mut widget_text = text.into();
    if is_monospace {
        widget_text = widget_text.monospace();
    }
    let label = egui::Label::new(widget_text).truncate();
    let resp = ui.add_sized(egui::vec2(width, 20.0), label);
    if let Some(h) = hover {
        resp.on_hover_text(h)
    } else {
        resp
    }
}

fn render_drop_overlay(ui: &mut egui::Ui) {
    ui.centered_and_justified(|ui| {
        let frame = egui::Frame::new()
            .fill(egui::Color32::from_black_alpha(210))
            .corner_radius(egui::CornerRadius::same(16))
            .stroke(egui::Stroke::new(2.5, ThemeTokens::ACCENT_PRIMARY))
            .inner_margin(egui::Margin::same(44));

        frame.show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.label(
                    egui::RichText::new("📥")
                        .size(56.0)
                        .color(ThemeTokens::ACCENT_HOVER),
                );
                ui.add_space(12.0);
                ui.heading(
                    egui::RichText::new("Drop ELF Binary to Inspect")
                        .size(24.0)
                        .strong()
                        .color(egui::Color32::WHITE),
                );
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new("Safe, local static inspection — binary is never executed")
                        .size(14.0)
                        .color(ThemeTokens::TEXT_SECONDARY),
                );
            });
        });
    });
}

fn row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.strong(label);
    ui.label(value);
    ui.end_row();
}

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;

    let b = bytes as f64;
    if b >= GIB {
        format!("{:.2} GiB", b / GIB)
    } else if b >= MIB {
        format!("{:.2} MiB", b / MIB)
    } else if b >= KIB {
        format!("{:.2} KiB", b / KIB)
    } else {
        format!("{bytes} B")
    }
}

fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    let chars: Vec<char> = s.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if i > 0 && (chars.len() - i).is_multiple_of(3) {
            result.push(',');
        }
        result.push(*c);
    }
    result
}

fn section_type_name(stype: u32) -> &'static str {
    match stype {
        0 => "NULL",
        1 => "PROGBITS",
        2 => "SYMTAB",
        3 => "STRTAB",
        4 => "RELA",
        5 => "HASH",
        6 => "DYNAMIC",
        7 => "NOTE",
        8 => "NOBITS",
        9 => "REL",
        11 => "DYNSYM",
        14 => "INIT_ARRAY",
        15 => "FINI_ARRAY",
        0x6ffffff6 => "GNU_HASH",
        0x6ffffffd => "VERDEF",
        0x6ffffffe => "VERNEED",
        0x6fffffff => "VERSYM",
        _ => "OTHER",
    }
}

fn section_flags_str(flags: u64) -> String {
    let mut s = String::new();
    if flags & 0x1 != 0 {
        s.push('W');
    }
    if flags & 0x2 != 0 {
        s.push('A');
    }
    if flags & 0x4 != 0 {
        s.push('X');
    }
    if flags & 0x10 != 0 {
        s.push('M');
    }
    if flags & 0x20 != 0 {
        s.push('S');
    }
    if flags & 0x400 != 0 {
        s.push('T');
    }
    if s.is_empty() { "-".to_string() } else { s }
}

fn segment_type_name(stype: u32) -> &'static str {
    match stype {
        0 => "NULL",
        1 => "LOAD",
        2 => "DYNAMIC",
        3 => "INTERP",
        4 => "NOTE",
        5 => "SHLIB",
        6 => "PHDR",
        7 => "TLS",
        0x6474e550 => "GNU_EH_FRAME",
        0x6474e551 => "GNU_STACK",
        0x6474e552 => "GNU_RELRO",
        0x6474e553 => "GNU_PROPERTY",
        _ => "OTHER",
    }
}

fn segment_flags_str(flags: u32) -> String {
    let r = if flags & 4 != 0 { "R" } else { "-" };
    let w = if flags & 2 != 0 { "W" } else { "-" };
    let x = if flags & 1 != 0 { "X" } else { "-" };
    format!("{r}{w}{x}")
}
