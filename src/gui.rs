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
    model::{Binary, Section, Segment},
    model::{
        Binary, ElfNote, PieStatus, Relocation, Relro, Section, SecurityMitigations, Segment,
        Symbol, SymbolType,
    },
};
use eframe::egui;

fn main() -> eframe::Result {
    eframe::run_native(
        "BinaryInspector",
        eframe::NativeOptions {
            renderer: eframe::Renderer::Glow,
            viewport: egui::ViewportBuilder::default()
                .with_title("BinaryInspector — Safe ELF Analysis")
                .with_inner_size([1100.0, 760.0])
                .with_inner_size([1180.0, 800.0])
                .with_min_inner_size([720.0, 480.0]),
            ..Default::default()
        },
        Box::new(|_cc| Ok(Box::<InspectorApp>::default())),
    )
}

#[derive(Clone, Copy, Default, PartialEq)]
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
}

#[derive(Clone, Copy, PartialEq, Default)]
enum SymbolFilter {
    #[default]
    All,
    Functions,
    Objects,
    Imports,
    Exports,
}

#[derive(Clone, Copy, PartialEq, Default)]
enum SymbolSort {
    #[default]
    Index,
    Name,
    Type,
    Binding,
    Address,
    Size,
}

#[derive(Clone, Copy, PartialEq, Default)]
enum SectionSort {
    #[default]
    Index,
    Name,
    Type,
    Address,
    Size,
    Entropy,
}

#[derive(Clone, Copy, PartialEq, Default)]
enum SegmentSort {
    #[default]
    Index,
    Type,
    Offset,
    Address,
    Size,
    Flags,
}

#[derive(Default)]
enum Inspection {
    #[default]
    Empty,
    Loading(Receiver<(PathBuf, Result<Binary, AppError>)>),
    Ready {
        path: PathBuf,
        binary: Binary,
        binary: Box<Binary>,
    },
    Failed {
        path: PathBuf,
        error: AppError,
    },
}

const DEFAULT_SIDEBAR_WIDTH: f32 = 200.0;
const DEFAULT_SECTION_COL_WIDTHS: [f32; 7] = [45.0, 170.0, 140.0, 85.0, 115.0, 95.0, 85.0];
const DEFAULT_SIDEBAR_WIDTH: f32 = 210.0;
const DEFAULT_SECTION_COL_WIDTHS: [f32; 8] = [45.0, 160.0, 120.0, 80.0, 105.0, 85.0, 75.0, 70.0];
const DEFAULT_SEGMENT_COL_WIDTHS: [f32; 8] = [45.0, 140.0, 80.0, 95.0, 115.0, 95.0, 95.0, 80.0];
const DEFAULT_SYMBOL_COL_WIDTHS: [f32; 8] = [50.0, 220.0, 85.0, 80.0, 75.0, 105.0, 75.0, 70.0];
const DEFAULT_RELOC_COL_WIDTHS: [f32; 5] = [105.0, 65.0, 220.0, 120.0, 75.0];

struct ViewState {
    view: View,
    search_query: String,
    section_sort: SectionSort,
    section_sort_asc: bool,
    segment_sort: SegmentSort,
    segment_sort_asc: bool,
    symbol_filter: SymbolFilter,
    symbol_sort: SymbolSort,
    symbol_sort_asc: bool,
    selected_symbol: Option<usize>,
    symbol_detail_height: f32,
    symbol_col_widths: [f32; 8],
    reloc_col_widths: [f32; 5],
    status_message: Option<(String, std::time::Instant)>,
    sidebar_width: f32,
    section_col_widths: [f32; 7],
    section_col_widths: [f32; 8],
    selected_section: Option<u16>,
    section_detail_height: f32,
    segment_col_widths: [f32; 8],
    selected_segment: Option<u16>,
    segment_detail_height: f32,
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
            symbol_sort: SymbolSort::Index,
            symbol_sort_asc: true,
            selected_symbol: None,
            symbol_detail_height: 175.0,
            symbol_col_widths: DEFAULT_SYMBOL_COL_WIDTHS,
            reloc_col_widths: DEFAULT_RELOC_COL_WIDTHS,
            status_message: None,
            sidebar_width: DEFAULT_SIDEBAR_WIDTH,
            section_col_widths: DEFAULT_SECTION_COL_WIDTHS,
            selected_section: None,
            section_detail_height: 175.0,
            segment_col_widths: DEFAULT_SEGMENT_COL_WIDTHS,
            selected_segment: None,
            segment_detail_height: 175.0,
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
        if matches!(&self.inspection, Inspection::Loading(_)) {
            return;
        }

        if !self.recent_files.contains(&path) {
            self.recent_files.insert(0, path.clone());
            if self.recent_files.len() > 6 {
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

    fn poll(&mut self, context: &egui::Context) {
        let result = match &self.inspection {
            Inspection::Loading(receiver) => receiver.try_recv().ok(),
            _ => None,
        };
        if let Some((path, result)) = result {
            self.inspection = match result {
                Ok(binary) => Inspection::Ready { path, binary },
                Err(error) => Inspection::Failed { path, error },
            };
        } else if matches!(&self.inspection, Inspection::Loading(_)) {
            context.request_repaint_after(Duration::from_millis(30));

        if let Some((path, inspect_result)) = result {
            match inspect_result {
                Ok(binary) => {
                    self.view_state
                        .set_status(format!("Loaded {}", path.display()));
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
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Select an ELF binary to inspect safely")
            .pick_file()
        {
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

        // 1. Keyboard shortcuts
        // Global shortcuts
        let (open_pressed, esc_pressed) = context.input(|input| {
            let open = input.modifiers.command && input.key_pressed(egui::Key::O);
            let esc = input.key_pressed(egui::Key::Escape);
            (open, esc)
        });

        if open_pressed {
            self.choose_file();
        }

        if esc_pressed {
            if !self.view_state.search_query.is_empty() {
            if self.view_state.selected_section.is_some() {
                self.view_state.selected_section = None;
            } else if self.view_state.selected_segment.is_some() {
                self.view_state.selected_segment = None;
            } else if self.view_state.selected_symbol.is_some() {
                self.view_state.selected_symbol = None;
            } else if !self.view_state.search_query.is_empty() {
                self.view_state.search_query.clear();
            } else if matches!(self.inspection, Inspection::Failed { .. }) {
                self.inspection = Inspection::Empty;
            }
        }

        // 2. Drag & Drop handling
        // Handle Drag and Drop
        let is_hovering = context.input(|input| !input.raw.hovered_files.is_empty());
        let dropped_file = context.input(|input| {
            input
                .raw
                .dropped_files
                .first()
                .map(|file| file.path().to_path_buf())
        });

        if let Some(path) = dropped_file {
            self.inspect(path);
        }

        self.poll(&context);
        self.render_main_ui(ui, is_hovering);
    }
}

        // 3. Top Header Bar
impl InspectorApp {
    fn render_main_ui(&mut self, ui: &mut egui::Ui, is_hovering: bool) {
        let mut choose_file = false;
        let mut unload_file = false;

        // Top Control Bar
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("🔍 BinaryInspector")
            ui.heading(
                egui::RichText::new("🔬 BinaryInspector")
                    .strong()
                    .size(17.0)
                    .color(egui::Color32::from_rgb(91, 91, 214)),
                    .color(egui::Color32::from_rgb(110, 110, 240)),
            );

            ui.separator();

            match &self.inspection {
                Inspection::Ready { path, .. } => {
                Inspection::Ready { path, binary } => {
                    let file_name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "Binary".to_string());

                    ui.label(egui::RichText::new(&file_name).strong().monospace());
                    ui.small(format_bytes(binary.file.size_bytes));
                    if ui
                        .small_button("✕")
                        .on_hover_text("Close binary (Esc)")
                        .clicked()
                    {
                        unload_file = true;
                    }
                }
                Inspection::Loading(_) => {
                    ui.spinner();
                    ui.label("Inspecting…");
                }
                _ => {}
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .button(egui::RichText::new("📂 Open Binary (Ctrl+O)").strong())
                    .clicked()
                {
                    choose_file = true;
                }
            });
        });

        if choose_file {
            self.choose_file();
        }
        if unload_file {
            self.inspection = Inspection::Empty;
            self.view_state.search_query.clear();
        }

        ui.separator();

        // 4. Central Area bounded to leave space for status bar
        // Central Area bounded
        if is_hovering {
            render_drop_overlay(ui);
            return;
        }

        let central_height = (ui.available_height() - 28.0).max(100.0);
        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width(), central_height),
            egui::Layout::top_down(egui::Align::LEFT),
            |ui| match &self.inspection {
                Inspection::Empty => {
                    let mut sample_to_load = None;
                    self.render_empty_state(ui, &mut sample_to_load, &mut choose_file);
                    if let Some(path) = sample_to_load {
                        self.inspect(path);
                    }
                    if choose_file {
                        self.choose_file();
                    }
                }
                Inspection::Loading(_) => {
                    ui.centered_and_justified(|ui| {
                        ui.vertical_centered(|ui| {
                            ui.spinner();
                            ui.add_space(10.0);
                            ui.label(
                                egui::RichText::new("Inspecting binary safely…")
                                    .size(16.0)
                                    .color(ui.visuals().weak_text_color()),
                            );
                            ui.small("Parsing ELF headers and dynamic tables");
                            ui.small("Parsing ELF headers, symbols, notes, and security metadata");
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

        // 5. Stable Bottom Status Bar
        // Bottom Status Bar
        ui.separator();
        ui.horizontal(|ui| {
            if let Some((msg, time)) = &self.view_state.status_message {
                if time.elapsed() < Duration::from_secs(3) {
                    ui.label(
                        egui::RichText::new(format!("✓ {msg}"))
                            .color(egui::Color32::from_rgb(70, 180, 100))
                            .strong(),
                    );
                    ui.separator();
                }
            }

            match &self.inspection {
                Inspection::Ready { binary, .. } => {
                    ui.label(format!("Class: {}", binary.elf.class));
                    ui.separator();
                    ui.label(format!("ISA: {}", binary.elf.machine));
                    ui.separator();
                    ui.label(format!("Sections: {}", binary.sections.len()));
                    ui.separator();
                    ui.label(format!("Segments: {}", binary.segments.len()));
                    ui.label(format!("Symbols: {}", binary.symbols.len()));
                    ui.separator();
                    ui.label(format!("RELRO: {}", binary.mitigations.relro));
                    ui.separator();
                    ui.label(format!(
                        "NX: {}",
                        if binary.mitigations.nx {
                            "Enabled"
                        } else {
                            "Disabled"
                        }
                    ));
                }
                _ => {
                    ui.label(egui::RichText::new("Ready").color(ui.visuals().weak_text_color()));
                }
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    egui::RichText::new("🛡️ Local analysis only — binary never executed")
                        .size(11.0)
                        .color(ui.visuals().weak_text_color()),
                );
            });
        });
    }
}

impl InspectorApp {
    fn render_empty_state(
        &self,
        ui: &mut egui::Ui,
        sample_to_load: &mut Option<PathBuf>,
        choose_file: &mut bool,
    ) {
        ui.vertical_centered(|ui| {
            ui.add_space(60.0);

            let hero_frame = egui::Frame::new()
                .fill(ui.visuals().faint_bg_color)
                .corner_radius(egui::CornerRadius::same(12))
                .stroke(egui::Stroke::new(
                    1.5,
                    egui::Color32::from_rgb(91, 91, 214).gamma_multiply(0.4),
                ))
                .inner_margin(egui::Margin::symmetric(36, 28));

            hero_frame.show(ui, |ui| {
                ui.set_max_width(520.0);

                ui.label(
                    egui::RichText::new("📁")
                        .size(44.0)
                        .color(egui::Color32::from_rgb(91, 91, 214)),
                );
                ui.add_space(10.0);
                ui.heading(egui::RichText::new("Inspect an ELF Binary").size(22.0));
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(
                        "Drag and drop any ELF executable, library, or core dump into this window.\nBinaryInspector analyzes local structure without execution.",
                        "Drag and drop any ELF executable, library, or core dump into this window.\nBinaryInspector analyzes local structure, symbols, and security mitigations.",
                    )
                    .color(ui.visuals().weak_text_color())
                    .size(13.5),
                );

                ui.add_space(20.0);
                if ui
                    .button(
                        egui::RichText::new("  Choose ELF Binary (Ctrl+O)  ")
                            .strong()
                            .size(15.0),
                    )
                    .clicked()
                {
                    *choose_file = true;
                }
            });

            // Quick Samples Section
            let samples_dir = Path::new("samples");
            if samples_dir.exists() {
                ui.add_space(32.0);
                ui.label(
                    egui::RichText::new("QUICK TEST SAMPLES")
                    egui::RichText::new("OR TRY A SAMPLE BINARY")
                        .strong()
                        .size(11.0)
                        .color(ui.visuals().weak_text_color()),
                );
                ui.add_space(8.0);

                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing = egui::vec2(8.0, 8.0);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 10.0;
                    let samples = [
                        ("Minimal Static", "samples/minimal-static"),
                        ("Dynamic C Binary", "samples/dynamic-c-binary"),
                        ("RPATH / RUNPATH", "samples/with-rpath-runpath"),
                        ("Custom Sections", "samples/custom-sections"),
                        ("BinaryInspector CLI", "samples/binary-inspector-cli"),
                        ("dynamic-c-binary", "samples/dynamic-c-binary"),
                        ("minimal-static", "samples/minimal-static"),
                        ("custom-sections", "samples/custom-sections"),
                        ("with-rpath-runpath", "samples/with-rpath-runpath"),
                    ];
                    for (label, path_str) in samples {
                        let path = PathBuf::from(path_str);
                        if path.exists() && ui.button(label).clicked() {
                        if path.exists()
                            && ui
                                .button(egui::RichText::new(format!("📄 {label}")).monospace())
                                .clicked()
                        {
                            *sample_to_load = Some(path);
                        }
                    }
                });
            }

            // Recent Files
            if !self.recent_files.is_empty() {
                ui.add_space(24.0);
                ui.label(
                    egui::RichText::new("RECENT FILES")
                    egui::RichText::new("RECENT BINARIES")
                        .strong()
                        .size(11.0)
                        .color(ui.visuals().weak_text_color()),
                );
                ui.add_space(6.0);
                for path in &self.recent_files {
                    let display_name = path
                    let name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| path.display().to_string());
                    if ui
                        .link(format!("📄 {display_name}"))
                        .on_hover_text(path.display().to_string())
                        .link(egui::RichText::new(format!("🕒 {name}")).monospace())
                        .clicked()
                    {
                        *sample_to_load = Some(path.clone());
                    }
                }
            }
        });
    }
}

fn render_failed_state(ui: &mut egui::Ui, path: &Path, error: &AppError, choose_file: &mut bool) {
    ui.centered_and_justified(|ui| {
        ui.vertical_centered(|ui| {
            ui.label(
                egui::RichText::new("⚠️")
                    .size(40.0)
                    .color(egui::Color32::from_rgb(220, 60, 60)),
                    .size(48.0)
                    .color(egui::Color32::from_rgb(230, 80, 80)),
            );
            ui.add_space(10.0);
            ui.heading(
                egui::RichText::new("Could not inspect target")
                    .color(egui::Color32::from_rgb(220, 60, 60)),
                egui::RichText::new("Failed to Inspect Binary")
                    .color(egui::Color32::from_rgb(230, 80, 80)),
            );
            ui.add_space(8.0);
            ui.monospace(path.display().to_string());
            ui.add_space(12.0);
            ui.add_space(6.0);
            ui.label(path.display().to_string());
            ui.add_space(16.0);

            let error_box = egui::Frame::new()
                .fill(ui.visuals().faint_bg_color)
                .corner_radius(egui::CornerRadius::same(8))
                .stroke(egui::Stroke::new(
                    1.0,
                    egui::Color32::from_rgb(220, 60, 60).gamma_multiply(0.5),
                ))
                .inner_margin(egui::Margin::symmetric(24, 16));

            error_box.show(ui, |ui| {
                ui.label(
                    egui::RichText::new(error.to_string())
                        .color(egui::Color32::from_rgb(230, 80, 80))
                        .monospace(),
                );
            });

            ui.add_space(20.0);
            if ui.button("Choose another binary").clicked() {
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
                    ui.add_space(6.0);

                    let nav_item = |ui: &mut egui::Ui,
                                    current_view: &mut View,
                                    target: View,
                                    icon: &str,
                                    label: &str,
                                    badge_count: Option<usize>| {
                        let is_active = *current_view == target;
                        let text = if let Some(count) = badge_count {
                            format!("{icon} {label} ({count})")
                        } else {
                            format!("{icon} {label}")
                        };

                        let response = ui.selectable_label(
                            is_active,
                            egui::RichText::new(text).size(14.0).strong(),
                            egui::RichText::new(text).size(13.5).strong(),
                        );
                        if response.clicked() {
                            *current_view = target;
                        }
                    };

                    nav_item(ui, &mut self.view, View::Overview, "📊", "Overview", None);
                    nav_item(
                        ui,
                        &mut self.view,
                        View::Mitigations,
                        "🛡️",
                        "Mitigations",
                        None,
                    );
                    nav_item(
                        ui,
                        &mut self.view,
                        View::Symbols,
                        "🏷️",
                        "Symbols",
                        Some(binary.symbols.len()),
                    );
                    nav_item(
                        ui,
                        &mut self.view,
                        View::Sections,
                        "📑",
                        "Sections",
                        Some(binary.sections.len()),
                    );
                    nav_item(
                        ui,
                        &mut self.view,
                        View::Segments,
                        "📦",
                        "Segments",
                        Some(binary.segments.len()),
                    );
                    nav_item(
                        ui,
                        &mut self.view,
                        View::Dependencies,
                        "🔗",
                        "Dependencies",
                        "Dynamic & Deps",
                        Some(binary.dynamic.needed.len()),
                    );
                    nav_item(
                        ui,
                        &mut self.view,
                        View::Notes,
                        "📝",
                        "Notes & Build",
                        Some(binary.notes.len()),
                    );
                    nav_item(
                        ui,
                        &mut self.view,
                        View::Relocations,
                        "🎯",
                        "Relocations",
                        Some(binary.relocations.len()),
                    );

                    ui.add_space(16.0);
                    ui.separator();
                    ui.add_space(8.0);

                    // Quick Target Details Card
                    ui.label(
                        egui::RichText::new("TARGET")
                            .strong()
                            .size(10.0)
                            .color(ui.visuals().weak_text_color()),
                    );
                    let file_name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "Binary".to_string());
                    ui.label(egui::RichText::new(file_name).strong());
                    ui.small(format_bytes(binary.file.size_bytes));
                    if ui.small_button("📋 Copy Path").clicked() {
                        ui.ctx().copy_text(path.display().to_string());
                        self.set_status("Path copied to clipboard");
                    }
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
                    (self.sidebar_width + splitter_resp.drag_delta().x).clamp(140.0, 450.0);
                    (self.sidebar_width + splitter_resp.drag_delta().x).clamp(150.0, 450.0);
            }
            if splitter_resp.double_clicked() {
                self.sidebar_width = DEFAULT_SIDEBAR_WIDTH;
            }
            let splitter_color = if splitter_resp.dragged() {
                egui::Color32::from_rgb(91, 91, 214)
            } else if splitter_resp.hovered() {
                egui::Color32::from_rgb(140, 140, 230)
            } else {
                ui.visuals().widgets.noninteractive.bg_stroke.color
            };
            ui.painter().vline(
                splitter_rect.center().x,
                splitter_rect.y_range(),
                egui::Stroke::new(1.5, splitter_color),
            );

            // 3. Main Content Area takes ALL remaining space!
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
            });
        });
    }

    fn render_overview(&mut self, ui: &mut egui::Ui, path: &Path, binary: &Binary) {
        ui.heading("Binary Overview");
        ui.add_space(8.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            // Card 1: File Identity
            // Card 1: File Identity & Hashes
            egui::CollapsingHeader::new(
                egui::RichText::new("📁 File Identity").heading().size(15.0),
                egui::RichText::new("📁 File Identity & Hashes")
                    .heading()
                    .size(15.0),
            )
            .default_open(true)
            .show(ui, |ui| {
                ui.group(|ui| {
                    ui.set_width(ui.available_width());
                    egui::Grid::new("file_grid")
                        .num_columns(2)
                        .spacing([20.0, 8.0])
                        .show(ui, |ui| {
                            row(ui, "Target Path", &path.display().to_string());
                            row(
                                ui,
                                "File Size",
                                &format!(
                                    "{} ({})",
                                    format_bytes(binary.file.size_bytes),
                                    format_number(binary.file.size_bytes) + " bytes"
                                ),
                            );
                            row(ui, "Format", "ELF (Executable and Linkable Format)");

                            ui.strong("SHA-256");
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

            // Card 2: ELF Architecture & ABI
            // Card 2: Security Audit Summary (checksec)
            egui::CollapsingHeader::new(
                egui::RichText::new("🛡️ Security Mitigations Summary")
                    .heading()
                    .size(15.0),
            )
            .default_open(true)
            .show(ui, |ui| {
                ui.group(|ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 12.0;

                        // RELRO badge
                        let (relro_txt, relro_col) = match binary.mitigations.relro {
                            Relro::Full => ("Full RELRO", egui::Color32::from_rgb(50, 180, 80)),
                            Relro::Partial => {
                                ("Partial RELRO", egui::Color32::from_rgb(220, 160, 40))
                            }
                            Relro::None => ("No RELRO", egui::Color32::from_rgb(220, 70, 70)),
                        };
                        badge(ui, relro_txt, relro_col);

                        // Canary badge
                        if binary.mitigations.stack_canary {
                            badge(ui, "Canary Found", egui::Color32::from_rgb(50, 180, 80));
                        } else {
                            badge(ui, "No Canary", egui::Color32::from_rgb(220, 70, 70));
                        }

                        // NX badge
                        if binary.mitigations.nx {
                            badge(ui, "NX Enabled", egui::Color32::from_rgb(50, 180, 80));
                        } else {
                            badge(
                                ui,
                                "NX Disabled (RWX)",
                                egui::Color32::from_rgb(220, 70, 70),
                            );
                        }

                        // PIE badge
                        let (pie_txt, pie_col) = match binary.mitigations.pie {
                            PieStatus::Pie => ("PIE Enabled", egui::Color32::from_rgb(50, 180, 80)),
                            PieStatus::Dso => {
                                ("DSO / Shared", egui::Color32::from_rgb(70, 140, 240))
                            }
                            PieStatus::NoPie => ("No PIE", egui::Color32::from_rgb(220, 160, 40)),
                        };
                        badge(ui, pie_txt, pie_col);

                        if binary.mitigations.rwx_segments > 0 {
                            badge(ui, "⚠️ W^X Violation", egui::Color32::from_rgb(220, 50, 50));
                        }
                    });

                    ui.add_space(6.0);
                    if ui
                        .button("🔍 View Detailed Mitigations Dashboard")
                        .clicked()
                    {
                        self.view = View::Mitigations;
                    }
                });
            });

            ui.add_space(10.0);

            // Card 3: ELF Architecture & ABI
            egui::CollapsingHeader::new(
                egui::RichText::new("⚙️ ELF Header & Architecture")
                    .heading()
                    .size(15.0),
            )
            .default_open(true)
            .show(ui, |ui| {
                ui.group(|ui| {
                    ui.set_width(ui.available_width());
                    egui::Grid::new("elf_grid")
                        .num_columns(2)
                        .spacing([20.0, 8.0])
                        .show(ui, |ui| {
                            row(ui, "Class", &binary.elf.class.to_string());
                            row(ui, "Endianness", &binary.elf.endianness.to_string());
                            row(ui, "Type", &binary.elf.elf_type.to_string());
                            row(ui, "Machine / ISA", &binary.elf.machine.to_string());
                            row(ui, "Operating System ABI", &binary.elf.os_abi.to_string());
                            row(ui, "ABI Version", &binary.elf.abi_version.to_string());
                            row(
                                ui,
                                "Processor Flags (e_flags)",
                                &format!("{:#x}", binary.elf.flags),
                            );
                        });
                });
            });

            ui.add_space(10.0);

            // Card 3: Execution & Security Metadata
            // Card 4: Header Table Structure & Offsets
            egui::CollapsingHeader::new(
                egui::RichText::new("🛡️ Execution & Security Properties")
                egui::RichText::new("📑 Header Tables & Layout")
                    .heading()
                    .size(15.0),
            )
            .default_open(true)
            .default_open(false)
            .show(ui, |ui| {
                ui.group(|ui| {
                    ui.set_width(ui.available_width());
                    egui::Grid::new("exec_grid")
                    egui::Grid::new("table_layout_grid")
                        .num_columns(2)
                        .spacing([20.0, 8.0])
                        .show(ui, |ui| {
                            ui.strong("Entry Point");
                            ui.horizontal(|ui| {
                                let entry_str = format!("{:#x}", binary.elf.entry_point);
                                ui.monospace(&entry_str);
                                if ui
                                    .small_button("📋")
                                    .on_hover_text("Copy address")
                                    .clicked()
                                {
                                    ui.ctx().copy_text(entry_str);
                                    self.set_status("Entry point copied");
                                }
                            });
                            ui.end_row();

                            let is_pie = matches!(
                                binary.elf.elf_type,
                                binary_inspector::model::ElfType::Shared
                            row(
                                ui,
                                "Program Header Offset",
                                &format!("{:#x}", binary.elf.program_offset),
                            );
                            row(
                                ui,
                                "Position Independent (PIE)",
                                if is_pie {
                                    "Yes (Shared object / PIE)"
                                } else {
                                    "No (Fixed load address)"
                                },
                                "Program Header Entry Size",
                                &format!("{} bytes", binary.elf.program_entry_size),
                            );

                            row(
                                ui,
                                "Immediate Binding (BIND_NOW)",
                                if binary.dynamic.bind_now {
                                    "Enabled (Full RELRO candidate)"
                                } else {
                                    "Lazy binding default"
                                },
                                "Program Header Count",
                                &binary.elf.program_count.to_string(),
                            );

                            row(ui, "Total Sections", &binary.sections.len().to_string());
                            row(ui, "Total Segments", &binary.segments.len().to_string());
                            row(
                                ui,
                                "Section Header Offset",
                                &format!("{:#x}", binary.elf.section_offset),
                            );
                            row(
                                ui,
                                "Section Header Entry Size",
                                &format!("{} bytes", binary.elf.section_entry_size),
                            );
                            row(
                                ui,
                                "Section Header Count",
                                &binary.elf.section_count.to_string(),
                            );
                        });
                });
            });

            ui.add_space(10.0);

            // Card 5: Build Info (Build ID / Kernel ABI)
            if !binary.notes.is_empty() {
                egui::CollapsingHeader::new(
                    egui::RichText::new("🏷️ Build Information")
                        .heading()
                        .size(15.0),
                )
                .default_open(true)
                .show(ui, |ui| {
                    ui.group(|ui| {
                        ui.set_width(ui.available_width());
                        egui::Grid::new("build_grid")
                            .num_columns(2)
                            .spacing([20.0, 8.0])
                            .show(ui, |ui| {
                                for note in &binary.notes {
                                    if let Some(bid) = &note.build_id {
                                        ui.strong("GNU Build ID");
                                        ui.horizontal(|ui| {
                                            ui.monospace(bid);
                                            if ui.small_button("📋 Copy").clicked() {
                                                ui.ctx().copy_text(bid.clone());
                                                self.set_status("Build ID copied");
                                            }
                                        });
                                        ui.end_row();
                                    }
                                    if let Some(abi) = &note.abi_tag {
                                        row(ui, "Target Kernel ABI", abi);
                                    }
                                }
                            });
                    });
                });
            }
        });
    }

    fn render_sections(&mut self, ui: &mut egui::Ui, binary: &Binary) {
    fn render_mitigations(&mut self, ui: &mut egui::Ui, mit: &SecurityMitigations) {
        ui.heading("🛡️ Security Hardening & Exploit Mitigations");
        ui.label("Automated security assessment inspecting binary protections (checksec).");
        ui.add_space(12.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            let card = |ui: &mut egui::Ui, title: &str, status: &str, color: egui::Color32, desc: &str| {
                let frame = egui::Frame::new()
                    .fill(ui.visuals().faint_bg_color)
                    .corner_radius(egui::CornerRadius::same(8))
                    .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.5)))
                    .inner_margin(egui::Margin::symmetric(16, 12));

                frame.show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.strong(egui::RichText::new(title).size(15.0));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            badge(ui, status, color);
                        });
                    });
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new(desc).size(12.5).color(ui.visuals().weak_text_color()));
                });
                ui.add_space(8.0);
            };

            // RELRO
            let (relro_status, relro_color, relro_desc) = match mit.relro {
                Relro::Full => ("Full RELRO", egui::Color32::from_rgb(50, 180, 80), "The Global Offset Table (GOT) is completely read-only and immediate binding is enforced, preventing GOT overwrite exploits."),
                Relro::Partial => ("Partial RELRO", egui::Color32::from_rgb(220, 160, 40), "ELF internal data sections are read-only after relocation, but GOT entries remain writable for lazy symbol binding."),
                Relro::None => ("No RELRO", egui::Color32::from_rgb(220, 70, 70), "No relocation read-only protection found. Internal tables and the GOT are fully writable."),
            };
            card(ui, "RELRO (Relocation Read-Only)", relro_status, relro_color, relro_desc);

            // Stack Canary
            if mit.stack_canary {
                card(ui, "Stack Canary Protection", "Enabled", egui::Color32::from_rgb(50, 180, 80), "Stack canary symbols (__stack_chk_fail) detected. Buffer overflows on the stack will trigger immediate termination.");
            } else {
                card(ui, "Stack Canary Protection", "Disabled (Vulnerable)", egui::Color32::from_rgb(220, 70, 70), "No stack canary protection symbols found. Stack-based buffer overflows may allow hijacking instruction flow.");
            }

            // NX
            if mit.nx {
                card(ui, "NX / DEP (Non-Executable Stack)", "Enabled", egui::Color32::from_rgb(50, 180, 80), "The stack segment is marked non-executable (PT_GNU_STACK without PF_X). Direct shellcode execution on the stack is blocked.");
            } else {
                card(ui, "NX / DEP (Executable Stack)", "Disabled (RWX)", egui::Color32::from_rgb(220, 70, 70), "The stack segment allows execution (PF_X). An attacker can inject and directly execute shellcode on the stack.");
            }

            // PIE
            let (pie_status, pie_color, pie_desc) = match mit.pie {
                PieStatus::Pie => ("PIE Enabled", egui::Color32::from_rgb(50, 180, 80), "Position-Independent Executable loaded at randomized base address via ASLR."),
                PieStatus::Dso => ("Dynamic Shared Object (DSO)", egui::Color32::from_rgb(70, 140, 240), "Shared library with relocatable code suitable for ASLR address randomization."),
                PieStatus::NoPie => ("No PIE (Fixed Base)", egui::Color32::from_rgb(220, 160, 40), "Fixed virtual base address executable. Code addresses are static, making ROP chain exploitation easier."),
            };
            card(ui, "PIE (Position Independent Executable)", pie_status, pie_color, pie_desc);

            // Fortify Source
            if !mit.fortified_functions.is_empty() {
                card(ui, "FORTIFY_SOURCE", &format!("{} Functions", mit.fortified_functions.len()), egui::Color32::from_rgb(50, 180, 80), "Fortified library calls detected, performing runtime bounds checking on sensitive string/memory operations.");
                ui.collapsing("View Fortified Function Symbols", |ui| {
                    for f in &mit.fortified_functions {
                        ui.monospace(format!("  • {f}"));
                    }
                });
                ui.add_space(8.0);
            } else {
                card(ui, "FORTIFY_SOURCE", "None Detected", egui::Color32::from_rgb(180, 180, 180), "No fortified libc wrapper symbols (e.g. __printf_chk) were found in the symbol table.");
            }

            // W^X RWX Segments
            if mit.rwx_segments == 0 {
                card(ui, "W^X Memory Policy", "Enforced (0 RWX)", egui::Color32::from_rgb(50, 180, 80), "No segments have both Write and Execute permissions. Memory is either writable or executable, but never both.");
            } else {
                card(ui, "W^X Memory Policy", &format!("VIOLATION ({} RWX Segments)", mit.rwx_segments), egui::Color32::from_rgb(220, 50, 50), "Warning: Program contains memory segments with both Write and Execute permissions, allowing code injection and runtime modification.");
            }

            // Insecure RPATH
            if mit.has_insecure_rpath {
                card(ui, "Runtime Search Paths (RPATH)", "Insecure Paths Detected", egui::Color32::from_rgb(220, 140, 40), "RPATH or RUNPATH contains relative directory lookups (e.g. '.'), which can allow local library hijacking.");
            } else {
                card(ui, "Runtime Search Paths (RPATH)", "Clean", egui::Color32::from_rgb(50, 180, 80), "No insecure relative or empty directories detected in dynamic library search paths.");
            }
        });
    }

    fn render_symbols(&mut self, ui: &mut egui::Ui, binary: &Binary) {
        ui.horizontal(|ui| {
            ui.heading(format!("Sections ({})", binary.sections.len()));
            ui.heading(format!("🏷️ Symbols ({})", binary.symbols.len()));

            if self.section_col_widths != DEFAULT_SECTION_COL_WIDTHS
                && ui
                    .small_button("↺ Reset Widths")
                    .on_hover_text("Reset all columns to default widths")
                    .clicked()
            {
                self.section_col_widths = DEFAULT_SECTION_COL_WIDTHS;
            ui.add_space(16.0);
            ui.label("🔍");
            ui.add(
                egui::TextEdit::singleline(&mut self.search_query)
                    .hint_text("Search symbols by name…")
                    .desired_width(220.0),
            );

            if !self.search_query.is_empty() && ui.small_button("✕").clicked() {
                self.search_query.clear();
            }

            ui.separator();

            // Filter pills
            let filter_btn = |ui: &mut egui::Ui,
                              current: &mut SymbolFilter,
                              target: SymbolFilter,
                              label: &str| {
                let is_sel = *current == target;
                if ui.selectable_label(is_sel, label).clicked() {
                    *current = target;
                }
            };
            filter_btn(ui, &mut self.symbol_filter, SymbolFilter::All, "All");
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

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let search_box = egui::TextEdit::singleline(&mut self.search_query)
                    .hint_text("🔍 Filter sections (name, address, type)...")
                    .desired_width(260.0);
                ui.add(search_box);
                if !self.search_query.is_empty() && ui.button("Clear").clicked() {
                    self.search_query.clear();
                if ui.button("↺ Reset Widths").clicked() {
                    self.symbol_col_widths = DEFAULT_SYMBOL_COL_WIDTHS;
                }
            });
        });
        ui.add_space(4.0);

        let query = self.search_query.to_lowercase();
        let mut filtered: Vec<&Section> = binary
            .sections
        ui.add_space(6.0);

        // Filter and sort symbols
        let q = self.search_query.to_lowercase();
        let mut visible: Vec<&Symbol> = binary
            .symbols
            .iter()
            .filter(|s| {
                if query.is_empty() {
                    return true;
                if !q.is_empty() && !s.name.to_lowercase().contains(&q) {
                    return false;
                }
                s.name.to_lowercase().contains(&query)
                    || format!("{:#x}", s.section_type).contains(&query)
                    || section_type_name(s.section_type)
                        .to_lowercase()
                        .contains(&query)
                    || format!("{:#x}", s.address).contains(&query)
                match self.symbol_filter {
                    SymbolFilter::All => true,
                    SymbolFilter::Functions => s.sym_type == SymbolType::Func,
                    SymbolFilter::Objects => s.sym_type == SymbolType::Object,
                    SymbolFilter::Imports => s.is_import,
                    SymbolFilter::Exports => s.is_export,
                }
            })
            .collect();

        // Sort sections
        filtered.sort_by(|a, b| {
            let ordering = match self.section_sort {
                SectionSort::Index => a.index.cmp(&b.index),
                SectionSort::Name => a.name.cmp(&b.name),
                SectionSort::Type => a.section_type.cmp(&b.section_type),
                SectionSort::Address => a.address.cmp(&b.address),
                SectionSort::Size => a.size.cmp(&b.size),
            };
            if self.section_sort_asc {
                ordering
            } else {
                ordering.reverse()
            }
        });

        if !query.is_empty() {
            ui.small(format!(
                "Showing {} of {} sections",
                filtered.len(),
                binary.sections.len()
            ));
            ui.add_space(2.0);
        match self.symbol_sort {
            SymbolSort::Index => visible.sort_by_key(|s| s.index),
            SymbolSort::Name => visible.sort_by_key(|s| &s.name),
            SymbolSort::Type => visible.sort_by_key(|s| s.sym_type.to_string()),
            SymbolSort::Binding => visible.sort_by_key(|s| s.binding.to_string()),
            SymbolSort::Address => visible.sort_by_key(|s| s.value),
            SymbolSort::Size => visible.sort_by_key(|s| s.size),
        }
        if !self.symbol_sort_asc {
            visible.reverse();
        }

        let has_detail = self.selected_section.is_some();
        let table_height = if has_detail {
            (ui.available_height() - self.section_detail_height - 12.0).max(100.0)
        ui.small(format!("Showing {} matching symbols", visible.len()));
        ui.add_space(4.0);

        let has_selection = self.selected_symbol.is_some();
        let table_avail_height = if has_selection {
            (ui.available_height() - self.symbol_detail_height - 12.0).max(100.0)
        } else {
            ui.available_height()
        };

        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width(), table_height),
            egui::Layout::top_down(egui::Align::LEFT),
            |ui| {
                egui::ScrollArea::both()
                    .id_salt("sections_scroll")
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 6.0;
                            render_col_header(
                                ui,
                                &mut self.section_col_widths[0],
                                DEFAULT_SECTION_COL_WIDTHS[0],
                                35.0,
                                "#",
                                sort_arrow(
                                    self.section_sort == SectionSort::Index,
                                    self.section_sort_asc,
                                ),
                                || {
                                    toggle_sort(
                                        &mut self.section_sort,
                                        SectionSort::Index,
                                        &mut self.section_sort_asc,
                                    );
                                },
                            );
                            render_col_header(
                                ui,
                                &mut self.section_col_widths[1],
                                DEFAULT_SECTION_COL_WIDTHS[1],
                                70.0,
                                "Name",
                                sort_arrow(
                                    self.section_sort == SectionSort::Name,
                                    self.section_sort_asc,
                                ),
                                || {
                                    toggle_sort(
                                        &mut self.section_sort,
                                        SectionSort::Name,
                                        &mut self.section_sort_asc,
                                    );
                                },
                            );
                            render_col_header(
                                ui,
                                &mut self.section_col_widths[2],
                                DEFAULT_SECTION_COL_WIDTHS[2],
                                70.0,
                                "Type",
                                sort_arrow(
                                    self.section_sort == SectionSort::Type,
                                    self.section_sort_asc,
                                ),
                                || {
                                    toggle_sort(
                                        &mut self.section_sort,
                                        SectionSort::Type,
                                        &mut self.section_sort_asc,
                                    );
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
                                70.0,
                                "Address",
                                sort_arrow(
                                    self.section_sort == SectionSort::Address,
                                    self.section_sort_asc,
                                ),
                                || {
                                    toggle_sort(
                                        &mut self.section_sort,
                                        SectionSort::Address,
                                        &mut self.section_sort_asc,
                                    );
                                },
                            );
                            render_col_header(
                                ui,
                                &mut self.section_col_widths[5],
                                DEFAULT_SECTION_COL_WIDTHS[5],
                                60.0,
                                "Size",
                                sort_arrow(
                                    self.section_sort == SectionSort::Size,
                                    self.section_sort_asc,
                                ),
                                || {
                                    toggle_sort(
                                        &mut self.section_sort,
                                        SectionSort::Size,
                                        &mut self.section_sort_asc,
                                    );
                                },
                            );
                            render_col_header(
                                ui,
                                &mut self.section_col_widths[6],
                                DEFAULT_SECTION_COL_WIDTHS[6],
                                50.0,
                                "Offset",
                                None,
                                || {},
                            );
                        });
        // Table
        egui::ScrollArea::both()
            .max_height(table_avail_height)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;

                        ui.separator();
                    let sort_field = self.symbol_sort;
                    let sort_asc = self.symbol_sort_asc;

                        for (row_idx, section) in filtered.into_iter().enumerate() {
                            let is_selected = self.selected_section == Some(section.index);
                            let row_fill = if is_selected {
                                ui.visuals().selection.bg_fill.gamma_multiply(0.25)
                            } else if row_idx % 2 == 1 {
                                ui.visuals().faint_bg_color.gamma_multiply(0.5)
                            } else {
                                egui::Color32::TRANSPARENT
                            };
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

                            let row_frame = egui::Frame::new()
                                .fill(row_fill)
                                .corner_radius(egui::CornerRadius::same(3))
                                .inner_margin(egui::Margin::symmetric(2, 2));
                ui.separator();

                            row_frame.show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 6.0;
                for sym in visible {
                    let is_selected = self.selected_symbol == Some(sym.index);
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 6.0;

                                    cell_label(
                                        ui,
                                        self.section_col_widths[0],
                                        section.index.to_string(),
                                        false,
                                        None,
                                    );
                        // Index
                        cell_label(
                            ui,
                            self.symbol_col_widths[0],
                            sym.index.to_string(),
                            true,
                            None,
                        );

                                    let name_btn = egui::Button::new(
                                        egui::RichText::new(&section.name).monospace().strong(),
                                    )
                                    .min_size(egui::vec2(self.section_col_widths[1], 20.0))
                                    .selected(is_selected)
                                    .truncate();
                                    if ui
                                        .add(name_btn)
                                        .on_hover_text(format!(
                                            "Click to inspect {}\n{}",
                                            section.name,
                                            if is_selected {
                                                "(Currently selected)"
                                            } else {
                                                ""
                                            }
                                        ))
                                        .clicked()
                                    {
                                        if is_selected {
                                            self.selected_section = None;
                                        } else {
                                            self.selected_section = Some(section.index);
                                        }
                                    }
                        // Name (selectable)
                        let name_display = if sym.name.is_empty() {
                            "<unnamed>"
                        } else {
                            &sym.name
                        };
                        let btn = egui::Button::new(egui::RichText::new(name_display).strong())
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

                                    let type_desc = format!(
                                        "{:#x} ({})",
                                        section.section_type,
                                        section_type_name(section.section_type)
                                    );
                                    cell_label(
                                        ui,
                                        self.section_col_widths[2],
                                        &type_desc,
                                        false,
                                        Some(&type_desc),
                                    );
                        // Type
                        cell_label(
                            ui,
                            self.symbol_col_widths[2],
                            sym.sym_type.to_string(),
                            true,
                            None,
                        );

                                    let flags_str = section_flags_str(section.flags);
                                    let flags_hover =
                                        format!("Flags: {:#x} ({flags_str})", section.flags);
                                    cell_label(
                                        ui,
                                        self.section_col_widths[3],
                                        egui::RichText::new(&flags_str)
                                            .color(ui.visuals().weak_text_color()),
                                        false,
                                        Some(&flags_hover),
                                    );
                        // Binding
                        cell_label(
                            ui,
                            self.symbol_col_widths[3],
                            sym.binding.to_string(),
                            true,
                            None,
                        );

                                    let addr_str = format!("{:#010x}", section.address);
                                    cell_label(
                                        ui,
                                        self.section_col_widths[4],
                                        &addr_str,
                                        true,
                                        Some(&addr_str),
                                    );
                        // Visibility
                        cell_label(
                            ui,
                            self.symbol_col_widths[4],
                            sym.visibility.to_string(),
                            true,
                            None,
                        );

                                    let size_str = format_bytes(section.size);
                                    let size_hover =
                                        format!("{} bytes ({:#x})", section.size, section.size);
                                    cell_label(
                                        ui,
                                        self.section_col_widths[5],
                                        &size_str,
                                        true,
                                        Some(&size_hover),
                                    );
                        // Address
                        let addr_str = format!("{:#010x}", sym.value);
                        cell_label(
                            ui,
                            self.symbol_col_widths[5],
                            &addr_str,
                            true,
                            Some(&addr_str),
                        );

                                    let offset_str = format!("{:#x}", section.offset);
                                    cell_label(
                                        ui,
                                        self.section_col_widths[6],
                                        &offset_str,
                                        true,
                                        Some(&offset_str),
                                    );
                                });
                            });
                        }
                        // Size
                        cell_label(
                            ui,
                            self.symbol_col_widths[6],
                            sym.size.to_string(),
                            true,
                            None,
                        );

                        // Table kind
                        cell_label(
                            ui,
                            self.symbol_col_widths[7],
                            sym.table.to_string(),
                            true,
                            None,
                        );
                    });
            },
        );
                }
            });

        if let Some(selected_idx) = self.selected_section {
            if let Some(sec) = binary.sections.iter().find(|s| s.index == selected_idx) {
        // Bottom Detail Panel
        if let Some(idx) = self.selected_symbol {
            if let Some(sym) = binary.symbols.get(idx) {
                ui.separator();

                let (splitter_rect, splitter_resp) = ui.allocate_exact_size(
                    egui::vec2(ui.available_width(), 6.0),
                    egui::Sense::click_and_drag(),
                );
                if splitter_resp.hovered() || splitter_resp.dragged() {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeVertical);
                }
                if splitter_resp.dragged() {
                    self.section_detail_height = (self.section_detail_height
                    self.symbol_detail_height = (self.symbol_detail_height
                        - splitter_resp.drag_delta().y)
                        .clamp(90.0, 450.0);
                        .clamp(80.0, 350.0);
                }
                if splitter_resp.double_clicked() {
                    self.section_detail_height = 175.0;
                }
                let color = if splitter_resp.dragged() {

                let fill = if splitter_resp.dragged() {
                    egui::Color32::from_rgb(91, 91, 214)
                } else if splitter_resp.hovered() {
                    egui::Color32::from_rgb(140, 140, 230)
                } else {
                    ui.visuals().widgets.noninteractive.bg_stroke.color
                    ui.visuals().faint_bg_color
                };
                ui.painter().hline(
                    splitter_rect.x_range(),
                    splitter_rect.center().y,
                    egui::Stroke::new(1.5, color),
                );
                ui.painter()
                    .rect_filled(splitter_rect, egui::CornerRadius::same(2), fill);

                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), self.section_detail_height),
                    egui::vec2(ui.available_width(), self.symbol_detail_height),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        egui::Frame::new()
                            .fill(ui.visuals().faint_bg_color)
                            .corner_radius(egui::CornerRadius::same(6))
                            .inner_margin(egui::Margin::symmetric(12, 8))
                        ui.horizontal(|ui| {
                            ui.strong(format!("Symbol Details: {}", sym.name));
                            if ui.small_button("📋 Copy Name").clicked() {
                                ui.ctx().copy_text(sym.name.clone());
                                self.set_status("Symbol name copied");
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
                            .spacing([24.0, 6.0])
                            .show(ui, |ui| {
                                self.render_section_detail_inspector(ui, sec);
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
                                        .map(|i| i.to_string())
                                        .unwrap_or_else(|| "UNDEF".to_string()),
                                );
                            });
                    },
                );
            }
        }
    }

    fn render_section_detail_inspector(&mut self, ui: &mut egui::Ui, sec: &Section) {
    fn render_sections(&mut self, ui: &mut egui::Ui, binary: &Binary) {
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(format!("🔍 Section Details: {}", sec.name))
                    .strong()
                    .size(14.0),
            ui.heading(format!("📑 Sections ({})", binary.sections.len()));

            ui.add_space(16.0);
            ui.label("🔍");
            ui.add(
                egui::TextEdit::singleline(&mut self.search_query)
                    .hint_text("Filter by name or type…")
                    .desired_width(200.0),
            );
            if ui.small_button("📋 Copy Name").clicked() {
                ui.ctx().copy_text(sec.name.clone());
                self.set_status("Section name copied");

            if !self.search_query.is_empty() && ui.small_button("✕").clicked() {
                self.search_query.clear();
            }
            if ui.small_button("📋 Copy Addr").clicked() {
                ui.ctx().copy_text(format!("{:#x}", sec.address));
                self.set_status("Address copied");
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("✕ Close").clicked() {
                    self.selected_section = None;
                if ui.button("↺ Reset Widths").clicked() {
                    self.section_col_widths = DEFAULT_SECTION_COL_WIDTHS;
                }
            });
        });
        ui.separator();

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("sec_detail_grid")
                .num_columns(4)
                .spacing([18.0, 4.0])
                .show(ui, |ui| {
                    ui.strong("Type:");
                    ui.label(format!(
                        "{:#x} ({})",
                        sec.section_type,
                        section_type_name(sec.section_type)
                    ));
                    ui.strong("Flags:");
                    ui.label(format!(
                        "{:#x} ({})",
                        sec.flags,
                        section_flags_str(sec.flags)
                    ));
                    ui.end_row();
        ui.add_space(6.0);

                    ui.strong("Virtual Address:");
                    ui.monospace(format!("{:#010x}", sec.address));
                    ui.strong("Range:");
                    ui.monospace(format!(
                        "{:#010x} .. {:#010x}",
                        sec.address,
                        sec.address.saturating_add(sec.size)
                    ));
                    ui.end_row();
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

                    ui.strong("File Offset:");
                    ui.monospace(format!("{:#x} ({} bytes)", sec.offset, sec.offset));
                    ui.strong("Size:");
                    ui.monospace(format!("{} ({} bytes)", format_bytes(sec.size), sec.size));
                    ui.end_row();
        match self.section_sort {
            SectionSort::Index => visible.sort_by_key(|s| s.index),
            SectionSort::Name => visible.sort_by_key(|s| &s.name),
            SectionSort::Type => visible.sort_by_key(|s| s.section_type),
            SectionSort::Address => visible.sort_by_key(|s| s.address),
            SectionSort::Size => visible.sort_by_key(|s| s.size),
            SectionSort::Entropy => visible.sort_by(|a, b| a.entropy.total_cmp(&b.entropy)),
        }
        if !self.section_sort_asc {
            visible.reverse();
        }

                    ui.strong("Link:");
                    ui.label(sec.link.to_string());
                    ui.strong("Raw Flags Hex:");
                    ui.monospace(format!("{:#x}", sec.flags));
                    ui.end_row();
        ui.small(format!("Showing {} sections", visible.len()));
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
                        55.0,
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

                        let name_btn =
                            egui::Button::new(egui::RichText::new(&section.name).strong())
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
                        cell_label(
                            ui,
                            self.section_col_widths[3],
                            egui::RichText::new(&flags_str).strong(),
                            false,
                            None,
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

                        // Entropy with color
                        let ent_str = format!("{:.2}", section.entropy);
                        let ent_color = if section.entropy > 7.2 {
                            egui::Color32::from_rgb(230, 80, 80)
                        } else if section.entropy > 6.0 {
                            egui::Color32::from_rgb(220, 160, 40)
                        } else if section.entropy < 2.0 {
                            egui::Color32::from_rgb(90, 180, 90)
                        } else {
                            ui.visuals().text_color()
                        };
                        cell_label(
                            ui,
                            self.section_col_widths[7],
                            egui::RichText::new(ent_str).color(ent_color),
                            true,
                            None,
                        );
                    });
                }
            });

        // Bottom Detail Panel
        if let Some(idx) = self.selected_section {
            if let Some(section) = binary.sections.iter().find(|s| s.index == idx) {
                ui.separator();

                let (splitter_rect, splitter_resp) = ui.allocate_exact_size(
                    egui::vec2(ui.available_width(), 6.0),
                    egui::Sense::click_and_drag(),
                );
                if splitter_resp.hovered() || splitter_resp.dragged() {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeVertical);
                }
                if splitter_resp.dragged() {
                    self.section_detail_height = (self.section_detail_height
                        - splitter_resp.drag_delta().y)
                        .clamp(80.0, 350.0);
                }

                let fill = if splitter_resp.dragged() {
                    egui::Color32::from_rgb(91, 91, 214)
                } else {
                    ui.visuals().faint_bg_color
                };
                ui.painter()
                    .rect_filled(splitter_rect, egui::CornerRadius::same(2), fill);

                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), self.section_detail_height),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.horizontal(|ui| {
                            ui.strong(format!("Section #{}: {}", section.index, section.name));
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
                            .spacing([24.0, 6.0])
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
                                row(ui, "Entropy", &format!("{:.3} bits/byte", section.entropy));
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
                                row(ui, "Extra Info (sh_info)", &format!("{:#x}", section.info));
                                row(
                                    ui,
                                    "Linked Section (sh_link)",
                                    &format!("#{}", section.link),
                                );
                            });
                    },
                );
            }
        }
    }

    fn render_segments(&mut self, ui: &mut egui::Ui, binary: &Binary) {
        ui.horizontal(|ui| {
            ui.heading(format!("Program Segments ({})", binary.segments.len()));

            if self.segment_col_widths != DEFAULT_SEGMENT_COL_WIDTHS
                && ui
                    .small_button("↺ Reset Widths")
                    .on_hover_text("Reset all columns to default widths")
                    .clicked()
            {
                self.segment_col_widths = DEFAULT_SEGMENT_COL_WIDTHS;
            }
            ui.heading(format!("📦 Segments ({})", binary.segments.len()));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("↺ Reset Widths").clicked() {
                    self.segment_col_widths = DEFAULT_SEGMENT_COL_WIDTHS;
                }
            });
        });
        ui.add_space(4.0);

        let mut segments: Vec<&Segment> = binary.segments.iter().collect();
        segments.sort_by(|a, b| {
            let ordering = match self.segment_sort {
                SegmentSort::Index => a.index.cmp(&b.index),
                SegmentSort::Type => a.segment_type.cmp(&b.segment_type),
                SegmentSort::Offset => a.offset.cmp(&b.offset),
                SegmentSort::Address => a.virtual_address.cmp(&b.virtual_address),
                SegmentSort::Size => a.memory_size.cmp(&b.memory_size),
                SegmentSort::Flags => a.flags.cmp(&b.flags),
            };
            if self.segment_sort_asc {
                ordering
            } else {
                ordering.reverse()
            }
        });
        ui.add_space(6.0);

        let has_detail = self.selected_segment.is_some();
        let table_height = if has_detail {
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

        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width(), table_height),
            egui::Layout::top_down(egui::Align::LEFT),
            |ui| {
                egui::ScrollArea::both()
                    .id_salt("segments_scroll")
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 6.0;
                            render_col_header(
                                ui,
                                &mut self.segment_col_widths[0],
                                DEFAULT_SEGMENT_COL_WIDTHS[0],
                                35.0,
                                "#",
                                sort_arrow(
                                    self.segment_sort == SegmentSort::Index,
                                    self.segment_sort_asc,
                                ),
                                || {
                                    toggle_sort(
                                        &mut self.segment_sort,
                                        SegmentSort::Index,
                                        &mut self.segment_sort_asc,
                                    );
                                },
                            );
                            render_col_header(
                                ui,
                                &mut self.segment_col_widths[1],
                                DEFAULT_SEGMENT_COL_WIDTHS[1],
                                80.0,
                                "Type",
                                sort_arrow(
                                    self.segment_sort == SegmentSort::Type,
                                    self.segment_sort_asc,
                                ),
                                || {
                                    toggle_sort(
                                        &mut self.segment_sort,
                                        SegmentSort::Type,
                                        &mut self.segment_sort_asc,
                                    );
                                },
                            );
                            render_col_header(
                                ui,
                                &mut self.segment_col_widths[2],
                                DEFAULT_SEGMENT_COL_WIDTHS[2],
                                50.0,
                                "Flags",
                                sort_arrow(
                                    self.segment_sort == SegmentSort::Flags,
                                    self.segment_sort_asc,
                                ),
                                || {
                                    toggle_sort(
                                        &mut self.segment_sort,
                                        SegmentSort::Flags,
                                        &mut self.segment_sort_asc,
                                    );
                                },
                            );
                            render_col_header(
                                ui,
                                &mut self.segment_col_widths[3],
                                DEFAULT_SEGMENT_COL_WIDTHS[3],
                                60.0,
                                "Offset",
                                sort_arrow(
                                    self.segment_sort == SegmentSort::Offset,
                                    self.segment_sort_asc,
                                ),
                                || {
                                    toggle_sort(
                                        &mut self.segment_sort,
                                        SegmentSort::Offset,
                                        &mut self.segment_sort_asc,
                                    );
                                },
                            );
                            render_col_header(
                                ui,
                                &mut self.segment_col_widths[4],
                                DEFAULT_SEGMENT_COL_WIDTHS[4],
                                70.0,
                                "Virtual Address",
                                sort_arrow(
                                    self.segment_sort == SegmentSort::Address,
                                    self.segment_sort_asc,
                                ),
                                || {
                                    toggle_sort(
                                        &mut self.segment_sort,
                                        SegmentSort::Address,
                                        &mut self.segment_sort_asc,
                                    );
                                },
                            );
                            render_col_header(
                                ui,
                                &mut self.segment_col_widths[5],
                                DEFAULT_SEGMENT_COL_WIDTHS[5],
                                60.0,
                                "File Size",
                                None,
                                || {},
                            );
                            render_col_header(
                                ui,
                                &mut self.segment_col_widths[6],
                                DEFAULT_SEGMENT_COL_WIDTHS[6],
                                60.0,
                                "Memory Size",
                                sort_arrow(
                                    self.segment_sort == SegmentSort::Size,
                                    self.segment_sort_asc,
                                ),
                                || {
                                    toggle_sort(
                                        &mut self.segment_sort,
                                        SegmentSort::Size,
                                        &mut self.segment_sort_asc,
                                    );
                                },
                            );
                            render_col_header(
                                ui,
                                &mut self.segment_col_widths[7],
                                DEFAULT_SEGMENT_COL_WIDTHS[7],
                                50.0,
                                "Align",
                                None,
                                || {},
                            );
                        });
        egui::ScrollArea::both()
            .max_height(table_avail_height)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;

                        ui.separator();
                    let sort_field = self.segment_sort;
                    let sort_asc = self.segment_sort_asc;

                        for (row_idx, segment) in segments.into_iter().enumerate() {
                            let is_selected = self.selected_segment == Some(segment.index);
                            let row_fill = if is_selected {
                                ui.visuals().selection.bg_fill.gamma_multiply(0.25)
                            } else if row_idx % 2 == 1 {
                                ui.visuals().faint_bg_color.gamma_multiply(0.5)
                            } else {
                                egui::Color32::TRANSPARENT
                            };
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
                        50.0,
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
                        65.0,
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
                        80.0,
                        "Virt Address",
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
                        65.0,
                        "File Size",
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
                        65.0,
                        "Mem Size",
                        None,
                        || {},
                    );
                    render_col_header(
                        ui,
                        &mut self.segment_col_widths[7],
                        DEFAULT_SEGMENT_COL_WIDTHS[7],
                        55.0,
                        "Align",
                        None,
                        || {},
                    );
                });

                            let row_frame = egui::Frame::new()
                                .fill(row_fill)
                                .corner_radius(egui::CornerRadius::same(3))
                                .inner_margin(egui::Margin::symmetric(2, 2));
                ui.separator();

                            row_frame.show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 6.0;
                for segment in visible {
                    let is_selected = self.selected_segment == Some(segment.index);
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 6.0;

                                    cell_label(
                                        ui,
                                        self.segment_col_widths[0],
                                        segment.index.to_string(),
                                        false,
                                        None,
                                    );
                        cell_label(
                            ui,
                            self.segment_col_widths[0],
                            segment.index.to_string(),
                            true,
                            None,
                        );

                                    let type_text = format!(
                                        "{:#x} ({})",
                                        segment.segment_type,
                                        segment_type_name(segment.segment_type)
                                    );
                                    let type_btn =
                                        egui::Button::new(egui::RichText::new(&type_text).strong())
                                            .min_size(egui::vec2(self.segment_col_widths[1], 20.0))
                                            .selected(is_selected)
                                            .truncate();
                                    if ui
                                        .add(type_btn)
                                        .on_hover_text(format!(
                                            "Click to inspect segment #{}",
                                            segment.index
                                        ))
                                        .clicked()
                                    {
                                        if is_selected {
                                            self.selected_segment = None;
                                        } else {
                                            self.selected_segment = Some(segment.index);
                                        }
                                    }
                        let type_str = format!(
                            "{:#x} ({})",
                            segment.segment_type,
                            segment_type_name(segment.segment_type)
                        );
                        let type_btn = egui::Button::new(egui::RichText::new(&type_str).strong())
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
                                    cell_label(
                                        ui,
                                        self.segment_col_widths[2],
                                        egui::RichText::new(flags_str).strong(),
                                        false,
                                        None,
                                    );
                        let flags_str = segment_flags_str(segment.flags);
                        let is_rwx = (segment.flags & 2 != 0) && (segment.flags & 1 != 0);
                        let flags_color = if is_rwx {
                            egui::Color32::from_rgb(230, 70, 70)
                        } else {
                            ui.visuals().text_color()
                        };
                        cell_label(
                            ui,
                            self.segment_col_widths[2],
                            egui::RichText::new(flags_str).color(flags_color).strong(),
                            false,
                            if is_rwx {
                                Some("⚠️ W^X violation: Write and Execute permissions")
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
                        let addr_str = format!("{:#010x}", segment.virtual_address);
                        cell_label(
                            ui,
                            self.segment_col_widths[4],
                            &addr_str,
                            true,
                            Some(&addr_str),
                        );

                                    let file_size_str = format_bytes(segment.file_size);
                                    cell_label(
                                        ui,
                                        self.segment_col_widths[5],
                                        &file_size_str,
                                        true,
                                        None,
                                    );
                        let file_size_str = format_bytes(segment.file_size);
                        cell_label(ui, self.segment_col_widths[5], &file_size_str, true, None);

                                    let mem_size_str = format_bytes(segment.memory_size);
                                    cell_label(
                                        ui,
                                        self.segment_col_widths[6],
                                        &mem_size_str,
                                        true,
                                        None,
                                    );
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
                            });
                        }
                        let align_str = format!("{:#x}", segment.alignment);
                        cell_label(
                            ui,
                            self.segment_col_widths[7],
                            &align_str,
                            true,
                            Some(&align_str),
                        );
                    });
            },
        );
                }
            });

        if let Some(selected_idx) = self.selected_segment {
            if let Some(seg) = binary.segments.iter().find(|s| s.index == selected_idx) {
        // Bottom Detail Panel
        if let Some(idx) = self.selected_segment {
            if let Some(segment) = binary.segments.iter().find(|s| s.index == idx) {
                ui.separator();

                let (splitter_rect, splitter_resp) = ui.allocate_exact_size(
                    egui::vec2(ui.available_width(), 6.0),
                    egui::Sense::click_and_drag(),
                );
                if splitter_resp.hovered() || splitter_resp.dragged() {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeVertical);
                }
                if splitter_resp.dragged() {
                    self.segment_detail_height = (self.segment_detail_height
                        - splitter_resp.drag_delta().y)
                        .clamp(90.0, 450.0);
                        .clamp(80.0, 350.0);
                }
                if splitter_resp.double_clicked() {
                    self.segment_detail_height = 175.0;
                }
                let color = if splitter_resp.dragged() {

                let fill = if splitter_resp.dragged() {
                    egui::Color32::from_rgb(91, 91, 214)
                } else if splitter_resp.hovered() {
                    egui::Color32::from_rgb(140, 140, 230)
                } else {
                    ui.visuals().widgets.noninteractive.bg_stroke.color
                    ui.visuals().faint_bg_color
                };
                ui.painter().hline(
                    splitter_rect.x_range(),
                    splitter_rect.center().y,
                    egui::Stroke::new(1.5, color),
                );
                ui.painter()
                    .rect_filled(splitter_rect, egui::CornerRadius::same(2), fill);

                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), self.segment_detail_height),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        egui::Frame::new()
                            .fill(ui.visuals().faint_bg_color)
                            .corner_radius(egui::CornerRadius::same(6))
                            .inner_margin(egui::Margin::symmetric(12, 8))
                        ui.horizontal(|ui| {
                            ui.strong(format!(
                                "Segment #{}: {}",
                                segment.index,
                                segment_type_name(segment.segment_type)
                            ));
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
                            .spacing([24.0, 6.0])
                            .show(ui, |ui| {
                                self.render_segment_detail_inspector(ui, seg);
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
            }
        }
    }

    fn render_segment_detail_inspector(&mut self, ui: &mut egui::Ui, seg: &Segment) {
        ui.horizontal(|ui| {
            ui.label(
    fn render_dependencies(&mut self, ui: &mut egui::Ui, binary: &Binary) {
        ui.heading("🔗 Dynamic Loader & Dependencies");
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
                ui.group(|ui| {
                    ui.set_width(ui.available_width());
                    egui::Grid::new("loader_grid")
                        .num_columns(2)
                        .spacing([20.0, 8.0])
                        .show(ui, |ui| {
                            row(
                                ui,
                                "ELF Interpreter (PT_INTERP)",
                                binary
                                    .dynamic
                                    .interpreter
                                    .as_deref()
                                    .unwrap_or("None (Statically Linked)"),
                            );
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
                                    "Immediate (BIND_NOW)"
                                } else {
                                    "Lazy Binding"
                                },
                            );
                        });
                });
            });

            ui.add_space(10.0);

            // Needed libraries
            egui::CollapsingHeader::new(
                egui::RichText::new(format!(
                    "🔍 Segment #{} Details ({})",
                    seg.index,
                    segment_type_name(seg.segment_type)
                    "📚 Required Dynamic Libraries ({})",
                    binary.dynamic.needed.len()
                ))
                .strong()
                .size(14.0),
            );
            if ui.small_button("📋 Copy Address").clicked() {
                ui.ctx().copy_text(format!("{:#x}", seg.virtual_address));
                self.set_status("Segment address copied");
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("✕ Close").clicked() {
                    self.selected_segment = None;
                .heading()
                .size(15.0),
            )
            .default_open(true)
            .show(ui, |ui| {
                if binary.dynamic.needed.is_empty() {
                    ui.label("No DT_NEEDED dependencies found.");
                } else {
                    for lib in &binary.dynamic.needed {
                        ui.horizontal(|ui| {
                            ui.label("•");
                            ui.monospace(egui::RichText::new(lib).strong());
                            if ui.small_button("📋 Copy").clicked() {
                                ui.ctx().copy_text(lib.clone());
                                self.set_status(format!("Copied {lib}"));
                            }
                        });
                    }
                }
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
                    egui::Grid::new("dyn_entries_grid")
                        .num_columns(3)
                        .spacing([20.0, 6.0])
                        .striped(true)
                        .show(ui, |ui| {
                            ui.strong("Tag");
                            ui.strong("Value");
                            ui.strong("Decoded Info");
                            ui.end_row();

                            for entry in &binary.dynamic.entries {
                                ui.monospace(&entry.tag_name);
                                ui.monospace(format!("{:#x}", entry.value));
                                ui.label(entry.string_value.as_deref().unwrap_or("-"));
                                ui.end_row();
                            }
                        });
                });
            }
        });
        ui.separator();
    }

    fn render_notes(&mut self, ui: &mut egui::Ui, notes: &[ElfNote]) {
        ui.heading(format!("📝 ELF Notes & Build Attributes ({})", notes.len()));
        ui.label("Embedded notes specifying build IDs, minimum OS ABI versions, and processor extensions.");
        ui.add_space(12.0);

        if notes.is_empty() {
            ui.label("No note segments or sections found in this binary.");
            return;
        }

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("seg_detail_grid")
                .num_columns(4)
                .spacing([18.0, 4.0])
                .show(ui, |ui| {
                    ui.strong("Type:");
                    ui.label(format!(
                        "{:#x} ({})",
                        seg.segment_type,
                        segment_type_name(seg.segment_type)
                    ));
                    ui.strong("Flags:");
                    ui.label(format!(
                        "{:#x} ({})",
                        seg.flags,
                        segment_flags_str(seg.flags)
                    ));
                    ui.end_row();
            for (idx, note) in notes.iter().enumerate() {
                let frame = egui::Frame::new()
                    .fill(ui.visuals().faint_bg_color)
                    .corner_radius(egui::CornerRadius::same(8))
                    .inner_margin(egui::Margin::symmetric(16, 12));

                    ui.strong("Virtual Address:");
                    ui.monospace(format!("{:#010x}", seg.virtual_address));
                    ui.strong("Memory Range:");
                    ui.monospace(format!(
                        "{:#010x} .. {:#010x}",
                        seg.virtual_address,
                        seg.virtual_address.saturating_add(seg.memory_size)
                    ));
                    ui.end_row();
                frame.show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.strong(format!("Note #{}: [{}]", idx + 1, note.name));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            badge(
                                ui,
                                &format!("Type {:#x}", note.note_type),
                                egui::Color32::from_rgb(110, 110, 240),
                            );
                        });
                    });
                    ui.add_space(4.0);
                    ui.label(&note.description);

                    ui.strong("File Offset:");
                    ui.monospace(format!("{:#x} ({} bytes)", seg.offset, seg.offset));
                    ui.strong("File Size:");
                    ui.monospace(format!(
                        "{} ({} bytes)",
                        format_bytes(seg.file_size),
                        seg.file_size
                    ));
                    ui.end_row();
                    if let Some(bid) = &note.build_id {
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            ui.strong("Build ID:");
                            ui.monospace(bid);
                            if ui.small_button("📋 Copy").clicked() {
                                ui.ctx().copy_text(bid.clone());
                                self.set_status("Build ID copied");
                            }
                        });
                    }

                    ui.strong("Memory Size:");
                    ui.monospace(format!(
                        "{} ({} bytes)",
                        format_bytes(seg.memory_size),
                        seg.memory_size
                    ));
                    ui.strong("Alignment:");
                    ui.monospace(format!("{:#x} ({} bytes)", seg.alignment, seg.alignment));
                    ui.end_row();
                    if !note.properties.is_empty() {
                        ui.add_space(4.0);
                        ui.strong("Features & Properties:");
                        for prop in &note.properties {
                            ui.monospace(format!("  • {prop}"));
                        }
                    }
                });
                ui.add_space(8.0);
            }
        });
    }

    fn render_dependencies(&mut self, ui: &mut egui::Ui, binary: &Binary) {
    fn render_relocations(&mut self, ui: &mut egui::Ui, relocations: &[Relocation]) {
        ui.horizontal(|ui| {
            ui.heading(format!(
                "Dynamic Dependencies ({})",
                binary.dynamic.needed.len()
            ));
            ui.heading(format!("🎯 Relocations ({})", relocations.len()));

            ui.add_space(16.0);
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
                let search_box = egui::TextEdit::singleline(&mut self.search_query)
                    .hint_text("🔍 Filter libraries...")
                    .desired_width(220.0);
                ui.add(search_box);
                if !self.search_query.is_empty() && ui.button("Clear").clicked() {
                    self.search_query.clear();
                if ui.button("↺ Reset Widths").clicked() {
                    self.reloc_col_widths = DEFAULT_RELOC_COL_WIDTHS;
                }
            });
        });
        ui.add_space(10.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            // Interpreter Card
            ui.group(|ui| {
                ui.set_width(ui.available_width());
                ui.heading(egui::RichText::new("Program Interpreter (PT_INTERP)").size(14.0));
                ui.separator();
                if let Some(interpreter) = &binary.dynamic.interpreter {
                    ui.horizontal(|ui| {
                        ui.monospace(interpreter);
                        if ui
                            .small_button("📋")
                            .on_hover_text("Copy interpreter path")
                            .clicked()
                        {
                            ui.ctx().copy_text(interpreter.clone());
                            self.set_status("Interpreter path copied");
                        }
                    });
        ui.add_space(6.0);

        let query = self.search_query.to_lowercase();
        let visible: Vec<&Relocation> = relocations
            .iter()
            .filter(|r| {
                if query.is_empty() {
                    true
                } else {
                    ui.label(
                        egui::RichText::new("None (Statically linked binary)")
                            .color(ui.visuals().weak_text_color()),
                    );
                    r.section_name.to_lowercase().contains(&query)
                        || r.symbol_name
                            .as_deref()
                            .unwrap_or("")
                            .to_lowercase()
                            .contains(&query)
                }
            })
            .collect();

        ui.small(format!("Showing {} relocations", visible.len()));
        ui.add_space(4.0);

        egui::ScrollArea::both().show(ui, |ui| {
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

            ui.add_space(10.0);
            ui.separator();

            // Library Search Paths Card (RPATH / RUNPATH)
            if binary.dynamic.rpath.is_some() || binary.dynamic.runpath.is_some() {
                ui.group(|ui| {
                    ui.set_width(ui.available_width());
                    ui.heading(egui::RichText::new("Search Paths").size(14.0));
                    ui.separator();
                    if let Some(rpath) = &binary.dynamic.rpath {
                        row(ui, "RPATH", rpath);
                    }
                    if let Some(runpath) = &binary.dynamic.runpath {
                        row(ui, "RUNPATH", runpath);
                    }
                });
                ui.add_space(10.0);
            }
            for r in visible {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;

            // Needed Libraries Card
            ui.group(|ui| {
                ui.set_width(ui.available_width());
                ui.heading(egui::RichText::new("Required Shared Libraries (DT_NEEDED)").size(14.0));
                ui.separator();
                    let off_str = format!("{:#010x}", r.offset);
                    cell_label(ui, self.reloc_col_widths[0], &off_str, true, Some(&off_str));

                let query = self.search_query.to_lowercase();
                let filtered_libs: Vec<&String> = binary
                    .dynamic
                    .needed
                    .iter()
                    .filter(|lib| query.is_empty() || lib.to_lowercase().contains(&query))
                    .collect();
                    cell_label(
                        ui,
                        self.reloc_col_widths[1],
                        r.rel_type.to_string(),
                        true,
                        None,
                    );

                if filtered_libs.is_empty() {
                    if binary.dynamic.needed.is_empty() {
                        ui.label(
                            egui::RichText::new("No dynamic libraries required.")
                                .color(ui.visuals().weak_text_color()),
                        );
                    } else {
                        ui.label(
                            egui::RichText::new("No libraries match the search filter.")
                                .color(ui.visuals().weak_text_color()),
                        );
                    }
                } else {
                    for (i, library) in filtered_libs.into_iter().enumerate() {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(format!("{}.", i + 1))
                                    .color(ui.visuals().weak_text_color()),
                            );
                            ui.monospace(library);
                            if ui
                                .small_button("📋")
                                .on_hover_text("Copy library name")
                                .clicked()
                            {
                                ui.ctx().copy_text(library.clone());
                                self.set_status(format!("Copied {library}"));
                            }
                        });
                    }
                }
            });
                    let sym_name = r.symbol_name.as_deref().unwrap_or("<none>");
                    cell_label(
                        ui,
                        self.reloc_col_widths[2],
                        egui::RichText::new(sym_name).strong(),
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
}

fn badge(ui: &mut egui::Ui, text: &str, color: egui::Color32) {
    let frame = egui::Frame::new()
        .fill(color.gamma_multiply(0.18))
        .corner_radius(egui::CornerRadius::same(6))
        .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.6)))
        .inner_margin(egui::Margin::symmetric(8, 3));

    frame.show(ui, |ui| {
        ui.label(egui::RichText::new(text).color(color).strong().size(12.0));
    });
}

fn sort_arrow(is_active: bool, is_asc: bool) -> Option<&'static str> {
    if is_active {
        if is_asc {
            Some(" ▲")
        } else {
            Some(" ▼")
        }
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
            egui::Color32::from_rgb(91, 91, 214)
        } else if handle_resp.hovered() {
            egui::Color32::from_rgb(140, 140, 230)
        } else {
            ui.visuals().faint_bg_color
        };
        ui.painter().vline(
            handle_rect.center().x,
            handle_rect.y_range(),
            egui::Stroke::new(1.5, stroke_color),
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
            .fill(egui::Color32::from_black_alpha(200))
            .corner_radius(egui::CornerRadius::same(16))
            .stroke(egui::Stroke::new(
                3.0,
                egui::Color32::from_rgb(110, 110, 240),
            ))
            .inner_margin(egui::Margin::same(40));

        frame.show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.label(
                    egui::RichText::new("📥")
                        .size(64.0)
                        .color(egui::Color32::from_rgb(120, 120, 255)),
                );
                ui.add_space(12.0);
                ui.heading(
                    egui::RichText::new("Drop ELF Binary Here to Inspect")
                        .size(24.0)
                        .strong()
                        .color(egui::Color32::WHITE),
                );
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new("Safe local analysis without execution")
                        .color(egui::Color32::from_gray(200)),
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
    if s.is_empty() {
        "-".to_string()
    } else {
        s
    }
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
