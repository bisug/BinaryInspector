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
    Sections,
    Segments,
    Dependencies,
}

#[derive(Clone, Copy, PartialEq, Default)]
enum SectionSort {
    #[default]
    Index,
    Name,
    Type,
    Address,
    Size,
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
    },
    Failed {
        path: PathBuf,
        error: AppError,
    },
}

#[derive(Default)]
struct ViewState {
    view: View,
    search_query: String,
    section_sort: SectionSort,
    section_sort_asc: bool,
    segment_sort: SegmentSort,
    segment_sort_asc: bool,
    status_message: Option<(String, std::time::Instant)>,
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
        }
    }

    fn choose_file(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Select an ELF binary to inspect safely")
            .pick_file()
        {
            self.inspect(path);
        }
    }
}

impl eframe::App for InspectorApp {
    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        let context = ui.ctx().clone();

        // 1. Keyboard shortcuts
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
                self.view_state.search_query.clear();
            } else if matches!(self.inspection, Inspection::Failed { .. }) {
                self.inspection = Inspection::Empty;
            }
        }

        // 2. Drag & Drop handling
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

        // 3. Top Header Bar
        let mut choose_file = false;
        let mut unload_file = false;

        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("🔍 BinaryInspector")
                    .strong()
                    .size(17.0)
                    .color(egui::Color32::from_rgb(91, 91, 214)),
            );
            ui.separator();

            match &self.inspection {
                Inspection::Ready { path, .. } => {
                    let file_name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "Binary".to_string());

                    ui.label(egui::RichText::new(&file_name).strong().monospace());
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

        // 4. Central Content
        if is_hovering {
            render_drop_overlay(ui);
            return;
        }

        match &self.inspection {
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
        }

        // 5. Bottom Status Bar
        ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
            ui.add_space(4.0);
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
                    }
                    _ => {
                        ui.label(
                            egui::RichText::new("Ready").color(ui.visuals().weak_text_color()),
                        );
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
                        .strong()
                        .size(11.0)
                        .color(ui.visuals().weak_text_color()),
                );
                ui.add_space(8.0);

                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing = egui::vec2(8.0, 8.0);
                    let samples = [
                        ("Minimal Static", "samples/minimal-static"),
                        ("Dynamic C Binary", "samples/dynamic-c-binary"),
                        ("RPATH / RUNPATH", "samples/with-rpath-runpath"),
                        ("Custom Sections", "samples/custom-sections"),
                        ("BinaryInspector CLI", "samples/binary-inspector-cli"),
                    ];
                    for (label, path_str) in samples {
                        let path = PathBuf::from(path_str);
                        if path.exists() && ui.button(label).clicked() {
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
                        .strong()
                        .size(11.0)
                        .color(ui.visuals().weak_text_color()),
                );
                ui.add_space(6.0);
                for path in &self.recent_files {
                    let display_name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| path.display().to_string());
                    if ui
                        .link(format!("📄 {display_name}"))
                        .on_hover_text(path.display().to_string())
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
            );
            ui.add_space(10.0);
            ui.heading(
                egui::RichText::new("Could not inspect target")
                    .color(egui::Color32::from_rgb(220, 60, 60)),
            );
            ui.add_space(8.0);
            ui.monospace(path.display().to_string());
            ui.add_space(12.0);

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
            // Sidebar Navigation Rail
            ui.vertical(|ui| {
                ui.set_width(190.0);
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

                    let response = ui
                        .selectable_label(is_active, egui::RichText::new(text).size(14.0).strong());
                    if response.clicked() {
                        *current_view = target;
                    }
                };

                nav_item(ui, &mut self.view, View::Overview, "📊", "Overview", None);
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
                    Some(binary.dynamic.needed.len()),
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
            });

            ui.separator();

            // Main Content Area
            ui.vertical(|ui| match self.view {
                View::Overview => self.render_overview(ui, path, binary),
                View::Sections => self.render_sections(ui, binary),
                View::Segments => self.render_segments(ui, binary),
                View::Dependencies => self.render_dependencies(ui, binary),
            });
        });
    }

    fn render_overview(&mut self, ui: &mut egui::Ui, path: &Path, binary: &Binary) {
        ui.heading("Binary Overview");
        ui.add_space(8.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            // Card 1: File Identity
            ui.group(|ui| {
                ui.set_width(ui.available_width());
                ui.heading(egui::RichText::new("📁 File Identity").size(15.0));
                ui.separator();
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
                    });
            });

            ui.add_space(12.0);

            // Card 2: ELF Architecture & ABI
            ui.group(|ui| {
                ui.set_width(ui.available_width());
                ui.heading(egui::RichText::new("⚙️ ELF Header & Architecture").size(15.0));
                ui.separator();
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
                    });
            });

            ui.add_space(12.0);

            // Card 3: Execution & Security Metadata
            ui.group(|ui| {
                ui.set_width(ui.available_width());
                ui.heading(egui::RichText::new("🛡️ Execution & Security Properties").size(15.0));
                ui.separator();
                egui::Grid::new("exec_grid")
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
                        );
                        row(
                            ui,
                            "Position Independent (PIE)",
                            if is_pie {
                                "Yes (Shared object / PIE)"
                            } else {
                                "No (Fixed load address)"
                            },
                        );

                        row(
                            ui,
                            "Immediate Binding (BIND_NOW)",
                            if binary.dynamic.bind_now {
                                "Enabled (Full RELRO candidate)"
                            } else {
                                "Lazy binding default"
                            },
                        );

                        row(ui, "Total Sections", &binary.sections.len().to_string());
                        row(ui, "Total Segments", &binary.segments.len().to_string());
                    });
            });
        });
    }

    fn render_sections(&mut self, ui: &mut egui::Ui, binary: &Binary) {
        ui.horizontal(|ui| {
            ui.heading(format!("Sections ({})", binary.sections.len()));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let search_box = egui::TextEdit::singleline(&mut self.search_query)
                    .hint_text("🔍 Filter sections (name, address, type)...")
                    .desired_width(260.0);
                ui.add(search_box);
                if !self.search_query.is_empty() && ui.button("Clear").clicked() {
                    self.search_query.clear();
                }
            });
        });
        ui.add_space(6.0);

        let query = self.search_query.to_lowercase();
        let mut filtered: Vec<&Section> = binary
            .sections
            .iter()
            .filter(|s| {
                if query.is_empty() {
                    return true;
                }
                s.name.to_lowercase().contains(&query)
                    || format!("{:#x}", s.section_type).contains(&query)
                    || section_type_name(s.section_type)
                        .to_lowercase()
                        .contains(&query)
                    || format!("{:#x}", s.address).contains(&query)
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
            ui.add_space(4.0);
        }

        egui::ScrollArea::both().show(ui, |ui| {
            egui::Grid::new("sections_table")
                .striped(true)
                .spacing([18.0, 6.0])
                .show(ui, |ui| {
                    // Header with clickable sort indicators
                    self.sort_section_header(ui, SectionSort::Index, "#");
                    self.sort_section_header(ui, SectionSort::Name, "Name");
                    self.sort_section_header(ui, SectionSort::Type, "Type");
                    ui.strong("Flags");
                    self.sort_section_header(ui, SectionSort::Address, "Address");
                    self.sort_section_header(ui, SectionSort::Size, "Size");
                    ui.strong("Offset");
                    ui.end_row();

                    for section in filtered {
                        ui.label(section.index.to_string());
                        ui.label(egui::RichText::new(&section.name).monospace().strong());
                        ui.label(format!(
                            "{:#x} ({})",
                            section.section_type,
                            section_type_name(section.section_type)
                        ));
                        ui.label(
                            egui::RichText::new(section_flags_str(section.flags))
                                .color(ui.visuals().weak_text_color()),
                        );
                        ui.monospace(format!("{:#010x}", section.address));
                        ui.monospace(format_bytes(section.size))
                            .on_hover_text(format!("{} bytes ({:#x})", section.size, section.size));
                        ui.monospace(format!("{:#x}", section.offset));
                        ui.end_row();
                    }
                });
        });
    }

    fn sort_section_header(&mut self, ui: &mut egui::Ui, column: SectionSort, label: &str) {
        let is_active = self.section_sort == column;
        let arrow = if is_active {
            if self.section_sort_asc {
                " ▲"
            } else {
                " ▼"
            }
        } else {
            ""
        };
        let text = format!("{label}{arrow}");
        if ui.button(egui::RichText::new(text).strong()).clicked() {
            if is_active {
                self.section_sort_asc = !self.section_sort_asc;
            } else {
                self.section_sort = column;
                self.section_sort_asc = true;
            }
        }
    }

    fn render_segments(&mut self, ui: &mut egui::Ui, binary: &Binary) {
        ui.heading(format!("Program Segments ({})", binary.segments.len()));
        ui.add_space(6.0);

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

        egui::ScrollArea::both().show(ui, |ui| {
            egui::Grid::new("segments_table")
                .striped(true)
                .spacing([18.0, 6.0])
                .show(ui, |ui| {
                    self.sort_segment_header(ui, SegmentSort::Index, "#");
                    self.sort_segment_header(ui, SegmentSort::Type, "Type");
                    self.sort_segment_header(ui, SegmentSort::Flags, "Flags");
                    self.sort_segment_header(ui, SegmentSort::Offset, "Offset");
                    self.sort_segment_header(ui, SegmentSort::Address, "Virtual Address");
                    ui.strong("File Size");
                    self.sort_segment_header(ui, SegmentSort::Size, "Memory Size");
                    ui.strong("Align");
                    ui.end_row();

                    for segment in segments {
                        ui.label(segment.index.to_string());
                        ui.label(format!(
                            "{:#x} ({})",
                            segment.segment_type,
                            segment_type_name(segment.segment_type)
                        ));
                        ui.label(egui::RichText::new(segment_flags_str(segment.flags)).strong());
                        ui.monospace(format!("{:#x}", segment.offset));
                        ui.monospace(format!("{:#010x}", segment.virtual_address));
                        ui.monospace(format_bytes(segment.file_size));
                        ui.monospace(format_bytes(segment.memory_size));
                        ui.monospace(format!("{:#x}", segment.alignment));
                        ui.end_row();
                    }
                });
        });
    }

    fn sort_segment_header(&mut self, ui: &mut egui::Ui, column: SegmentSort, label: &str) {
        let is_active = self.segment_sort == column;
        let arrow = if is_active {
            if self.segment_sort_asc {
                " ▲"
            } else {
                " ▼"
            }
        } else {
            ""
        };
        let text = format!("{label}{arrow}");
        if ui.button(egui::RichText::new(text).strong()).clicked() {
            if is_active {
                self.segment_sort_asc = !self.segment_sort_asc;
            } else {
                self.segment_sort = column;
                self.segment_sort_asc = true;
            }
        }
    }

    fn render_dependencies(&mut self, ui: &mut egui::Ui, binary: &Binary) {
        ui.horizontal(|ui| {
            ui.heading(format!(
                "Dynamic Dependencies ({})",
                binary.dynamic.needed.len()
            ));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let search_box = egui::TextEdit::singleline(&mut self.search_query)
                    .hint_text("🔍 Filter libraries...")
                    .desired_width(220.0);
                ui.add(search_box);
                if !self.search_query.is_empty() && ui.button("Clear").clicked() {
                    self.search_query.clear();
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
                } else {
                    ui.label(
                        egui::RichText::new("None (Statically linked binary)")
                            .color(ui.visuals().weak_text_color()),
                    );
                }
            });

            ui.add_space(10.0);

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

            // Needed Libraries Card
            ui.group(|ui| {
                ui.set_width(ui.available_width());
                ui.heading(egui::RichText::new("Required Shared Libraries (DT_NEEDED)").size(14.0));
                ui.separator();

                let query = self.search_query.to_lowercase();
                let filtered_libs: Vec<&String> = binary
                    .dynamic
                    .needed
                    .iter()
                    .filter(|lib| query.is_empty() || lib.to_lowercase().contains(&query))
                    .collect();

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
        });
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
