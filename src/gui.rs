//! Native desktop interface for BinaryInspector.

#![forbid(unsafe_code)]

use std::{
    path::PathBuf,
    sync::mpsc::{self, Receiver},
    time::Duration,
};

use binary_inspector::{error::AppError, inspect, model::Binary};
use eframe::egui;

fn main() -> eframe::Result {
    eframe::run_native(
        "BinaryInspector",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([1040.0, 720.0]),
            ..Default::default()
        },
        Box::new(|_| Ok(Box::<InspectorApp>::default())),
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

enum Inspection {
    Empty,
    Loading(Receiver<(PathBuf, Result<Binary, AppError>)>),
    Ready { path: PathBuf, binary: Binary },
    Failed { path: PathBuf, error: AppError },
}

struct InspectorApp {
    inspection: Inspection,
    view: View,
}

impl Default for InspectorApp {
    fn default() -> Self {
        Self {
            inspection: Inspection::Empty,
            view: View::default(),
        }
    }
}

impl InspectorApp {
    fn inspect(&mut self, path: PathBuf) {
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn({
            let path = path.clone();
            move || {
                let _ = sender.send((path.clone(), inspect(&path)));
            }
        });
        self.inspection = Inspection::Loading(receiver);
        self.view = View::Overview;
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
            .set_title("Inspect an ELF binary")
            .pick_file()
        {
            self.inspect(path);
        }
    }
}

impl eframe::App for InspectorApp {
    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        let context = ui.ctx().clone();
        let dropped = context.input(|input| {
            input
                .raw
                .dropped_files
                .first()
                .map(|file| file.path().to_path_buf())
        });
        if let Some(path) = dropped {
            self.inspect(path);
        }
        self.poll(&context);

        let mut choose_file = false;
        ui.horizontal(|ui| {
            ui.heading("BinaryInspector");
            ui.separator();
            choose_file = ui.button("Open binary").clicked();
            if let Inspection::Loading(_) = self.inspection {
                ui.spinner();
                ui.label("Inspecting safely…");
            }
        });
        ui.separator();

        match &self.inspection {
            Inspection::Empty => ui.vertical_centered(|ui| {
                ui.add_space(180.0);
                ui.heading("Inspect an ELF binary");
                ui.label(
                    "Open a file or drag one into this window. BinaryInspector never executes it.",
                );
                ui.add_space(12.0);
                choose_file |= ui.button("Open binary").clicked();
            }),
            Inspection::Loading(_) => ui.centered_and_justified(|ui| {
                ui.spinner();
            }),
            Inspection::Failed { path, error } => ui.vertical(|ui| {
                ui.heading("Could not inspect file");
                ui.label(path.display().to_string());
                ui.colored_label(egui::Color32::from_rgb(190, 45, 45), error.to_string());
                choose_file |= ui.button("Choose another file").clicked();
            }),
            Inspection::Ready { path, binary } => ui.horizontal_top(|ui| {
                ui.vertical(|ui| {
                    ui.set_width(180.0);
                    ui.label(path.display().to_string());
                    ui.separator();
                    ui.selectable_value(&mut self.view, View::Overview, "Overview");
                    ui.selectable_value(&mut self.view, View::Sections, "Sections");
                    ui.selectable_value(&mut self.view, View::Segments, "Segments");
                    ui.selectable_value(&mut self.view, View::Dependencies, "Dependencies");
                });
                ui.separator();
                ui.vertical(|ui| match self.view {
                    View::Overview => overview(ui, binary),
                    View::Sections => sections(ui, binary),
                    View::Segments => segments(ui, binary),
                    View::Dependencies => dependencies(ui, binary),
                });
            }),
        };
        if choose_file {
            self.choose_file();
        }
    }
}

fn overview(ui: &mut egui::Ui, binary: &Binary) {
    ui.heading("Overview");
    egui::Grid::new("overview")
        .num_columns(2)
        .spacing([24.0, 10.0])
        .show(ui, |ui| {
            row(ui, "Format", "ELF");
            row(
                ui,
                "File size",
                &format!("{} bytes", binary.file.size_bytes),
            );
            row(ui, "Class", &binary.elf.class.to_string());
            row(ui, "Endianness", &binary.elf.endianness.to_string());
            row(ui, "Type", &binary.elf.elf_type.to_string());
            row(ui, "Machine", &binary.elf.machine.to_string());
            row(ui, "OS ABI", &binary.elf.os_abi.to_string());
            row(ui, "Entry point", &format!("{:#x}", binary.elf.entry_point));
        });
}

fn row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.strong(label);
    ui.label(value);
    ui.end_row();
}

fn sections(ui: &mut egui::Ui, binary: &Binary) {
    ui.heading(format!("Sections ({})", binary.sections.len()));
    egui::ScrollArea::both().show(ui, |ui| {
        egui::Grid::new("sections").striped(true).show(ui, |ui| {
            ui.strong("#");
            ui.strong("Name");
            ui.strong("Type");
            ui.strong("Address");
            ui.strong("Size");
            ui.end_row();
            for section in &binary.sections {
                ui.label(section.index.to_string());
                ui.label(&section.name);
                ui.monospace(format!("{:#x}", section.section_type));
                ui.monospace(format!("{:#x}", section.address));
                ui.monospace(format!("{:#x}", section.size));
                ui.end_row();
            }
        });
    });
}

fn segments(ui: &mut egui::Ui, binary: &Binary) {
    ui.heading(format!("Segments ({})", binary.segments.len()));
    egui::ScrollArea::both().show(ui, |ui| {
        egui::Grid::new("segments").striped(true).show(ui, |ui| {
            ui.strong("#");
            ui.strong("Type");
            ui.strong("Offset");
            ui.strong("Virtual address");
            ui.strong("Memory size");
            ui.end_row();
            for segment in &binary.segments {
                ui.label(segment.index.to_string());
                ui.monospace(format!("{:#x}", segment.segment_type));
                ui.monospace(format!("{:#x}", segment.offset));
                ui.monospace(format!("{:#x}", segment.virtual_address));
                ui.monospace(format!("{:#x}", segment.memory_size));
                ui.end_row();
            }
        });
    });
}

fn dependencies(ui: &mut egui::Ui, binary: &Binary) {
    ui.heading("Dependencies");
    if let Some(interpreter) = &binary.dynamic.interpreter {
        ui.label(format!("Interpreter: {interpreter}"));
    }
    if let Some(rpath) = &binary.dynamic.rpath {
        ui.label(format!("RPATH: {rpath}"));
    }
    if let Some(runpath) = &binary.dynamic.runpath {
        ui.label(format!("RUNPATH: {runpath}"));
    }
    ui.add_space(8.0);
    for library in &binary.dynamic.needed {
        ui.monospace(library);
    }
    if binary.dynamic.needed.is_empty() {
        ui.label("No dynamic dependencies found.");
    }
}
