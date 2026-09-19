//! Serializable domain models independent of output format.

use std::fmt;

use serde::Serialize;

/// A completed inspection result.
#[derive(Debug, Serialize)]
pub struct Binary {
    /// The recognized file format.
    pub format: FileFormat,
    /// Basic metadata obtained from the filesystem.
    pub file: FileMetadata,
    /// ELF identification and header fields.
    pub elf: ElfHeader,
    /// Sections in file order.
    pub sections: Vec<Section>,
    /// Program segments in file order.
    pub segments: Vec<Segment>,
    /// Dynamic-loader metadata, when present.
    pub dynamic: DynamicInfo,
    /// Extracted static and dynamic symbols.
    pub symbols: Vec<Symbol>,
    /// Security hardening mitigations and exploit protections.
    pub mitigations: SecurityMitigations,
    /// ELF note segments and sections (e.g. Build ID, ABI tags).
    pub notes: Vec<ElfNote>,
    /// Relocation entries.
    pub relocations: Vec<Relocation>,
    /// Cryptographic hashes of the binary file.
    pub hashes: FileHashes,
}

/// Cryptographic hashes computed for the binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileHashes {
    /// SHA-256 hexadecimal hash.
    pub sha256: String,
}

/// Dynamic-loader metadata extracted without loading the binary.
#[derive(Debug, Default, Serialize)]
pub struct DynamicInfo {
    /// The requested ELF interpreter from `PT_INTERP`.
    pub interpreter: Option<String>,
    /// `DT_NEEDED` library names in file order.
    pub needed: Vec<String>,
    /// `DT_RPATH`, if present.
    pub rpath: Option<String>,
    /// `DT_RUNPATH`, if present.
    pub runpath: Option<String>,
    /// Whether dynamic flags request immediate binding.
    pub bind_now: bool,
    /// All parsed dynamic tags and entries.
    pub entries: Vec<DynamicEntry>,
}

/// One entry from the ELF dynamic table (`.dynamic`).
#[derive(Debug, Clone, Serialize)]
pub struct DynamicEntry {
    /// Numeric dynamic tag (e.g. DT_NEEDED, DT_SONAME, DT_RPATH).
    pub tag: u64,
    /// Tag name or human-readable description.
    pub tag_name: String,
    /// Raw numeric value or address.
    pub value: u64,
    /// String representation or decoded library name if applicable.
    pub string_value: Option<String>,
}

/// One ELF section-table entry.
#[derive(Debug, Serialize)]
pub struct Section {
    /// Zero-based section-table index.
    pub index: u16,
    /// Terminal-safe, byte-escaped section name.
    pub name: String,
    /// Numeric ELF section type.
    pub section_type: u32,
    /// Raw ELF section flags.
    pub flags: u64,
    /// Virtual address.
    pub address: u64,
    /// File offset.
    pub offset: u64,
    /// Size in bytes.
    pub size: u64,
    /// Linked section index, when defined by the section type.
    pub link: u32,
    /// Extra section information (`sh_info`).
    pub info: u32,
    /// Alignment requirement in memory (`sh_addralign`).
    pub alignment: u64,
    /// Entry size if the section contains fixed-size records (`sh_entsize`).
    pub entry_size: u64,
    /// Shannon entropy (0.0 to 8.0 bits/byte) of section contents.
    pub entropy: f64,
}

/// One ELF program-header entry.
#[derive(Debug, Serialize)]
pub struct Segment {
    /// Zero-based program-header index.
    pub index: u16,
    /// Numeric ELF segment type.
    pub segment_type: u32,
    /// Raw ELF segment flags.
    pub flags: u32,
    /// File offset.
    pub offset: u64,
    /// Virtual address.
    pub virtual_address: u64,
    /// Bytes occupied in the file.
    pub file_size: u64,
    /// Bytes occupied in memory.
    pub memory_size: u64,
    /// Required alignment.
    pub alignment: u64,
}

/// The inspected file format.
#[derive(Debug, Serialize)]
pub enum FileFormat {
    /// Executable and Linkable Format.
    Elf,
}

/// Safe filesystem metadata included in a report.
#[derive(Debug, Serialize)]
pub struct FileMetadata {
    /// File length in bytes at read time.
    pub size_bytes: u64,
}

/// ELF header fields reported by the inspector.
#[derive(Debug, Serialize)]
pub struct ElfHeader {
    /// ELF word size.
    pub class: ElfClass,
    /// Byte order used by numeric ELF fields.
    pub endianness: Endianness,
    /// ELF object type.
    pub elf_type: ElfType,
    /// Target instruction-set architecture.
    pub machine: Machine,
    /// Target operating-system ABI.
    pub os_abi: OsAbi,
    /// ABI version byte from the ELF identifier.
    pub abi_version: u8,
    /// Program entry address.
    pub entry_point: u64,
    /// Processor-specific flags (`e_flags`).
    pub flags: u32,
    /// Section header table file offset.
    pub section_offset: u64,
    /// Section header entry size.
    pub section_entry_size: u16,
    /// Section count.
    pub section_count: u16,
    /// Program header table file offset.
    pub program_offset: u64,
    /// Program header entry size.
    pub program_entry_size: u16,
    /// Program header count.
    pub program_count: u16,
}

/// ELF class from `EI_CLASS`.
#[derive(Debug, Serialize)]
pub enum ElfClass {
    /// 32-bit ELF.
    Elf32,
    /// 64-bit ELF.
    Elf64,
}

impl fmt::Display for ElfClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Elf32 => "ELF32",
            Self::Elf64 => "ELF64",
        })
    }
}

/// ELF byte order from `EI_DATA`.
#[derive(Debug, Serialize)]
pub enum Endianness {
    /// Little-endian encoding.
    Little,
    /// Big-endian encoding.
    Big,
}

impl fmt::Display for Endianness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Little => "little-endian",
            Self::Big => "big-endian",
        })
    }
}

/// ELF object type.
#[derive(Debug, Serialize)]
pub enum ElfType {
    /// Relocatable object.
    Relocatable,
    /// Executable object.
    Executable,
    /// Shared object.
    Shared,
    /// Core dump.
    Core,
    /// An unrecognized standardized or processor-specific value.
    Other(u16),
}

impl fmt::Display for ElfType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Relocatable => formatter.write_str("relocatable"),
            Self::Executable => formatter.write_str("executable"),
            Self::Shared => formatter.write_str("shared object"),
            Self::Core => formatter.write_str("core"),
            Self::Other(value) => write!(formatter, "other ({value:#x})"),
        }
    }
}

/// Common ELF machine values, retaining unknown values losslessly.
#[derive(Debug, Serialize)]
pub enum Machine {
    /// Intel 80386.
    X86,
    /// AMD x86-64.
    X86_64,
    /// 32-bit ARM.
    Arm,
    /// AArch64.
    Aarch64,
    /// RISC-V.
    RiscV,
    /// An unrecognized machine value.
    Other(u16),
}

impl fmt::Display for Machine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86 => formatter.write_str("Intel 80386"),
            Self::X86_64 => formatter.write_str("x86-64"),
            Self::Arm => formatter.write_str("ARM"),
            Self::Aarch64 => formatter.write_str("AArch64"),
            Self::RiscV => formatter.write_str("RISC-V"),
            Self::Other(value) => write!(formatter, "other ({value:#x})"),
        }
    }
}

/// ELF OS ABI value, retaining unknown values losslessly.
#[derive(Debug, Serialize)]
pub enum OsAbi {
    /// System V ABI.
    SystemV,
    /// GNU extension ABI.
    Gnu,
    /// Linux ABI alias.
    Linux,
    /// FreeBSD ABI.
    FreeBsd,
    /// An unrecognized OS ABI value.
    Other(u8),
}

impl fmt::Display for OsAbi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SystemV => formatter.write_str("System V"),
            Self::Gnu => formatter.write_str("GNU"),
            Self::Linux => formatter.write_str("Linux"),
            Self::FreeBsd => formatter.write_str("FreeBSD"),
            Self::Other(value) => write!(formatter, "other ({value:#x})"),
        }
    }
}

/// Security hardening analysis for the inspected binary (checksec).
#[derive(Debug, Clone, Serialize)]
pub struct SecurityMitigations {
    /// Relocation Read-Only (RELRO) level.
    pub relro: Relro,
    /// Whether stack canary protection symbols are present.
    pub stack_canary: bool,
    /// Whether the stack segment is marked non-executable (NX/DEP).
    pub nx: bool,
    /// Position Independent Executable (PIE) status.
    pub pie: PieStatus,
    /// List of fortified library call symbols detected (e.g. `__printf_chk`).
    pub fortified_functions: Vec<String>,
    /// Count of program segments that have both Write and Execute permissions.
    pub rwx_segments: usize,
    /// Whether insecure runtime search paths (RPATH/RUNPATH) were detected.
    pub has_insecure_rpath: bool,
}

/// RELRO protection status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Relro {
    /// No RELRO segment present.
    None,
    /// GNU_RELRO segment present without immediate binding.
    Partial,
    /// GNU_RELRO segment present with BIND_NOW enabled.
    Full,
}

impl fmt::Display for Relro {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => formatter.write_str("No RELRO"),
            Self::Partial => formatter.write_str("Partial RELRO"),
            Self::Full => formatter.write_str("Full RELRO"),
        }
    }
}

/// Position Independent Executable (PIE) status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PieStatus {
    /// Standard executable built with fixed base address.
    NoPie,
    /// Position Independent Executable.
    Pie,
    /// Shared object / dynamic shared library.
    Dso,
}

impl fmt::Display for PieStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPie => formatter.write_str("No PIE"),
            Self::Pie => formatter.write_str("PIE enabled"),
            Self::Dso => formatter.write_str("Dynamic Shared Object (DSO)"),
        }
    }
}

/// Origin table for a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SymbolTableKind {
    /// Static symbol table (`.symtab`).
    Static,
    /// Dynamic symbol table (`.dynsym`).
    Dynamic,
}

impl fmt::Display for SymbolTableKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static => formatter.write_str(".symtab"),
            Self::Dynamic => formatter.write_str(".dynsym"),
        }
    }
}

/// Symbol type classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SymbolType {
    /// Symbol type is not specified.
    NoType,
    /// Symbol is associated with a data object.
    Object,
    /// Symbol is associated with a function or executable code.
    Func,
    /// Symbol is associated with a section.
    Section,
    /// Symbol specifies the source file associated with the object.
    File,
    /// Symbol labels an uninitialized common block.
    Common,
    /// Symbol specifies a Thread-Local Storage entity.
    Tls,
    /// GNU indirect function.
    GnuIfunc,
    /// Unrecognized symbol type.
    Other(u8),
}

impl fmt::Display for SymbolType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoType => formatter.write_str("NOTYPE"),
            Self::Object => formatter.write_str("OBJECT"),
            Self::Func => formatter.write_str("FUNC"),
            Self::Section => formatter.write_str("SECTION"),
            Self::File => formatter.write_str("FILE"),
            Self::Common => formatter.write_str("COMMON"),
            Self::Tls => formatter.write_str("TLS"),
            Self::GnuIfunc => formatter.write_str("GNU_IFUNC"),
            Self::Other(v) => write!(formatter, "OTHER({v})"),
        }
    }
}

/// Symbol binding attribute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SymbolBinding {
    /// Local symbol, not visible outside its object file.
    Local,
    /// Global symbol, visible to all object files being combined.
    Global,
    /// Weak symbol, similar to global but with lower precedence.
    Weak,
    /// GNU unique symbol.
    GnuUnique,
    /// Unrecognized symbol binding.
    Other(u8),
}

impl fmt::Display for SymbolBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => formatter.write_str("LOCAL"),
            Self::Global => formatter.write_str("GLOBAL"),
            Self::Weak => formatter.write_str("WEAK"),
            Self::GnuUnique => formatter.write_str("GNU_UNIQUE"),
            Self::Other(v) => write!(formatter, "OTHER({v})"),
        }
    }
}

/// Symbol visibility attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SymbolVisibility {
    /// Default visibility as specified by symbol binding.
    Default,
    /// Internal visibility (processor-specific).
    Internal,
    /// Hidden visibility (not visible to other modules).
    Hidden,
    /// Protected visibility (not preemptible by other modules).
    Protected,
}

impl fmt::Display for SymbolVisibility {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => formatter.write_str("DEFAULT"),
            Self::Internal => formatter.write_str("INTERNAL"),
            Self::Hidden => formatter.write_str("HIDDEN"),
            Self::Protected => formatter.write_str("PROTECTED"),
        }
    }
}

/// A parsed symbol from an ELF symbol table.
#[derive(Debug, Clone, Serialize)]
pub struct Symbol {
    /// Zero-based index within the symbol table.
    pub index: usize,
    /// Symbol name.
    pub name: String,
    /// Symbol value / address.
    pub value: u64,
    /// Symbol size in bytes.
    pub size: u64,
    /// Symbol type.
    pub sym_type: SymbolType,
    /// Symbol binding.
    pub binding: SymbolBinding,
    /// Symbol visibility.
    pub visibility: SymbolVisibility,
    /// Section index defining the symbol, or None if undefined (`SHN_UNDEF`).
    pub section_index: Option<u16>,
    /// Whether the symbol is imported (undefined).
    pub is_import: bool,
    /// Whether the symbol is exported (defined with global or weak binding).
    pub is_export: bool,
    /// Originating symbol table.
    pub table: SymbolTableKind,
}

/// A parsed ELF note record.
#[derive(Debug, Clone, Serialize)]
pub struct ElfNote {
    /// Note owner name (e.g. "GNU", "Go").
    pub name: String,
    /// Numeric note type.
    pub note_type: u32,
    /// Human-readable note description or decoded payload.
    pub description: String,
    /// Build ID hex string if this note is `NT_GNU_BUILD_ID`.
    pub build_id: Option<String>,
    /// Minimum OS version string if this note is `NT_GNU_ABI_TAG`.
    pub abi_tag: Option<String>,
    /// GNU properties if this note is `NT_GNU_PROPERTY_TYPE_0`.
    pub properties: Vec<String>,
}

/// A relocation entry parsed from `SHT_REL` or `SHT_RELA`.
#[derive(Debug, Clone, Serialize)]
pub struct Relocation {
    /// Section containing the relocation.
    pub section_name: String,
    /// Offset where relocation should be applied.
    pub offset: u64,
    /// Numeric relocation type.
    pub rel_type: u32,
    /// Symbol index referenced by relocation.
    pub symbol_index: u32,
    /// Symbol name if resolved.
    pub symbol_name: Option<String>,
    /// Addend for RELA relocations.
    pub addend: Option<i64>,
}
