//! Build script: generates ARM A64 x18 detection table from authoritative XML spec.
//!
//! Parses `data/encoding/*.xml` (ARM A64 ISA XML, vendored from ARM spec 2026-03)
//! and generates a Rust source file with a decode table for `references_x18()`.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

/// A GPR register field found in an instruction encoding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct GprField {
    name: String,
    lsb: u32,
    width: u32,
}

/// A parsed instruction encoding with mask/value and GPR fields.
#[derive(Debug, Clone)]
struct ParsedEncoding {
    name: String,
    mask: u32,
    value: u32,
    gpr_fields: Vec<GprField>,
    emul_class: u8,
}

/// Map a psname decode path (group.subgroup) to an EmulClass discriminant.
/// Must match the EmulClass enum in decoder.rs.
fn psname_to_emul_class(psname: &str) -> u8 {
    // Extract group.subgroup from "A64.group.subgroup.encoding"
    let parts: Vec<&str> = psname.split('.').collect();
    if parts.len() < 3 {
        return 255; // Other
    }
    let key = format!("{}.{}", parts[1], parts[2]);
    match key.as_str() {
        // Data Processing — Immediate
        "dpimm.addsub_imm" => 0,      // AddSubImm
        "dpimm.log_imm" => 1,         // LogicalImm
        "dpimm.movewide" => 2,        // MoveWide
        "dpimm.bitfield" => 3,        // Bitfield
        "dpimm.extract" => 4,         // Extract
        "dpimm.pcreladdr" => 5,       // PcRelAddr
        // Data Processing — Register
        "dpreg.log_shift" => 6,       // LogicalShiftedReg
        "dpreg.addsub_shift" => 7,    // AddSubShiftedReg
        "dpreg.addsub_ext" => 8,      // AddSubExtReg
        "dpreg.addsub_carry" => 9,    // AddSubCarry
        "dpreg.condsel" => 10,        // CondSelect
        "dpreg.dp_2src" => 11,        // DataProc2Src
        "dpreg.dp_3src" => 12,        // DataProc3Src
        "dpreg.condcmp_reg" => 13,    // CondCompareReg
        "dpreg.condcmp_imm" => 14,    // CondCompareImm
        "dpreg.dp_1src" => 15,        // DataProc1Src
        // Load/Store
        "ldst.ldst_pos" => 16,        // LdrStrUnsignedImm
        "ldst.ldst_immpost" => 17,    // LdrStrPrePost
        "ldst.ldst_immpre" => 17,     // LdrStrPrePost (same handler)
        "ldst.ldst_unscaled" => 18,   // LdrStrUnscaled
        "ldst.ldst_regoff" => 19,     // LdrStrRegOffset
        "ldst.ldstpair_off" => 20,    // LdpStp
        "ldst.ldstpair_post" => 20,   // LdpStp (same handler)
        "ldst.ldstpair_pre" => 20,    // LdpStp (same handler)
        "ldst.loadlit" => 21,         // LoadLiteral
        "ldst.ldstnapair_offs" => 20, // LdpStp (no-allocate pair, same shape)
        // Branches
        "control.compbranch" => 22,   // CompareBranch (CBZ/CBNZ)
        "control.testbranch" => 23,   // TestBranch (TBZ/TBNZ)
        // FP ↔ GPR conversion
        "simd_dp.float2int" => 24,    // FloatGprConvert (FMOV etc.)
        // Load/store exclusive and atomics
        "ldst.ldstexclr" => 25,       // LoadStoreExclusive
        "ldst.ldstexclp" => 25,       // LoadStoreExclusive
        "ldst.memop" => 26,           // AtomicMemOp
        "ldst.ldstord" => 27,         // LoadStoreOrdered (LDAR/STLR)
        "ldst.ldapstl_unscaled" => 27, // LoadStoreOrdered
        // Catch-all
        _ => 255,                     // Other
    }
}

/// Standard GPR register field names in ARM A64.
const GPR_FIELD_NAMES: &[&str] = &["Rd", "Rn", "Rm", "Rt", "Rt2", "Ra", "Rs"];

fn main() {
    println!("cargo:rerun-if-changed=data/encoding/");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=FAKELINUX_REGEN_DECODER");

    // The decode table is committed under src/generated/, so the emulator builds
    // and works out of the box without the ARM spec. Regeneration is opt-in: it
    // happens only when FAKELINUX_REGEN_DECODER is set AND the ARM A64 ISA XML is
    // present in data/encoding/ (install it with scripts/fetch-arm-isa-xml.sh).
    // Otherwise the committed table is used as-is.
    let table_path = Path::new("src/generated/x18_table.rs");
    let tests_path = Path::new("src/generated/x18_tests.rs");

    let regen = std::env::var_os("FAKELINUX_REGEN_DECODER").is_some();
    if !regen {
        if !table_path.exists() {
            eprintln!("Warning: no committed decode table found; writing an empty one. \
                       Set FAKELINUX_REGEN_DECODER=1 with data/encoding/ populated to generate it.");
            write_empty_table(table_path, tests_path);
        }
        return;
    }

    let encoding_dir = Path::new("data/encoding");
    let have_xml = encoding_dir.exists()
        && fs::read_dir(encoding_dir).map_or(false, |rd| {
            rd.filter_map(|e| e.ok())
                .any(|e| e.path().extension().map_or(false, |x| x == "xml"))
        });
    if !have_xml {
        eprintln!("Warning: FAKELINUX_REGEN_DECODER is set but data/encoding/ has no XML. \
                   Run scripts/fetch-arm-isa-xml.sh first. Keeping the committed table.");
        if !table_path.exists() {
            write_empty_table(table_path, tests_path);
        }
        return;
    }
    eprintln!("build.rs: FAKELINUX_REGEN_DECODER set — regenerating decode table from data/encoding/");

    let mut all_encodings: Vec<ParsedEncoding> = Vec::new();
    let mut files_parsed = 0u32;
    let mut files_skipped = 0u32;

    let mut xml_files: Vec<_> = fs::read_dir(encoding_dir)
        .expect("cannot read data/encoding/")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "xml"))
        .collect();
    xml_files.sort_by_key(|e| e.file_name());

    for entry in &xml_files {
        let path = entry.path();
        let fname = path.file_name().unwrap().to_str().unwrap();

        // Skip non-instruction files
        if fname == "encodingindex.xml"
            || fname == "shared_pseudocode.xml"
            || fname == "notice.xml"
            || fname.starts_with("constraint_")
            || fname.starts_with("shared_")
        {
            continue;
        }

        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Quick text filters before parsing XML
        if !content.contains("<instructionsection") {
            continue;
        }
        // Skip alias pages (they duplicate primary encodings)
        if content.contains("type=\"alias\"") {
            files_skipped += 1;
            continue;
        }

        let doc = match roxmltree::Document::parse_with_options(
            &content,
            roxmltree::ParsingOptions {
                allow_dtd: true,
                ..Default::default()
            },
        ) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Warning: failed to parse {}: {}", fname, e);
                continue;
            }
        };

        let root = doc.root_element();
        if root.tag_name().name() != "instructionsection" {
            continue;
        }

        // Get instruction class from docvars
        let instr_class = get_docvar(&root, "instr-class").unwrap_or_default();

        // Skip SVE/SME — not relevant for this project's workloads
        if matches!(
            instr_class.as_str(),
            "sve" | "sve2" | "mortlach" | "mortlach2"
        ) {
            files_skipped += 1;
            continue;
        }

        // Parse explanation section to determine GPR fields for non-general classes
        let gpr_field_names_from_explanations = if instr_class != "general" {
            parse_gpr_from_explanations(&root)
        } else {
            HashSet::new()
        };

        // Process each iclass
        for classes_node in root.children().filter(|n| n.tag_name().name() == "classes") {
            for iclass in classes_node
                .children()
                .filter(|n| n.tag_name().name() == "iclass")
            {
                // Get iclass-level instr-class (may override top-level)
                let iclass_class =
                    get_docvar(&iclass, "instr-class").unwrap_or_else(|| instr_class.clone());
                if matches!(
                    iclass_class.as_str(),
                    "sve" | "sve2" | "mortlach" | "mortlach2"
                ) {
                    continue;
                }

                // Find regdiagram
                let regdiagram = match iclass
                    .children()
                    .find(|n| n.tag_name().name() == "regdiagram")
                {
                    Some(rd) => rd,
                    None => continue,
                };

                // Parse base mask/value and field positions from regdiagram
                let (base_mask, base_value, fields) = parse_regdiagram(&regdiagram);

                // Extract emulation class from psname decode path
                let psname = regdiagram.attribute("psname").unwrap_or("");
                let emul_class = psname_to_emul_class(psname);

                // Determine GPR fields
                let gpr_fields: Vec<GprField> = if iclass_class == "general" {
                    // For general class, all standard register fields are GPR
                    fields
                        .iter()
                        .filter(|f| GPR_FIELD_NAMES.contains(&f.name.as_str()))
                        .cloned()
                        .collect()
                } else {
                    // For other classes, use explanation-based detection
                    fields
                        .iter()
                        .filter(|f| gpr_field_names_from_explanations.contains(&f.name))
                        .cloned()
                        .collect()
                };

                // Process each encoding within this iclass
                let encodings: Vec<_> = iclass
                    .children()
                    .filter(|n| n.tag_name().name() == "encoding")
                    .collect();

                if encodings.is_empty() {
                    // No sub-encodings, use iclass-level entry
                    if !gpr_fields.is_empty() || instr_class == "general" {
                        all_encodings.push(ParsedEncoding {
                            name: iclass
                                .attribute("id")
                                .unwrap_or("unknown")
                                .to_string(),
                            mask: base_mask,
                            value: base_value,
                            gpr_fields: gpr_fields.clone(),
                            emul_class,
                        });
                    }
                } else {
                    // Collect all encodings and check if they share the same GPR fields
                    let mut encoding_entries: Vec<ParsedEncoding> = Vec::new();

                    for enc in &encodings {
                        let enc_name = enc.attribute("name").unwrap_or("unknown");
                        let (enc_mask, enc_value) =
                            apply_encoding_overrides(base_mask, base_value, enc, &regdiagram);

                        // Sanity check: value must match mask
                        debug_assert_eq!(
                            enc_value & enc_mask,
                            enc_value,
                            "Encoding {} has value bits outside mask",
                            enc_name
                        );

                        encoding_entries.push(ParsedEncoding {
                            name: enc_name.to_string(),
                            mask: enc_mask,
                            value: enc_value,
                            gpr_fields: gpr_fields.clone(),
                            emul_class,
                        });
                    }

                    // If all encodings within this iclass share the same GPR fields,
                    // use the broader iclass-level mask/value (fewer entries)
                    let all_same_gpr = encoding_entries
                        .iter()
                        .all(|e| e.gpr_fields == gpr_fields);

                    if all_same_gpr && !gpr_fields.is_empty() {
                        // Use iclass-level entry (broader match, fewer entries)
                        all_encodings.push(ParsedEncoding {
                            name: format!(
                                "{}",
                                iclass.attribute("id").unwrap_or("unknown")
                            ),
                            mask: base_mask,
                            value: base_value,
                            gpr_fields,
                            emul_class,
                        });
                    } else {
                        // Use per-encoding entries
                        for e in encoding_entries {
                            if !e.gpr_fields.is_empty() {
                                all_encodings.push(e);
                            }
                        }
                    }
                }

                files_parsed += 1;
            }
        }
    }

    // Sanity-check all entries
    let mut bad_entries = Vec::new();
    for enc in &all_encodings {
        if (enc.value & enc.mask) != enc.value {
            bad_entries.push(format!(
                "{}: mask={:#010x} value={:#010x} (value & mask = {:#010x})",
                enc.name,
                enc.mask,
                enc.value,
                enc.value & enc.mask
            ));
        }
    }
    if !bad_entries.is_empty() {
        eprintln!(
            "WARNING: {} encodings have value bits outside mask:",
            bad_entries.len()
        );
        for b in &bad_entries[..bad_entries.len().min(10)] {
            eprintln!("  {}", b);
        }
    }

    // Sort by descending mask specificity (most mask bits set first)
    // Tie-break by mask value descending for determinism
    all_encodings.sort_by(|a, b| {
        let a_bits = a.mask.count_ones();
        let b_bits = b.mask.count_ones();
        b_bits
            .cmp(&a_bits)
            .then(b.mask.cmp(&a.mask))
            .then(b.value.cmp(&a.value))
    });

    // Deduplicate: remove entries with identical (mask, value) — keep first (most specific)
    let mut seen = HashSet::new();
    all_encodings.retain(|e| seen.insert((e.mask, e.value)));

    eprintln!(
        "build.rs: generated {} table entries from {} iclasses ({} files skipped)",
        all_encodings.len(),
        files_parsed,
        files_skipped
    );

    if all_encodings.is_empty() {
        eprintln!("Warning: parsed 0 encodings from data/encoding/; keeping committed table");
        return;
    }
    write_generated_table(&all_encodings, table_path);
    write_generated_tests(&all_encodings, tests_path);
}

/// Write `content` to `path` only if it differs from what's already there.
/// Avoids rebuild loops and needless git churn when regeneration is a no-op.
fn write_if_changed(path: &Path, content: &str) {
    if fs::read_to_string(path).ok().as_deref() == Some(content) {
        eprintln!("build.rs: {} unchanged", path.display());
        return;
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("cannot create generated dir");
    }
    fs::write(path, content).expect("cannot write generated file");
    eprintln!("build.rs: wrote {}", path.display());
}

/// Parse a <regdiagram> element to extract (mask, value, fields).
fn parse_regdiagram(
    regdiagram: &roxmltree::Node,
) -> (u32, u32, Vec<GprField>) {
    let mut mask: u32 = 0;
    let mut value: u32 = 0;
    let mut fields: Vec<GprField> = Vec::new();

    for boxn in regdiagram
        .children()
        .filter(|n| n.tag_name().name() == "box")
    {
        let hibit: u32 = boxn
            .attribute("hibit")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let width: u32 = boxn
            .attribute("width")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        let lsb = hibit + 1 - width;

        // Collect <c> children
        let c_nodes: Vec<_> = boxn
            .children()
            .filter(|n| n.tag_name().name() == "c")
            .collect();

        // Determine fixed bits from <c> elements
        if !c_nodes.is_empty() {
            // Check if this is a colspan (variable) or individual bit values
            if c_nodes.len() == 1 && c_nodes[0].attribute("colspan").is_some() {
                // All variable — don't set mask bits
            } else {
                // Individual <c> elements, one per bit from MSB to LSB
                for (i, c) in c_nodes.iter().enumerate() {
                    let bit_pos = hibit as i32 - i as i32;
                    if bit_pos < 0 || bit_pos > 31 {
                        continue;
                    }
                    let bit_pos = bit_pos as u32;
                    let text = c.text().unwrap_or("").trim();
                    match text {
                        "0" => {
                            mask |= 1 << bit_pos;
                            // value bit stays 0
                        }
                        "1" => {
                            mask |= 1 << bit_pos;
                            value |= 1 << bit_pos;
                        }
                        _ => {
                            // "x", "", or other → variable, don't set mask
                        }
                    }
                }
            }
        }

        // Record named fields that might be register operands
        if let Some(name) = boxn.attribute("name") {
            if GPR_FIELD_NAMES.contains(&name)
                || name == "Xm"
                || name == "Xn"
                || name == "Xt"
            {
                fields.push(GprField {
                    name: name.to_string(),
                    lsb,
                    width,
                });
            }
        }
    }

    (mask, value, fields)
}

/// Apply encoding-level box overrides to the base mask/value.
fn apply_encoding_overrides(
    base_mask: u32,
    base_value: u32,
    encoding: &roxmltree::Node,
    _parent_regdiagram: &roxmltree::Node,
) -> (u32, u32) {
    let mut mask = base_mask;
    let mut value = base_value;

    for boxn in encoding
        .children()
        .filter(|n| n.tag_name().name() == "box")
    {
        let hibit: u32 = match boxn.attribute("hibit").and_then(|s| s.parse().ok()) {
            Some(h) => h,
            None => continue,
        };

        let c_nodes: Vec<_> = boxn
            .children()
            .filter(|n| n.tag_name().name() == "c")
            .collect();

        for (i, c) in c_nodes.iter().enumerate() {
            let bit_pos = hibit as i32 - i as i32;
            if bit_pos < 0 || bit_pos > 31 {
                continue;
            }
            let bit_pos = bit_pos as u32;
            let text = c.text().unwrap_or("").trim();
            match text {
                "0" => {
                    mask |= 1 << bit_pos;
                    value &= !(1 << bit_pos);
                }
                "1" => {
                    mask |= 1 << bit_pos;
                    value |= 1 << bit_pos;
                }
                _ => {
                    // Empty <c/> in encoding inherits parent (no change)
                }
            }
        }
    }

    (mask, value)
}

/// Parse <explanations> to find which register fields are GPR.
/// Returns a set of field names (e.g., "Rn", "Rd") that are GPR.
fn parse_gpr_from_explanations(root: &roxmltree::Node) -> HashSet<String> {
    let mut gpr_names = HashSet::new();

    for explanations in root
        .children()
        .filter(|n| n.tag_name().name() == "explanations")
    {
        for explanation in explanations
            .children()
            .filter(|n| n.tag_name().name() == "explanation")
        {
            for account in explanation
                .children()
                .filter(|n| n.tag_name().name() == "account")
            {
                let encoded_in = match account.attribute("encodedin") {
                    Some(e) => e.to_string(),
                    None => continue,
                };

                // Only care about standard register field names
                if !GPR_FIELD_NAMES.contains(&encoded_in.as_str()) {
                    continue;
                }

                // Check if any text in the account subtree mentions "general-purpose"
                let full_text = collect_text(&account);
                if full_text.contains("general-purpose") {
                    gpr_names.insert(encoded_in);
                }
            }
        }
    }

    gpr_names
}

/// Recursively collect all text content from a node and its children.
fn collect_text(node: &roxmltree::Node) -> String {
    let mut text = String::new();
    for child in node.children() {
        if child.is_text() {
            text.push_str(child.text().unwrap_or(""));
        } else {
            text.push_str(&collect_text(&child));
        }
    }
    text
}

/// Get a docvar value from within a node's <docvars> children.
fn get_docvar(node: &roxmltree::Node, key: &str) -> Option<String> {
    for docvars in node
        .children()
        .filter(|n| n.tag_name().name() == "docvars")
    {
        for docvar in docvars
            .children()
            .filter(|n| n.tag_name().name() == "docvar")
        {
            if docvar.attribute("key") == Some(key) {
                return docvar.attribute("value").map(|s| s.to_string());
            }
        }
    }
    None
}

/// Generate the decode table source and write it to `dest_path` (committed file).
fn write_generated_table(encodings: &[ParsedEncoding], dest_path: &Path) {
    let mut f = String::new();
    let f = &mut f;

    writeln!(
        f,
        "// Auto-generated from the ARM A64 ISA XML spec."
    )
    .unwrap();
    writeln!(f, "// DO NOT EDIT — regenerate with FAKELINUX_REGEN_DECODER=1 (see data/encoding/README.md).").unwrap();
    writeln!(f, "//").unwrap();
    writeln!(f, "// {} entries", encodings.len()).unwrap();
    writeln!(f).unwrap();

    writeln!(f, "/// Entry in the generated x18 detection table.").unwrap();
    writeln!(f, "#[derive(Debug, Clone, Copy)]").unwrap();
    writeln!(f, "pub struct GenEntry {{").unwrap();
    writeln!(f, "    pub mask: u32,").unwrap();
    writeln!(f, "    pub value: u32,").unwrap();
    writeln!(
        f,
        "    /// LSB positions of GPR fields (5 bits each). 0xFF = sentinel (no more fields)."
    )
    .unwrap();
    writeln!(f, "    pub gpr_lsbs: [u8; 5],").unwrap();
    writeln!(f, "    /// Emulation class discriminant (see EmulClass enum in decoder.rs).").unwrap();
    writeln!(f, "    pub emul_class: u8,").unwrap();
    writeln!(f, "    pub name: &'static str,").unwrap();
    writeln!(f, "}}").unwrap();
    writeln!(f).unwrap();

    writeln!(
        f,
        "pub static GEN_TABLE: &[GenEntry] = &["
    )
    .unwrap();

    for enc in encodings {
        let mut lsbs = [0xFFu8; 5];
        for (i, field) in enc.gpr_fields.iter().take(5).enumerate() {
            lsbs[i] = field.lsb as u8;
        }

        writeln!(
            f,
            "    GenEntry {{ mask: {:#010x}, value: {:#010x}, gpr_lsbs: [{}, {}, {}, {}, {}], emul_class: {}, name: {:?} }},",
            enc.mask,
            enc.value,
            lsbs[0],
            lsbs[1],
            lsbs[2],
            lsbs[3],
            lsbs[4],
            enc.emul_class,
            enc.name
        )
        .unwrap();
    }

    writeln!(f, "];").unwrap();

    write_if_changed(dest_path, f);
}

/// Generate spot-check tests and write them to `dest_path` (committed file).
fn write_generated_tests(encodings: &[ParsedEncoding], dest_path: &Path) {
    let mut f = String::new();
    let f = &mut f;

    writeln!(f, "// Auto-generated spot-check tests from the ARM A64 ISA XML spec.").unwrap();
    writeln!(f, "// DO NOT EDIT.").unwrap();
    writeln!(f).unwrap();

    let mut test_count = 0;
    let mut seen_values = HashSet::new();

    for enc in encodings {
        if enc.gpr_fields.is_empty() {
            continue;
        }
        // Generate one test per encoding that has GPR fields (limit to avoid huge test suite)
        if test_count >= 50 {
            break;
        }
        // Skip duplicates
        if !seen_values.insert((enc.mask, enc.value)) {
            continue;
        }

        // Build a test instruction: start with the value (fixed bits), set first GPR field to 18
        let field = &enc.gpr_fields[0];
        let field_mask = 0x1Fu32 << field.lsb;
        // Skip if the GPR field bits overlap with fixed bits in the mask
        if (enc.mask & field_mask) != 0 {
            continue; // field is (partially) fixed, can't freely set to 18
        }
        let instr_with_x18 = enc.value | (18u32 << field.lsb);
        // Verify the constructed instruction matches its own mask
        if (instr_with_x18 & enc.mask) != enc.value {
            continue;
        }

        let test_name = enc
            .name
            .replace(|c: char| !c.is_alphanumeric() && c != '_', "_")
            .to_lowercase();

        writeln!(f, "#[test]").unwrap();
        writeln!(
            f,
            "fn test_gen_{}_{}_{}_x18() {{",
            test_name, field.name.to_lowercase(), test_count
        )
        .unwrap();
        writeln!(
            f,
            "    // {}: {}@{} = x18",
            enc.name, field.name, field.lsb
        )
        .unwrap();
        writeln!(
            f,
            "    assert!(super::references_x18({:#010x}), \"expected x18 detection for {}\");",
            instr_with_x18, enc.name
        )
        .unwrap();
        writeln!(f, "}}").unwrap();
        writeln!(f).unwrap();

        // Also generate a negative test (same instruction but reg=0)
        let instr_without_x18 = enc.value; // all GPR fields are 0
        // Only add negative test if no field at position 0 overlaps with value bits
        let any_field_zero = enc.gpr_fields.iter().any(|f| {
            let reg = (instr_without_x18 >> f.lsb) & 0x1F;
            reg == 18
        });
        if !any_field_zero {
            writeln!(f, "#[test]").unwrap();
            writeln!(
                f,
                "fn test_gen_{}_no_x18_{}_neg() {{",
                test_name, test_count
            )
            .unwrap();
            writeln!(
                f,
                "    // {}: all GPR fields = 0",
                enc.name
            )
            .unwrap();
            writeln!(
                f,
                "    assert!(!super::references_x18({:#010x}), \"false positive for {}\");",
                instr_without_x18, enc.name
            )
            .unwrap();
            writeln!(f, "}}").unwrap();
            writeln!(f).unwrap();
        }

        test_count += 1;
    }

    write_if_changed(dest_path, f);
}

/// Write an empty table + tests (fallback when no committed table and no spec).
fn write_empty_table(table_path: &Path, tests_path: &Path) {
    let mut t = String::new();
    writeln!(t, "// Empty table — no ARM spec available at build time.").unwrap();
    writeln!(t, "#[derive(Debug, Clone, Copy)]").unwrap();
    writeln!(t, "pub struct GenEntry {{ pub mask: u32, pub value: u32, pub gpr_lsbs: [u8; 5], pub emul_class: u8, pub name: &'static str }}").unwrap();
    writeln!(t, "pub static GEN_TABLE: &[GenEntry] = &[];").unwrap();
    write_if_changed(table_path, &t);

    write_if_changed(tests_path, "// No tests — no ARM spec available at build time.\n");
}
