//! Tests externally defined executable byte inputs and their bounded pure parsers.
//!
//! ELF and shebang inputs have no canonical Terrane encoder. The oracle is an
//! independent field model and range arithmetic, rather than byte uniqueness.

use super::support::Generator;
use terrane_core::derived::{
    ElfDynamic, ElfHeader, ElfProgram, ElfValue, Magic, ShebangValue, classify_magic,
    parse_elf_dynamic, parse_elf_header, parse_elf_programs, parse_shebang,
};

fn field(bytes: &mut [u8], offset: usize, width: usize, value: u64, little: bool) {
    let encoded = if little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    let selected = if little {
        &encoded[..width]
    } else {
        &encoded[8 - width..]
    };
    bytes[offset..offset + width].copy_from_slice(selected);
}

fn header_bytes(model: &ElfHeader) -> Vec<u8> {
    let narrow = model.value.class == 32;
    let size = if narrow { 52 } else { 64 };
    let mut bytes = vec![0; size];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = if narrow { 1 } else { 2 };
    bytes[5] = if model.little_endian { 1 } else { 2 };
    bytes[6] = 1;
    for (offset, width, value) in [
        (16, 2, u64::from(model.value.elf_type)),
        (18, 2, u64::from(model.value.machine)),
        (20, 4, 1),
        (
            if narrow { 28 } else { 32 },
            if narrow { 4 } else { 8 },
            model.program_offset,
        ),
        (if narrow { 40 } else { 52 }, 2, size as u64),
        (
            if narrow { 42 } else { 54 },
            2,
            u64::from(model.program_width),
        ),
        (
            if narrow { 44 } else { 56 },
            2,
            u64::from(model.program_count),
        ),
    ] {
        field(&mut bytes, offset, width, value, model.little_endian);
    }
    bytes
}

fn program_bytes(header: &ElfHeader, models: &[ElfProgram]) -> Vec<u8> {
    let narrow = header.value.class == 32;
    let width = if narrow { 32 } else { 56 };
    let mut bytes = vec![0; width * models.len()];
    for (encoded, model) in bytes.chunks_exact_mut(width).zip(models) {
        for (offset, field_width, value) in [
            (0, 4, u64::from(model.kind)),
            (
                if narrow { 4 } else { 8 },
                if narrow { 4 } else { 8 },
                model.offset,
            ),
            (
                if narrow { 8 } else { 16 },
                if narrow { 4 } else { 8 },
                model.address,
            ),
            (
                if narrow { 16 } else { 32 },
                if narrow { 4 } else { 8 },
                model.file_size,
            ),
            (
                if narrow { 20 } else { 40 },
                if narrow { 4 } else { 8 },
                model.memory_size,
            ),
        ] {
            field(encoded, offset, field_width, value, header.little_endian);
        }
    }
    bytes
}

fn dynamic_bytes(header: &ElfHeader, values: &[(u64, u64)]) -> Vec<u8> {
    let word = if header.value.class == 32 { 4 } else { 8 };
    let mut bytes = vec![0; word * 2 * values.len()];
    for (encoded, (tag, value)) in bytes.chunks_exact_mut(word * 2).zip(values) {
        field(encoded, 0, word, *tag, header.little_endian);
        field(encoded, word, word, *value, header.little_endian);
    }
    bytes
}

#[test]
fn elf_field_models_cover_both_classes_byte_orders_and_checked_ranges() {
    let mut generator = Generator::new(0x80ab_d173_e5d2_479f);
    for class in [32, 64] {
        for little_endian in [false, true] {
            for count in [0, 1, 7, u16::MAX - 1] {
                let model = ElfHeader {
                    value: ElfValue {
                        class,
                        machine: generator.next() as u16,
                        elf_type: generator.next() as u16,
                        interpreter: None,
                        needed: vec![],
                    },
                    little_endian,
                    program_offset: if count == 0 { 0 } else { 64 },
                    program_count: count,
                    program_width: if class == 32 { 32 } else { 56 },
                };
                let bytes = header_bytes(&model);
                let size = (model.program_offset
                    + u64::from(count) * u64::from(model.program_width))
                .max(bytes.len() as u64);
                assert_eq!(parse_elf_header(&bytes, size).unwrap(), model);
                for end in 0..bytes.len() {
                    assert!(parse_elf_header(&bytes[..end], size).is_err());
                }
                if count > 0 {
                    assert!(parse_elf_header(&bytes, size - 1).is_err());
                }
                let mut extended = model.clone();
                extended.program_count = u16::MAX;
                assert!(parse_elf_header(&header_bytes(&extended), u64::MAX).is_err());
                let mut wrong_width = model.clone();
                wrong_width.program_count = 1;
                wrong_width.program_width += 1;
                assert!(parse_elf_header(&header_bytes(&wrong_width), u64::MAX).is_err());

                let programs: Vec<_> = [0, 1, 2, 3, u32::MAX]
                    .into_iter()
                    .map(|kind| {
                        let file_size = generator.next() % 1024;
                        ElfProgram {
                            kind,
                            offset: 4096 - file_size,
                            address: u64::from(generator.next() as u32),
                            file_size,
                            memory_size: file_size + 1,
                        }
                    })
                    .collect();
                let encoded = program_bytes(&model, &programs);
                assert_eq!(
                    parse_elf_programs(&model, &encoded, 4096).unwrap(),
                    programs
                );
                for end in 0..encoded.len() {
                    let result = parse_elf_programs(&model, &encoded[..end], 4096);
                    if end % usize::from(model.program_width) == 0 {
                        assert_eq!(
                            result.unwrap(),
                            programs[..end / usize::from(model.program_width)]
                        );
                    } else {
                        assert!(result.is_err());
                    }
                }
                assert!(parse_elf_programs(&model, &encoded, 4095).is_err());
                let mut invalid = programs.clone();
                invalid[1].memory_size = invalid[1].file_size.saturating_sub(1);
                invalid[1].file_size = invalid[1].memory_size + 1;
                assert!(
                    parse_elf_programs(&model, &program_bytes(&model, &invalid), 4096).is_err()
                );

                let address = u64::from(generator.next() as u32);
                let length = u64::from(generator.next() as u32);
                let needed = vec![0, 23, u64::from(u32::MAX)];
                for terminated in [false, true] {
                    let mut values = vec![(5, address), (10, length)];
                    values.extend(needed.iter().map(|value| (1, *value)));
                    values.push((99, 7));
                    if terminated {
                        values.extend([(0, 0), (5, 12)]);
                    }
                    let encoded = dynamic_bytes(&model, &values);
                    assert_eq!(
                        parse_elf_dynamic(&model, &encoded).unwrap(),
                        ElfDynamic {
                            string_address: Some(address),
                            string_size: Some(length),
                            needed: needed.clone(),
                            terminated,
                        }
                    );
                    for end in 0..encoded.len() {
                        if end % (if class == 32 { 8 } else { 16 }) != 0 {
                            assert!(parse_elf_dynamic(&model, &encoded[..end]).is_err());
                        }
                    }
                }
                for tag in [5, 10] {
                    assert!(
                        parse_elf_dynamic(&model, &dynamic_bytes(&model, &[(tag, 1), (tag, 2)]))
                            .is_err()
                    );
                }
                assert_eq!(
                    parse_elf_dynamic(&model, &[]).unwrap(),
                    ElfDynamic {
                        string_address: None,
                        string_size: None,
                        needed: vec![],
                        terminated: false,
                    }
                );
            }
        }
    }
}

#[test]
fn classifier_and_shebang_models_cover_registry_precedence_and_prefix_limits() {
    let mut generator = Generator::new(0xa261_33dc_e5b8_471b);
    let mut tar = vec![0; 263];
    tar[257..].copy_from_slice(b"ustar\0");
    for (bytes, expected) in [
        (b"\x7fELF".to_vec(), Magic::Elf),
        (b"#!/path".to_vec(), Magic::Shebang),
        (b"!<arch>\n".to_vec(), Magic::Ar),
        (vec![0x28, 0xb5, 0x2f, 0xfd], Magic::Zstd),
        (vec![0x1f, 0x8b], Magic::Gzip),
        (tar, Magic::Tar),
        (b"UTF-8 text\n\t".to_vec(), Magic::Text),
        (vec![0], Magic::Other),
    ] {
        let mut extended = bytes.clone();
        extended.extend_from_slice(&generator.bytes::<32>());
        assert_eq!(classify_magic(&bytes), expected);
        if expected != Magic::Text {
            assert_eq!(classify_magic(&extended), expected);
        }
        assert_eq!(Magic::parse(expected.as_str()).unwrap(), expected);
    }
    assert_eq!(classify_magic(&[]), Magic::Text);
    let mut beyond = vec![b'x'; 65536];
    beyond.push(0);
    assert_eq!(classify_magic(&beyond), Magic::Text);

    for interpreter in ["/interpreter", "/λ/generated"] {
        for argument in [None, Some("--one two")] {
            let model = ShebangValue {
                interpreter: interpreter.into(),
                argument: argument.map(Into::into),
            };
            for ending in ["\n", "\r\n", ""] {
                let bytes = format!("#! \t{interpreter}\t{} \t{ending}", argument.unwrap_or(""))
                    .into_bytes();
                assert_eq!(parse_shebang(&bytes, true).unwrap(), model);
                if ending.is_empty() {
                    assert!(parse_shebang(&bytes, false).is_err());
                }
            }
        }
    }
    let mut boundary = b"#!/i ".to_vec();
    boundary.resize(65535, b'a');
    boundary.push(b'\n');
    assert_eq!(
        parse_shebang(&boundary, false)
            .unwrap()
            .argument
            .unwrap()
            .len(),
        65530
    );
    boundary[65535] = b'a';
    boundary.push(b'\n');
    assert!(parse_shebang(&boundary, true).is_err());
    for malformed in [
        b"relative".as_slice(),
        b"#!relative\n",
        b"#!\n",
        b"#!/x\0\n",
        b"#!/\xff\n",
    ] {
        assert!(parse_shebang(malformed, true).is_err());
    }
}

#[test]
fn textual_ref_key_and_view_parsers_preserve_independent_target_and_path_models() {
    use terrane_core::{
        bucket::BucketKey,
        refs::RefName,
        surface::{View, ViewTarget},
    };
    let mut generator = Generator::new(0x43d8_712e_b5c6_1dfa);
    for class in ["heads", "tags", "notes", "jobs", "conflicts", "derived"] {
        for case in 0..8 {
            let reference = match class {
                "notes" => format!("refs/notes/profiles/_/name-{case}"),
                "conflicts" => format!("refs/conflicts/_/name-{case}/00000000000000000001"),
                _ => format!("refs/{class}/_/name-{case}"),
            };
            let parsed = RefName::parse(&reference).unwrap();
            assert_eq!(parsed.as_str(), reference);
            BucketKey::parse(&format!("{reference}:record")).unwrap();
            for subtree in [
                "".to_string(),
                "subtree/λ".into(),
                super::support::maximum_key(),
            ] {
                for policy in [None, Some("policy")] {
                    let selector = format!(
                        "{reference}:/{subtree}{}",
                        policy.map(|name| format!("@{name}")).unwrap_or_default()
                    );
                    assert_eq!(
                        View::parse(&selector).unwrap(),
                        View {
                            target: ViewTarget::Ref(parsed.clone()),
                            subtree: subtree.as_bytes().to_vec(),
                            policy: policy.map(Into::into)
                        }
                    );
                }
            }
        }
    }
    for size in [0, 1, 31, 4096] {
        let digest = generator.bytes::<32>();
        let text: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        let subtree = if size == 4096 {
            super::support::maximum_key()
        } else {
            "p".repeat(size)
        };
        assert_eq!(
            View::parse(&format!("commit:{text}:/{subtree}")).unwrap(),
            View {
                target: ViewTarget::Commit(digest),
                subtree: subtree.into_bytes(),
                policy: None
            }
        );
    }
    for malformed in [
        "refs/heads",
        "refs/unknown/_/a",
        "refs/heads//a",
        "refs/heads/../a",
        "refs/heads/a?",
        "refs/heads/a\0",
    ] {
        assert!(RefName::parse(malformed).is_err());
    }
    for malformed in [
        "commit:0",
        "refs/heads/_/a:",
        "refs/heads/_/a:/../x",
        "refs/heads/_/a@",
        "refs/heads/_/a@bad/name",
    ] {
        assert!(View::parse(malformed).is_err());
    }
    assert!(
        View::parse(&format!(
            "refs/heads/_/a:/{}",
            format!("{}x", super::support::maximum_key())
        ))
        .is_err()
    );
}
