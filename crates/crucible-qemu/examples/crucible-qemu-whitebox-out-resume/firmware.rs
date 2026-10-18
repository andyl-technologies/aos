//! Encodes real guest frames and builds the established 64 KiB reset-ROM source.

use std::error::Error;
use std::path::Path;

use crucible_protocol::{
    SelectableRegister, SelectionRequest, WhiteboxLifecycleMarkerEvent, WhiteboxMarkerPayload,
    WhiteboxSemanticMarkerBody, encode_whitebox_marker_frame,
};

use super::{Mode, SELECTABLE};

pub(super) fn write(output: &Path, mode: Mode) -> Result<(), Box<dyn Error>> {
    std::fs::create_dir(output)?;
    let registration =
        SelectableRegister::new(1, SELECTABLE, vec![1], vec![1], vec!["readiness".into()])?
            .encode()?;
    let setup = encode_whitebox_marker_frame(&WhiteboxMarkerPayload::Lifecycle(
        WhiteboxLifecycleMarkerEvent::SetupComplete,
    ))?;
    let first = marker("first")?;
    let first_request = SelectionRequest::new(2, SELECTABLE, "first", None, 128)?.encode()?;
    let second = marker("second")?;
    let second_request = SelectionRequest::new(3, SELECTABLE, "second", None, 128)?.encode()?;
    let frames = [
        ("registration", registration),
        ("setup", setup),
        ("first", first),
        ("first_request", first_request),
        ("second", second),
        ("second_request", second_request),
    ];
    // The public fresh-node constructor primes to 1,000,000 ps before it
    // transfers observable ownership. These 40,000 real instructions keep
    // every protocol frame beyond that original 50 ps/instruction boundary.
    let mut assembly = String::from(
        r#".section .text,"ax"
.code16
.global _start
.macro emit frame, length
  pushw %cs
  popw %ds
  xorw %ax,%ax
  movw %ax,%es
  movw $\frame,%si
  movw $0x5000,%di
  movw $\length,%cx
  rep movsb
  movw %ax,%ds
  movl $0x5000,%eax
  movl $\length,%ecx
  outb %al,$0xe7
.endm
_start:
  cli
  cld
  movl $20000,%edx
prime_loop:
  decl %edx
  jnz prime_loop
"#,
    );
    // Every emission overwrites the same mutable guest RAM range. Register
    // frames stay observational; request frames are overwritten by the actual
    // host-authorized reply before native resume permits the next instruction.
    for (name, bytes) in &frames[..4] {
        assembly.push_str(&format!(" emit {name}, {}\n", bytes.len()));
    }
    match mode {
        Mode::Normal => {
            for (name, bytes) in &frames[4..] {
                assembly.push_str(&format!(" emit {name}, {}\n", bytes.len()));
            }
        }
        Mode::LateRegister => {
            assembly.push_str(&format!(" emit registration, {}\n", frames[0].1.len()));
        }
    }
    assembly.push_str("finished:\n jmp finished\n");
    for (name, bytes) in &frames {
        std::fs::write(output.join(format!("{name}.bin")), bytes)?;
        assembly.push_str(&format!("{name}:\n .incbin \"{name}.bin\"\n"));
    }
    assembly.push_str(".section .reset,\"ax\"\n.code16\n ljmp $0xf000,$0x0000\n");
    std::fs::write(output.join("bios.S"), assembly)?;
    std::fs::write(
        output.join("bios.ld"),
        "OUTPUT_FORMAT(elf32-i386)\nENTRY(_start)\nSECTIONS {\n\
         . = 0; .text : { *(.text*) }\n\
         . = 0xfff0; .reset : { *(.reset*) }\n\
         . = 0xffff; .last : { BYTE(0) }\n\
         /DISCARD/ : { *(.note*) *(.comment*) }\n}\n",
    )?;
    Ok(())
}

fn marker(instance: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(encode_whitebox_marker_frame(
        &WhiteboxMarkerPayload::SemanticMarker(WhiteboxSemanticMarkerBody {
            marker: "out.frame".into(),
            instance: instance.into(),
            details: Vec::new(),
        }),
    )?)
}
