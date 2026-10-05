//! Minimal ELF image for the tracee: a few PT_LOAD segments, no libc, no
//! interpreter, so the address space holds only our regions and a stack.

const PAGE_SIZE: u64 = 0x1000;
const EHDR_SIZE: u16 = 64;
const PHDR_SIZE: u16 = 56;

const PT_LOAD: u32 = 1;
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

pub struct Segment<'a> {
    /// Page aligned load address.
    pub vaddr: u64,
    /// Initial contents; the rest of `memsz` is zero.
    pub data: &'a [u8],
    pub memsz: u64,
    /// `PF_*` bits.
    pub flags: u32,
}

/// Build a static ELF64 little-endian executable with the given segments.
// TODO: ELF32 variant for x86 / armv7 backends.
pub fn build_elf64(machine: u16, entry: u64, segments: &[Segment]) -> Vec<u8> {
    let phnum = segments.len() as u16;
    let mut e = Vec::new();

    // e_ident
    e.extend_from_slice(b"\x7fELF");
    e.push(2); // ELFCLASS64
    e.push(1); // ELFDATA2LSB
    e.push(1); // EV_CURRENT
    e.push(0); // ELFOSABI_NONE
    e.resize(16, 0);

    e.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
    e.extend_from_slice(&machine.to_le_bytes());
    e.extend_from_slice(&1u32.to_le_bytes()); // e_version
    e.extend_from_slice(&entry.to_le_bytes());
    e.extend_from_slice(&(EHDR_SIZE as u64).to_le_bytes()); // e_phoff
    e.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    e.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    e.extend_from_slice(&EHDR_SIZE.to_le_bytes());
    e.extend_from_slice(&PHDR_SIZE.to_le_bytes());
    e.extend_from_slice(&phnum.to_le_bytes());
    e.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    e.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    e.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
    debug_assert_eq!(e.len(), EHDR_SIZE as usize);

    // Headers fit in the first page; each segment's data starts on its own
    // page so file offset and vaddr are congruent modulo PAGE_SIZE.
    let mut offset = PAGE_SIZE;
    let mut offsets = Vec::new();
    for s in segments {
        assert_eq!(
            s.vaddr % PAGE_SIZE,
            0,
            "segment address must be page aligned"
        );
        offsets.push(offset);
        offset += (s.data.len() as u64).next_multiple_of(PAGE_SIZE);
    }

    for (s, off) in segments.iter().zip(&offsets) {
        e.extend_from_slice(&PT_LOAD.to_le_bytes());
        e.extend_from_slice(&s.flags.to_le_bytes());
        e.extend_from_slice(&off.to_le_bytes()); // p_offset
        e.extend_from_slice(&s.vaddr.to_le_bytes()); // p_vaddr
        e.extend_from_slice(&s.vaddr.to_le_bytes()); // p_paddr
        e.extend_from_slice(&(s.data.len() as u64).to_le_bytes()); // p_filesz
        e.extend_from_slice(&s.memsz.to_le_bytes());
        e.extend_from_slice(&PAGE_SIZE.to_le_bytes()); // p_align
    }

    for (s, off) in segments.iter().zip(&offsets) {
        e.resize(*off as usize, 0);
        e.extend_from_slice(s.data);
    }
    e
}
