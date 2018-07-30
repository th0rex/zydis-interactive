#![deny(bare_trait_objects)]
#![feature(try_from)]

#[macro_use]
extern crate failure;

#[macro_use]
extern crate zydis;

use std::convert::{TryFrom, TryInto};
use std::ffi::CStr;
use std::fmt::{self, Write};
use std::num::ParseIntError;
use std::result;
use std::str;

use arrayvec::{Array, ArrayVec};

use failure::{Context, ResultExt};

use zydis::gen::{
    ZYDIS_ADDRESS_WIDTH_32, ZYDIS_ADDRESS_WIDTH_64, ZYDIS_MACHINE_MODE_LONG_64,
    ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDR_FORMAT_ABSOLUTE,
    ZYDIS_ADDR_FORMAT_RELATIVE_SIGNED, ZYDIS_ADDR_FORMAT_RELATIVE_UNSIGNED,
    ZYDIS_DISP_FORMAT_HEX_SIGNED, ZYDIS_DISP_FORMAT_HEX_UNSIGNED, ZYDIS_FORMATTER_STYLE_INTEL,
    ZYDIS_IMM_FORMAT_HEX_AUTO, ZYDIS_IMM_FORMAT_HEX_SIGNED, ZYDIS_IMM_FORMAT_HEX_UNSIGNED,
};
use zydis::{
    gen::{ZydisAddressFormat, ZydisDisplacementFormat, ZydisImmediateFormat, ZydisStatusCodes},
    status_description, Decoder, Formatter, FormatterProperty,
};

mod rewrite_condition_code;

use self::rewrite_condition_code::{format_operand_imm, print_mnemonic, UserData};

#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>,
}

#[derive(Clone, Debug, Fail)]
pub enum ErrorKind {
    #[fail(display = "Zydis formatting error: {}", _0)]
    FormattingError(&'static str),
    #[fail(display = "Invalid utf8 from zydis: {}", _0)]
    UTF8Error(str::Utf8Error),
    #[fail(display = "Failed to append to string: {}", _0)]
    WriteError(fmt::Error),
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        self.inner.get_context().clone()
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(inner: Context<ErrorKind>) -> Error {
        Error { inner: inner }
    }
}

pub type Result<T> = result::Result<T, Error>;

static HELP_MESSAGE: &'static str = r#"```
Zydis is at       https://zydis.re
Source Code is at https://github.com/th0rex/zydis-interactive
!help - Help
!dis OPTIONS <data here> - disassemble
   OPTIONS can be one or more of the following, seperated by a space:
   +x86  32 bit mode
   +x64  64 bit mode
   +base=0..2^64 Base address to use in relative instructions
   +uppercase={true|false} Uppercase mnemonics
   +force_memseg={true|false} Force showing the segment
   +force_memsize={true|false} Force showing the size
   +address_format={absolute|unsigned_rel|signed_rel} What format to show addresses in
   +disp_format={signed|unsigned} What format to show displacements in
   +imm_format={auto|signed|unsigned} What format to show immediates in
   +pad_addr=0..255 Number of padding bytes for addresses
   +pad_disp=0..255 Number of padding bytes for displacements
   +pad_imm=0..255 Number of padding bytes for immediates
   +rewrite_cc={false|true} Rewrite condition codes in (V)CMPPS and (V)CMPPD to human readable form ("eq", "lt", ...)
Defaults are:
   +x86 +base=0 +uppercase=false
   +force_memseg=false +force_memsize=false +address_format=absolute
   +disp_format=signed +imm_format=unsigned
   +pad_addr=2 +pad_disp=2 +pad_imm=2
   +rewrite_cc=false

Most invalid bytes will be ignored, only [0-9A-Fa-f] are treated as data, and 0 is only treated as data if there is no `x` directly following it
(i.e. you can most likely paste the data in any format you like)
```
For example:
!dis +x64 "\x90\x90"
!dis +x64 +rewrite_cc=true +force_memseg=true +force_memsize=true 0x62, 0xF1, 0x6C, 0x5F, 0xC2, 0x54, 0x98, 0x40, 0x0F
!dis +x64 62F16C5FC25498400F
"#;

pub trait VecLike<T>: AsRef<[T]> {
    fn clear(&mut self);

    fn push(&mut self, item: T);
}

impl<T> VecLike<T> for Vec<T> {
    #[inline]
    fn clear(&mut self) {
        Vec::clear(self)
    }

    #[inline]
    fn push(&mut self, item: T) {
        Vec::push(self, item)
    }
}

impl<A: Array> VecLike<A::Item> for ArrayVec<A> {
    #[inline]
    fn clear(&mut self) {
        ArrayVec::<A>::clear(self)
    }

    #[inline]
    fn push(&mut self, item: A::Item) {
        ArrayVec::<A>::push(self, item)
    }
}

enum Arch {
    X86,
    X64,
}

#[derive(Default)]
struct Options {
    arch: Option<Arch>,

    base: Option<u64>,

    uppercase: Option<bool>,
    force_memseg: Option<bool>,
    force_memsize: Option<bool>,
    address_format: Option<ZydisAddressFormat>,
    disp_format: Option<ZydisDisplacementFormat>,
    imm_format: Option<ZydisImmediateFormat>,
    hex_uppercase: Option<bool>,
    hex_padding_addr: Option<u8>,
    hex_padding_disp: Option<u8>,
    hex_padding_imm: Option<u8>,

    rewrite_cc: Option<bool>,
}

trait ParseStrRadix<T> {
    fn parse_radix(&self, base: u32) -> result::Result<T, ParseIntError>;
}

impl ParseStrRadix<u64> for str {
    fn parse_radix(&self, base: u32) -> result::Result<u64, ParseIntError> {
        u64::from_str_radix(self, base)
    }
}

impl ParseStrRadix<u8> for str {
    fn parse_radix(&self, base: u32) -> result::Result<u8, ParseIntError> {
        u8::from_str_radix(self, base)
    }
}

macro_rules! parse_number {
    ($v:expr, $o:expr, $s:expr) => {
        let len = $s.len();
        if $o.len() > len && &$o[..len] == $s {
            let tmp = &$o[len..];
            let (offset, base) = if tmp.find("0x").is_some() {
                (2, 16)
            } else {
                (0, 10)
            };

            $v = (&tmp[offset..]).parse_radix(base).ok();
        }
    };
}

impl Options {
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn parse_option(&mut self, opt: &str) {
        match opt {
            "x86"                         => self.arch           = Some(Arch::X86),
            "x64"                         => self.arch           = Some(Arch::X64),
            "uppercase=true"              => self.uppercase      = Some(true),
            "uppercase=false"             => self.uppercase      = Some(false),
            "force_memseg=true"           => self.force_memseg   = Some(true),
            "force_memseg=false"          => self.force_memseg   = Some(false),
            "force_memsize=true"          => self.force_memsize  = Some(true),
            "force_memsize=false"         => self.force_memsize  = Some(false),
            "address_format=absolute"     => self.address_format = Some(ZYDIS_ADDR_FORMAT_ABSOLUTE),
            "address_format=unsigned_rel" => self.address_format = Some(ZYDIS_ADDR_FORMAT_RELATIVE_UNSIGNED),
            "address_format=signed_rel"   => self.address_format = Some(ZYDIS_ADDR_FORMAT_RELATIVE_SIGNED),
            "disp_format=signed"          => self.address_format = Some(ZYDIS_DISP_FORMAT_HEX_SIGNED),
            "disp_format=unsigned"        => self.address_format = Some(ZYDIS_DISP_FORMAT_HEX_UNSIGNED),
            "imm_format=auto"             => self.imm_format     = Some(ZYDIS_IMM_FORMAT_HEX_AUTO),
            "imm_format=signed"           => self.imm_format     = Some(ZYDIS_IMM_FORMAT_HEX_SIGNED),
            "imm_format=unsigned"         => self.imm_format     = Some(ZYDIS_IMM_FORMAT_HEX_UNSIGNED),
            "rewrite_cc=true"             => self.rewrite_cc     = Some(true),
            "rewrite_cc=false"            => self.rewrite_cc     = Some(false),
            _                             => {
                parse_number!(self.base,             opt, "base=");
                parse_number!(self.hex_padding_addr, opt, "pad_addr=");
                parse_number!(self.hex_padding_disp, opt, "pad_disp=");
                parse_number!(self.hex_padding_imm,  opt, "pad_imm=");
            },
        }
    }
}

struct ParsedOptions<'a>(Option<UserData>, u64, Formatter<'a>, Decoder);

impl<'a> TryFrom<Options> for ParsedOptions<'a> {
    type Error = ZydisStatusCodes;

    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn try_from(options: Options) -> result::Result<Self, Self::Error> {
        let mut formatter = Formatter::new(ZYDIS_FORMATTER_STYLE_INTEL)?;

        let decoder = match options.arch.unwrap_or(Arch::X86) {
            Arch::X86 => Decoder::new(ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32)?,
            Arch::X64 => Decoder::new(ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64)?,
        };

        formatter.set_property(FormatterProperty::Uppercase(options.uppercase.unwrap_or(false)))?;
        formatter.set_property(FormatterProperty::ForceMemseg(options.force_memseg.unwrap_or(false)))?;
        formatter.set_property(FormatterProperty::ForceMemsize(options.force_memsize.unwrap_or(false)))?;
        formatter.set_property(FormatterProperty::AddressFormat(options.address_format.unwrap_or(ZYDIS_ADDR_FORMAT_ABSOLUTE)))?;
        formatter.set_property(FormatterProperty::DispFormat(options.disp_format.unwrap_or(ZYDIS_DISP_FORMAT_HEX_SIGNED)))?;
        formatter.set_property(FormatterProperty::ImmFormat(options.imm_format.unwrap_or(ZYDIS_IMM_FORMAT_HEX_UNSIGNED)))?;
        formatter.set_property(FormatterProperty::HexUppercase(options.hex_uppercase.unwrap_or(true)))?;
        formatter.set_property(FormatterProperty::HexPaddingAddr(options.hex_padding_addr.unwrap_or(2)))?;
        formatter.set_property(FormatterProperty::HexPaddingDisp(options.hex_padding_disp.unwrap_or(2)))?;
        formatter.set_property(FormatterProperty::HexPaddingImm(options.hex_padding_imm.unwrap_or(2)))?;

        let base = options.base.unwrap_or(0);

        let user_data = if options.rewrite_cc.unwrap_or(false) {
            Some(UserData {
                orig_print_mnemonic: formatter.set_print_mnemonic(Box::new(print_mnemonic))?,
                orig_format_operand: formatter.set_format_operand_imm(Box::new(format_operand_imm))?,
                omit_immediate: false,
            })
        } else {
            None
        };

        Ok(ParsedOptions(user_data, base, formatter, decoder))
    }
}

fn decode_hex(mut b: u8) -> u8 {
    b -= b'0';
    if b > 9 {
        b - 7
    } else {
        b
    }
}

fn is_hex_digit(b: u8) -> bool {
    (b as char).is_digit(16)
}

fn decode_bytes_into<V: VecLike<u8>>(hex: &[u8], bytes: &mut V) {
    let mut last_val = None;

    for (i, &b) in hex.iter().enumerate() {
        if b == b'0' && i + 1 < hex.len() && hex[i + 1] == b'x' {
            continue;
        }

        if is_hex_digit(b) {
            let b = b.to_ascii_uppercase();
            if let Some(tmp) = last_val {
                bytes.push((tmp << 4) | decode_hex(b));

                last_val = None;
            } else {
                last_val = Some(decode_hex(b));
            }
        }
    }
}

fn disassemble<V: VecLike<u8>>(
    data: &str,
    bytes: &mut V,
    out: &mut String,
    length_limit: Option<usize>,
) -> Result<bool> {
    let mut options = Options::default();
    let limit = length_limit.unwrap_or_else(usize::max_value);

    for thing in data.trim().split(' ') {
        if thing.len() == 0 {
            continue;
        }

        if &thing[..1] == "+" {
            options.parse_option(&thing[1..]);
        } else {
            decode_bytes_into(thing.as_bytes(), bytes);
        }
    }

    let ParsedOptions(mut user_data, base, formatter, decoder) = options
        .try_into()
        .map_err(|x| ErrorKind::FormattingError(status_description(x)))?;

    let mut buffer = vec![0u8; 200];

    for (insn, ip) in decoder.instruction_iterator(bytes.as_ref(), base) {
        let user_data: Option<&mut dyn std::any::Any> = match &mut user_data {
            Some(x) => {
                x.omit_immediate = false;
                Some(x)
            }
            None => None,
        };

        formatter
            .format_instruction_raw(&insn, &mut buffer, user_data)
            .map_err(|x| ErrorKind::FormattingError(status_description(x)))?;

        let insn = unsafe { CStr::from_ptr(buffer.as_ptr() as _) }
            .to_str()
            .with_context(|e| ErrorKind::UTF8Error(e.clone()))?;

        // Limit the length of the message
        if out.len() + insn.len() > limit {
            return Ok(true);
        }

        write!(out, "0x{:08X} {}\n", ip, insn).with_context(|e| ErrorKind::WriteError(e.clone()))?;
    }

    Ok(false)
}

pub enum CommandResult {
    Help,
    Disassembled(bool),
}

pub fn handle_command<V: VecLike<u8>>(
    command: &str,
    bytes: &mut V,
    out: &mut String,
    length_limit: Option<usize>,
    init: Option<&str>,
) -> Result<Option<CommandResult>> {
    if command.len() < 5 {
        return Ok(None);
    }

    match &command[..5] {
        "!help" => {
            out.clear();
            out.push_str(HELP_MESSAGE);
            Ok(Some(CommandResult::Help))
        }
        "!dis " => {
            bytes.clear();
            out.clear();
            out.push_str(init.unwrap_or(""));
            let result = disassemble(&command[5..], bytes, out, length_limit)?;
            Ok(Some(CommandResult::Disassembled(result)))
        }
        _ => Ok(None),
    }
}
