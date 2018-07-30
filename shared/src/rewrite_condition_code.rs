//! Hooks for the formatter that rewrite condition codes in the (V)CMPPS and (V)CMPPD instructions.

use std::{any::Any, fmt::Write, mem, ptr};

use zydis::gen::{
    ZYDIS_MNEMONIC_CMPPD, ZYDIS_MNEMONIC_CMPPS, ZYDIS_MNEMONIC_VCMPPD, ZYDIS_MNEMONIC_VCMPPS,
    ZYDIS_OPERAND_TYPE_IMMEDIATE, ZYDIS_STATUS_SKIP_OPERAND, ZYDIS_STATUS_USER,
};
use zydis::{
    gen::{ZydisDecodedInstruction, ZydisDecodedOperand, ZydisStatusCodes, ZydisString},
    user_data_to_c_void, Formatter, Hook, Result, ZydisError,
};

static CONDITION_CODES: &'static [&'static str] = &[
    "eq", "lt", "le", "unord", "neq", "nlt", "nle", "ord", "eq_uq", "nge", "ngt", "false", "oq",
    "ge", "gt", "true", "eq_os", "lt_oq", "le_oq", "unord_s", "neq_us", "nlt_uq", "nle_uq",
    "ord_s", "eq_us", "nge_uq", "ngt_uq", "false_os", "neg_os", "ge_oq", "gt_oq", "true_us",
];

pub struct UserData {
    pub orig_print_mnemonic: Hook,
    pub orig_format_operand: Hook,
    pub omit_immediate: bool,
}

fn user_err<T>(_: T) -> ZydisError {
    ZYDIS_STATUS_USER.into()
}

pub fn print_mnemonic(
    formatter: &Formatter,
    buffer: &mut ZydisString,
    insn: &ZydisDecodedInstruction,
    user_data: Option<&mut dyn Any>,
) -> Result<()> {
    match user_data.and_then(|x| x.downcast_mut::<UserData>()) {
        Some(&mut UserData {
            ref mut omit_immediate,
            orig_print_mnemonic: Hook::PrintMnemonic(Some(orig_print_mnemonic)),
            ..
        }) => {
            *omit_immediate = true;

            let count = insn.operandCount as usize;

            if count > 0 && insn.operands[count - 1].type_ == ZYDIS_OPERAND_TYPE_IMMEDIATE as u8 {
                let cc = unsafe { insn.operands[count].imm.value.u as usize };

                match insn.mnemonic as u32 {
                    ZYDIS_MNEMONIC_CMPPS if cc < 8 => {
                        return write!(buffer, "cmp{}ps", CONDITION_CODES[cc]).map_err(user_err)
                    }
                    ZYDIS_MNEMONIC_CMPPD if cc < 8 => {
                        return write!(buffer, "cmp{}pd", CONDITION_CODES[cc]).map_err(user_err)
                    }
                    ZYDIS_MNEMONIC_VCMPPS if cc < 0x20 => {
                        return write!(buffer, "vcmp{}ps", CONDITION_CODES[cc]).map_err(user_err)
                    }
                    ZYDIS_MNEMONIC_VCMPPD if cc < 0x20 => {
                        return write!(buffer, "vcmp{}pd", CONDITION_CODES[cc]).map_err(user_err)
                    }
                    _ => {}
                }
            }

            *omit_immediate = false;
            unsafe {
                check!(
                    orig_print_mnemonic(mem::transmute(formatter), buffer, insn, ptr::null_mut()),
                    ()
                )
            }
        }
        _ => Ok(()),
    }
}

pub fn format_operand_imm(
    formatter: &Formatter,
    buffer: &mut ZydisString,
    insn: &ZydisDecodedInstruction,
    operand: &ZydisDecodedOperand,
    user_data: Option<&mut dyn Any>,
) -> Result<()> {
    match user_data.and_then(|x| x.downcast_mut::<UserData>()) {
        Some(x) => match x {
            &mut UserData {
                omit_immediate,
                orig_format_operand: Hook::FormatOperandImm(Some(orig_format_operand)),
                ..
            } => {
                if omit_immediate {
                    Err(ZYDIS_STATUS_SKIP_OPERAND.into())
                } else {
                    unsafe {
                        check!(
                            orig_format_operand(
                                mem::transmute(formatter),
                                buffer,
                                insn,
                                operand,
                                user_data_to_c_void(&mut (x as &mut dyn Any))
                            ),
                            ()
                        )
                    }
                }
            }
            _ => Ok(()),
        },
        _ => Ok(()),
    }
}
