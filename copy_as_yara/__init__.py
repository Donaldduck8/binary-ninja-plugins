from binaryninja import Architecture, Settings
from binaryninja.function import Function
from binaryninja.log import log_error
from binaryninja.binaryview import BinaryView
from binaryninja.plugin import PluginCommand
from binaryninjaui import UIContext, UIActionContext
from PySide6.QtGui import QGuiApplication

from mkyara import YaraGenerator
from mkyara.yararule import YaraRule, StringType

from capstone import (
    CS_ARCH_X86,
    CS_MODE_32,
    CS_MODE_64,
    CS_ARCH_ALL
)

def setup_context() -> UIActionContext:
    ctx = UIContext.activeContext()
    handler = ctx.contentActionHandler()

    if handler:
        context = handler.actionContext()

    return context

def setup_globals(context) -> dict:
    snippet_globals = {"current_function": None}

    if context.function:
        snippet_globals["current_function"] = context.function

    if context.address is not None and isinstance(context.length, int):
        snippet_globals["current_selection"] = (context.address, context.address + context.length)

    else:
        snippet_globals["current_selection"] = None

    return snippet_globals

def bv_arch_to_cs_arch_and_mode(bv_arch: Architecture):
    if bv_arch.name == "x86":
        return CS_ARCH_X86, CS_MODE_32
    elif bv_arch.name == "x86_64":
        return CS_ARCH_X86, CS_MODE_64
    
    return CS_ARCH_ALL, CS_MODE_64

def copy_as_yara(bv: BinaryView, wildcarding: bool = False, mkyara_mode: str = "loose") -> None:
    opcodes, mnemonics, addresses = [], [], []
    context = setup_globals(setup_context())
    current_function: Function
    current_function, current_selection = context["current_function"], context["current_selection"]
    selection_start, selection_end = current_selection

    cs_arch, cs_mode = bv_arch_to_cs_arch_and_mode(bv.arch)

    if current_function is None or current_selection is None:
        log_error("No function selected!")

    else:
        # Visit every basic block in the current function
        for block in current_function:
            dis_text = block.get_disassembly_text()

            for idx, inst in enumerate(dis_text):
                # Make sure this instruction is within the selection range
                if inst.address >= selection_start and inst.address < selection_end:

                    # If this instruction is the last in this function, just go to the end
                    if (idx + 1) < len(dis_text):
                        inst_bytes = bv.read(inst.address, (dis_text[idx + 1].address - inst.address))
                        machine_code = inst_bytes.hex()

                    else:
                        inst_bytes = bv.read(inst.address, (block.end - dis_text[idx].address))
                        machine_code = inst_bytes.hex()

                    if wildcarding:
                        yara_gen = YaraGenerator(mkyara_mode, cs_arch, cs_mode)
                        yara_gen.add_chunk(inst_bytes, offset=inst.address - selection_start)
                        yara_rule_temp = yara_gen.generate_rule()
                        yara_string = yara_rule_temp.strings[0]
                        machine_code = yara_string.value.replace("\n", "")

                    opcodes.append(machine_code)
                    mnemonics.append(str(inst))
                    addresses.append(inst.address)

        padding = max([len(i) for i in opcodes]) + 1
        to_return = ""
        for inst_opcodes, inst_mnemonics, inst_address in zip(opcodes, mnemonics, addresses):
            to_return += f"{inst_opcodes}{' ' * (padding - len(inst_opcodes))} // [{hex(inst_address)}] {inst_mnemonics}\n"

        # Whether to output raw pattern or YARA rule
        if Settings().get_bool("mkyara.output.whole_yara_rule"):
            yara_rule = YaraRule()
            yara_rule.add_string("pattern", to_return, StringType.HEX)
            yara_rule.condition = "any of them"
            yara_rule.rule_name = "generated_rule"
            yara_rule.comments.append("Generated automatically using mkYARA")
            to_return = yara_rule.get_rule_string()

        print(to_return)
        print("[mkYARA] Rule / Pattern has been copied to clipboard!")

        clip = QGuiApplication.clipboard()
        clip.setText(to_return)

def run_data(bv: BinaryView) -> None:
    copy_as_yara(bv, False, None)

def run_wildcard_loose(bv: BinaryView) -> None:
    copy_as_yara(bv, True, "loose")

def run_wildcard_normal(bv: BinaryView) -> None:
    copy_as_yara(bv, True, "normal")

def run_wildcard_strict(bv: BinaryView) -> None:
    copy_as_yara(bv, True, "strict")

settings = Settings()
settings.register_group("mkyara", "mkYARA")

settings.register_setting("mkyara.output.whole_yara_rule", """
	{
		"title" : "Output the pattern as part of a pre-generated YARA skeleton",
		"type" : "boolean",
		"default" : false,
		"description" : "Whether to output the raw pattern for use in your own YARA rule, or a pre-generated YARA rule using only this pattern."
	}
""")

PluginCommand.register("Copy for YARA\\Data", "Copy the disassembly as is.", run_data)
PluginCommand.register("Copy for YARA\\Wildcards (Loose)", "Replace addresses with wildcards.", run_wildcard_loose)
PluginCommand.register("Copy for YARA\\Wildcards (Normal)", "Replace addresses with wildcards.", run_wildcard_normal)
PluginCommand.register("Copy for YARA\\Wildcards (Strict)", "Replace addresses with wildcards.", run_wildcard_strict)
