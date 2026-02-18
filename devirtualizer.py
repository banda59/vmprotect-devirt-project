#!/usr/bin/env python3
"""
VMProtect Devirtualizer v2.0
Integrated with Pin tool traces and semantic analysis
"""

import argparse
import json
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
from collections import defaultdict
import re

try:
    from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64
    HAS_KEYSTONE = True
except ImportError:
    HAS_KEYSTONE = False
    print("[!] Warning: keystone-engine not available. Install: pip install keystone-engine")

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    print("[!] Warning: capstone not available. Install: pip install capstone")


@dataclass
class HandlerMapping:
    """Maps handler IP to its native x86 equivalent"""
    handler_ip: int
    handler_name: str
    operation_class: str
    x86_template: str  # e.g., "add eax, ebx"
    bytecode_values: Set[int]
    call_count: int
    
    # Semantic info
    input_regs: List[str]
    output_regs: List[str]
    stack_delta: int
    

@dataclass
class BytecodeInstruction:
    """Represents one VM bytecode instruction"""
    seq: int
    handler_ip: int
    handler_name: str
    bc_value: Optional[int]
    bc_addr: Optional[int]
    
    # Register state at execution
    regs: Dict[str, int]
    
    # Mapped x86
    x86_asm: Optional[str] = None
    x86_bytes: Optional[bytes] = None


@dataclass
class VMFunction:
    """Represents a devirtualized function"""
    entry_va: int
    instructions: List[BytecodeInstruction]
    
    # Generated x86 code
    x86_code: bytearray
    x86_size: int
    
    # Relocation info
    relocations: List[Tuple[int, int]]  # (offset, target_va)


def _parse_arithmetic_formula(formula: str) -> Optional[Tuple[str, str, str]]:
    """Helper to parse simple arithmetic formulas like '(init_eax + init_ebx)'"""
    # Matches patterns like "(init_eax + init_ebx)"
    match = re.match(r"\s*\(\s*init_(\w+)\s*([+\-*^&|])\s*init_(\w+)\s*\)\s*", formula)
    if match:
        # Returns (operand1, operator, operand2) e.g., ("eax", "+", "ebx")
        return match.group(1), match.group(2), match.group(3)
    return None


class Devirtualizer:
    """
    Main devirtualizer class
    Integrates Pin tool output + semantic analysis + x86 code generation
    """
    
    def __init__(
        self,
        orig_binary: Path,
        trace_file: Path,
        bytecode_file: Path,
        semantics_file: Optional[Path],
        clusters_file: Optional[Path],
        image_base: int,
        vm_entry_va: int,
        output_binary: Path,
        arch: str = "x86",
    ):
        self.orig_binary = orig_binary
        self.trace_file = trace_file
        self.bytecode_file = bytecode_file
        self.semantics_file = semantics_file
        self.clusters_file = clusters_file
        self.image_base = image_base
        self.vm_entry_va = vm_entry_va
        self.output_binary = output_binary
        self.arch = arch
        self.bits = 32 if arch == "x86" else 64
        
        # Data structures
        self.handler_mappings: Dict[int, HandlerMapping] = {}
        self.bc_instructions: List[BytecodeInstruction] = []
        self.vm_function: Optional[VMFunction] = None
        
        # Code generation
        self.ks: Optional[Ks] = None
        self.cs: Optional[Cs] = None
        
        self._init_engines()
    
    def _init_engines(self):
        """Initialize Keystone and Capstone"""
        if not HAS_KEYSTONE:
            raise RuntimeError("Keystone engine required for code generation")
        
        mode = KS_MODE_32 if self.bits == 32 else KS_MODE_64
        self.ks = Ks(KS_ARCH_X86, mode)
        
        if HAS_CAPSTONE:
            cs_mode = CS_MODE_32 if self.bits == 32 else CS_MODE_64
            self.cs = Cs(CS_ARCH_X86, cs_mode)
    
    def load_semantics(self):
        """Load handler semantics from analyze.py output"""
        if not self.semantics_file or not self.semantics_file.exists():
            print("[!] No semantics file provided. Using heuristic mapping.")
            return
        
        print(f"[*] Loading semantics from {self.semantics_file}")
        with open(self.semantics_file, "r") as f:
            semantics_data = json.load(f)
        
        for item in semantics_data:
            h_ip = int(item["ip"], 16)
            
            # Determine x86 template from semantic analysis
            x86_template = self._semantic_to_x86(item)
            
            mapping = HandlerMapping(
                handler_ip=h_ip,
                handler_name=item.get("name", f"handler_{h_ip:08x}"),
                operation_class=item["operation_class"],
                x86_template=x86_template,
                bytecode_values=set(),  # Filled later from bytecode log
                call_count=0,
                input_regs=item.get("input_regs", []),
                output_regs=item.get("output_regs", []),
                stack_delta=item.get("stack_delta", 0),
            )
            
            self.handler_mappings[h_ip] = mapping
        
        print(f"[+] Loaded {len(self.handler_mappings)} handler mappings")
    
    def _semantic_to_x86(self, semantic_item: dict) -> str:
        """
        Convert semantic analysis to a more accurate x86 template.
        This version is more robust and less reliant on hardcoded registers.
        """
        op_class = semantic_item["operation_class"]
        x86_equiv = semantic_item.get("x86_equivalent")
        
        # Use explicit x86 equivalent from Triton analysis if available and reliable
        if x86_equiv and x86_equiv != "arithmetic_unknown":
            return x86_equiv
        
        output_regs = sorted(list(semantic_item.get("output_regs", [])))
        input_regs = sorted(list(semantic_item.get("input_regs", [])))
        formulas = semantic_item.get("output_formulas", {})

        # Helper to get the first register of a certain size (e.g., 'eax' not 'ax')
        def get_main_reg(regs: list) -> Optional[str]:
            if not regs:
                return None
            # Prioritize 32/64 bit registers
            for reg in regs:
                if (self.bits == 32 and reg.startswith('e')) or \
                   (self.bits == 64 and reg.startswith('r')):
                    return reg
            return regs[0] # Fallback

        dest_reg = get_main_reg(output_regs)

        if op_class == "stack_push":
            src_reg = get_main_reg(input_regs)
            if src_reg:
                return f"push {src_reg}"
            return "push eax"  # Fallback
        
        elif op_class == "stack_pop":
            if dest_reg:
                return f"pop {dest_reg}"
            return "pop eax" # Fallback
        
        elif op_class == "const_store":
            # This class implies loading an immediate into a register.
            # The immediate value itself is the bytecode.
            if dest_reg:
                return f"mov {dest_reg}, IMM32"
            return "mov eax, IMM32" # Fallback
        
        elif op_class == "arithmetic":
            if not dest_reg or dest_reg not in formulas:
                return "nop" # Cannot determine output

            formula = formulas[dest_reg]
            parsed_formula = _parse_arithmetic_formula(formula)

            if parsed_formula:
                op1, operator, op2 = parsed_formula
                
                op_map = {"+": "add", "-": "sub", "*": "imul", "^": "xor", "&": "and", "|": "or"}
                instr = op_map.get(operator)

                if not instr:
                    return "nop"

                # Case 1: dest is one of the operands (e.g., eax = eax + ebx) -> instr dest, src
                if dest_reg == op1:
                    return f"{instr} {dest_reg}, {op2}"
                elif dest_reg == op2 and instr not in ["sub"]: # Handle non-commutative
                    return f"{instr} {dest_reg}, {op1}"
                # Case 2: dest is different (e.g., ecx = eax + ebx)
                else:
                    if instr == "add":
                        return f"lea {dest_reg}, [{op1} + {op2}]"
                    else:
                        # Fallback to mov + op for other instructions
                        return f"mov {dest_reg}, {op1}; {instr} {dest_reg}, {op2}"
            
            return "nop" # Fallback if formula parsing fails
        
        elif op_class == "memory_load":
            mem_reads = semantic_item.get("mem_reads", [])
            if dest_reg and mem_reads:
                addr_expr = mem_reads[0][0]
                if 'init_' in addr_expr and '(' not in addr_expr:
                    src_reg = addr_expr.replace('init_', '')
                    return f"mov {dest_reg}, [{src_reg}]"
            if dest_reg:
                return f"mov {dest_reg}, [esi]" # Fallback to original heuristic
            return "mov eax, [esi]"
        
        elif op_class == "memory_store":
            mem_writes = semantic_item.get("mem_writes", [])
            if mem_writes and len(input_regs) > 1:
                addr_expr = mem_writes[0][0]
                addr_reg = None
                if 'init_' in addr_expr and '(' not in addr_expr:
                    addr_reg = addr_expr.replace('init_', '')
                
                if addr_reg:
                    # The data register is the other input register
                    data_reg = next((r for r in input_regs if r != addr_reg), None)
                    if data_reg:
                        return f"mov [{addr_reg}], {data_reg}"
            return "mov [edi], eax"
        
        elif op_class == "control_flow":
            return "jmp LABEL"
        
        else:
            return "nop"

    def load_bytecode_trace(self):
        """Load bytecode trace from Pin tool output"""
        print(f"[*] Loading bytecode trace from {self.bytecode_file}")
        
        bc_instructions = []
        
        with open(self.bytecode_file, "r") as f:
            import csv
            reader = csv.reader(f)
            
            for row in reader:
                if not row or row[0].startswith("#") or row[0].lower() == "name":
                    continue
                
                if len(row) < 15:  # name,id,tid,seq,ip,bc_addr,bc_val,gax...sp
                    continue
                
                try:
                    name = row[0]
                    handler_id = int(row[1])
                    tid = int(row[2])
                    seq = int(row[3])
                    h_ip = int(row[4], 16)
                    
                    bc_addr = int(row[5], 16) if row[5] != "INVALID" else None
                    bc_val = int(row[6], 16) if row[6] != "INVALID" else None
                    
                    # Parse registers
                    regs = {}
                    reg_names = ["gax", "gbx", "gcx", "gdx", "gsi", "gdi", "gbp", "sp"]
                    for i, rname in enumerate(reg_names, start=7):
                        if i < len(row):
                            regs[rname] = int(row[i], 16)
                    
                    bc_instr = BytecodeInstruction(
                        seq=seq,
                        handler_ip=h_ip,
                        handler_name=name,
                        bc_value=bc_val,
                        bc_addr=bc_addr,
                        regs=regs,
                    )
                    
                    bc_instructions.append(bc_instr)
                    
                    # Update handler mapping
                    if h_ip in self.handler_mappings:
                        mapping = self.handler_mappings[h_ip]
                        mapping.call_count += 1
                        if bc_val is not None:
                            mapping.bytecode_values.add(bc_val)
                
                except Exception as e:
                    continue
        
        self.bc_instructions = sorted(bc_instructions, key=lambda x: x.seq)
        print(f"[+] Loaded {len(self.bc_instructions)} bytecode instructions")
        
        # Create default mappings for unmapped handlers
        for bc in self.bc_instructions:
            if bc.handler_ip not in self.handler_mappings:
                self.handler_mappings[bc.handler_ip] = HandlerMapping(
                    handler_ip=bc.handler_ip,
                    handler_name=bc.handler_name,
                    operation_class="unknown",
                    x86_template="nop",
                    bytecode_values={bc.bc_value} if bc.bc_value else set(),
                    call_count=1,
                    input_regs=[],
                    output_regs=[],
                    stack_delta=0,
                )
    
    def map_bytecode_to_x86(self):
        """Map each bytecode instruction to x86 assembly"""
        print("[*] Mapping bytecode to x86...")
        
        for bc in self.bc_instructions:
            mapping = self.handler_mappings.get(bc.handler_ip)
            if not mapping:
                bc.x86_asm = "nop"
                continue
            
            template = mapping.x86_template
            
            # Substitute concrete values
            x86_asm = self._instantiate_template(template, bc, mapping)
            bc.x86_asm = x86_asm
        
        print(f"[+] Mapped {len(self.bc_instructions)} instructions")
    
    def _instantiate_template(
        self,
        template: str,
        bc: BytecodeInstruction,
        mapping: HandlerMapping
    ) -> str:
        """
        Instantiate x86 template with concrete values from bytecode context
        """
        # Handle immediate values
        if "IMM32" in template and bc.bc_value is not None:
            template = template.replace("IMM32", f"0x{bc.bc_value:x}")
        
        # Handle const load optimization
        if mapping.operation_class == "const_store" and bc.bc_value is not None:
            # Pure constant load
            return f"mov eax, 0x{bc.bc_value:x}"
        
        # Handle register operands based on actual register state
        # (More sophisticated analysis would track data flow)
        
        # Handle memory addresses
        if "[esi]" in template and bc.regs.get("gsi"):
            addr = bc.regs["gsi"]
            # Could resolve to concrete address or keep symbolic
            pass
        
        # Control flow - would need CFG reconstruction
        if "jmp" in template.lower() or "call" in template.lower():
            # Placeholder - requires full CFG analysis
            return template
        
        return template
    
    def optimize_x86_code(self):
        """
        Perform optimization passes on generated x86
        - Remove redundant moves
        - Constant folding
        - Dead code elimination
        """
        print("[*] Optimizing x86 code...")
        
        # Simple optimization: remove consecutive identical moves
        optimized = []
        prev_instr = None
        
        for bc in self.bc_instructions:
            if bc.x86_asm == prev_instr and bc.x86_asm.startswith("mov"):
                # Skip redundant move
                continue
            optimized.append(bc)
            prev_instr = bc.x86_asm
        
        removed = len(self.bc_instructions) - len(optimized)
        self.bc_instructions = optimized
        
        print(f"[+] Removed {removed} redundant instructions")
    
    def generate_x86_code(self) -> bytearray:
        """Generate x86 machine code from mapped instructions"""
        print("[*] Generating x86 machine code...")
        
        code = bytearray()
        relocations = []
        
        for i, bc in enumerate(self.bc_instructions):
            if not bc.x86_asm or bc.x86_asm == "nop":
                # Emit NOP
                code.extend(b"\x90")
                continue
            
            try:
                # Assemble instruction
                encoding, count = self.ks.asm(bc.x86_asm)
                if encoding:
                    bc.x86_bytes = bytes(encoding)
                    code.extend(encoding)
                else:
                    # Fallback to NOP
                    code.extend(b"\x90")
                    print(f"[!] Failed to assemble: {bc.x86_asm}")
            
            except Exception as e:
                print(f"[!] Assembly error for '{bc.x86_asm}': {e}")
                code.extend(b"\x90")
        
        print(f"[+] Generated {len(code)} bytes of x86 code")
        return code
    
    def reconstruct_control_flow(self):
        """
        Reconstruct control flow graph from VM execution trace
        This is a simplified version - full CFG reconstruction is complex
        """
        print("[*] Analyzing control flow...")
        
        # Detect handler transitions that indicate control flow changes
        cf_candidates = []
        
        for i in range(len(self.bc_instructions) - 1):
            curr = self.bc_instructions[i]
            next_bc = self.bc_instructions[i + 1]
            
            # Large sequence gap indicates control flow change
            if next_bc.seq - curr.seq > 10:
                cf_candidates.append((curr, next_bc))
            
            # Specific handler types
            mapping = self.handler_mappings.get(curr.handler_ip)
            if mapping and "control_flow" in mapping.operation_class:
                cf_candidates.append((curr, next_bc))
        
        print(f"[+] Found {len(cf_candidates)} control flow candidates")
        
        # TODO: Build CFG and insert proper jumps/branches
        # For now, this is linear code generation
    
    def patch_binary(self, x86_code: bytearray):
        """
        Patch the original binary with devirtualized code
        """
        print(f"[*] Patching binary {self.orig_binary} -> {self.output_binary}")
        
        # Load original binary
        with open(self.orig_binary, "rb") as f:
            binary_data = bytearray(f.read())
        
        # Find VM entry point RVA
        vm_entry_rva = self.vm_entry_va - self.image_base
        
        # Convert RVA to file offset
        vm_entry_offset = self._rva_to_file_offset(binary_data, vm_entry_rva)
        
        if vm_entry_offset is None:
            raise ValueError(f"Could not locate VM entry RVA 0x{vm_entry_rva:x} in binary")
        
        print(f"[*] VM entry at file offset 0x{vm_entry_offset:x}")
        
        # Calculate required space
        code_size = len(x86_code)
        
        # Strategy 1: Overwrite VM stub if there's enough space
        # Check if we can fit the code
        if code_size <= 1024:  # Typical VM stub size
            # Overwrite VM entry with devirtualized code
            binary_data[vm_entry_offset:vm_entry_offset + code_size] = x86_code
            
            # Fill remaining space with NOPs
            remaining = 1024 - code_size
            if remaining > 0:
                binary_data[vm_entry_offset + code_size:vm_entry_offset + 1024] = b"\x90" * remaining
        
        else:
            # Strategy 2: Add new section (more complex, requires PE manipulation)
            print("[!] Code too large for inline patching. Consider adding new section.")
            # For now, truncate and warn
            x86_code = x86_code[:1024]
            binary_data[vm_entry_offset:vm_entry_offset + 1024] = x86_code
        
        # Write patched binary
        with open(self.output_binary, "wb") as f:
            f.write(binary_data)
        
        print(f"[+] Patched binary saved to {self.output_binary}")
    
    def _rva_to_file_offset(self, binary_data: bytes, rva: int) -> Optional[int]:
        """Convert RVA to file offset using PE headers"""
        try:
            # Parse PE header
            e_lfanew = struct.unpack_from("<I", binary_data, 0x3C)[0]
            
            if binary_data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
                return None
            
            # Read COFF header
            file_header_offset = e_lfanew + 4
            machine, num_sections, _, _, _, size_opt_hdr, _ = struct.unpack_from(
                "<HHIIIHH", binary_data, file_header_offset
            )
            
            # Read section headers
            section_table_offset = file_header_offset + 20 + size_opt_hdr
            
            for i in range(num_sections):
                offset = section_table_offset + (i * 40)
                section_header = binary_data[offset:offset + 40]
                
                virt_size, virt_addr, raw_size, raw_ptr = struct.unpack_from(
                    "<IIII", section_header, 8
                )
                
                # Check if RVA falls in this section
                if virt_addr <= rva < virt_addr + max(virt_size, raw_size):
                    file_offset = raw_ptr + (rva - virt_addr)
                    return file_offset
            
            return None
        
        except Exception as e:
            print(f"[!] Error parsing PE: {e}")
            return None
    
    def generate_report(self):
        """Generate devirtualization report"""
        report_path = self.output_binary.with_suffix(".report.txt")
        
        with open(report_path, "w") as f:
            f.write("=" * 70 + "\n")
            f.write("VMProtect Devirtualization Report\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"Input binary: {self.orig_binary}\n")
            f.write(f"Output binary: {self.output_binary}\n")
            f.write(f"VM Entry VA: 0x{self.vm_entry_va:08x}\n")
            f.write(f"Architecture: {self.arch}\n")
            f.write("\n")
            
            f.write(f"Handler Mappings: {len(self.handler_mappings)}\n")
            f.write(f"Bytecode Instructions: {len(self.bc_instructions)}\n")
            f.write("\n")
            
            f.write("Handler Summary:\n")
            f.write("-" * 70 + "\n")
            
            for h_ip, mapping in sorted(self.handler_mappings.items(), 
                                        key=lambda x: -x[1].call_count)[:20]:
                f.write(f"0x{h_ip:08x} - {mapping.handler_name}\n")
                f.write(f"  Operation: {mapping.operation_class}\n")
                f.write(f"  X86: {mapping.x86_template}\n")
                f.write(f"  Calls: {mapping.call_count}\n")
                f.write(f"  Bytecodes: {len(mapping.bytecode_values)}\n")
                f.write("\n")
            
            f.write("\n")
            f.write("Generated X86 Code (first 50 instructions):\n")
            f.write("-" * 70 + "\n")
            
            for i, bc in enumerate(self.bc_instructions[:50], 1):
                f.write(f"{i:3d}. seq={bc.seq:6d} {bc.handler_name:20s} -> {bc.x86_asm}\n")
        
        print(f"[+] Report saved to {report_path}")
    
    def run(self):
        """Main devirtualization pipeline"""
        print("\n" + "=" * 70)
        print("VMProtect Devirtualizer v2.0")
        print("=" * 70 + "\n")
        
        # Step 1: Load semantic analysis
        self.load_semantics()
        
        # Step 2: Load bytecode trace from Pin tool
        self.load_bytecode_trace()
        
        # Step 3: Map bytecode to x86
        self.map_bytecode_to_x86()
        
        # Step 4: Reconstruct control flow
        self.reconstruct_control_flow()
        
        # Step 5: Optimize
        self.optimize_x86_code()
        
        # Step 6: Generate x86 machine code
        x86_code = self.generate_x86_code()
        
        # Step 7: Patch binary
        self.patch_binary(x86_code)
        
        # Step 8: Generate report
        self.generate_report()
        
        print("\n[+] Devirtualization complete!")


def main():
    parser = argparse.ArgumentParser(
        description="VMProtect Devirtualizer v2.0 - Integrated with Pin tool traces"
    )
    
    parser.add_argument("--orig", required=True, help="Original protected binary")
    parser.add_argument("--trace", required=True, help="vmp_trace.txt from Pin tool")
    parser.add_argument("--bytecode", required=True, help="vmp_bytecode.csv from Pin tool")
    parser.add_argument("--semantics", help="semantics.json from analyze.py (recommended)")
    parser.add_argument("--clusters", help="clusters.json from analyze.py (optional)")
    
    parser.add_argument("--image-base", type=lambda x: int(x, 0), default=0x400000,
                       help="Image base address (default: 0x400000)")
    parser.add_argument("--vm-entry", type=lambda x: int(x, 0), required=True,
                       help="VM entry point VA (hex)")
    
    parser.add_argument("--out", required=True, help="Output devirtualized binary")
    parser.add_argument("--arch", choices=["x86", "x64"], default="x86",
                       help="Target architecture")
    
    args = parser.parse_args()
    
    # Validate inputs
    if not Path(args.orig).exists():
        print(f"[!] Original binary not found: {args.orig}")
        return 1
    
    if not Path(args.trace).exists():
        print(f"[!] Trace file not found: {args.trace}")
        return 1
    
    if not Path(args.bytecode).exists():
        print(f"[!] Bytecode file not found: {args.bytecode}")
        return 1
    
    # Create devirtualizer
    devirt = Devirtualizer(
        orig_binary=Path(args.orig),
        trace_file=Path(args.trace),
        bytecode_file=Path(args.bytecode),
        semantics_file=Path(args.semantics) if args.semantics else None,
        clusters_file=Path(args.clusters) if args.clusters else None,
        image_base=args.image_base,
        vm_entry_va=args.vm_entry,
        output_binary=Path(args.out),
        arch=args.arch,
    )
    
    # Run devirtualization
    try:
        devirt.run()
        return 0
    except Exception as e:
        print(f"\n[!] Devirtualization failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
