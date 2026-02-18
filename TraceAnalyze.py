from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from collections import Counter, defaultdict

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    HAS_CAPSTONE = True
except Exception:
    HAS_CAPSTONE = False

try:
    from triton import TritonContext, ARCH, Instruction, OPERAND, AST_NODE
    HAS_TRITON = True
except Exception:
    HAS_TRITON = False


@dataclass
class InstrRecord:
    seq: int
    ip: int
    bytes: bytes


@dataclass
class BCRecord:
    name: str
    handler_id: int
    tid: int
    seq: int
    ip: int
    bc_addr: Optional[int]
    bc_val: Optional[int]
    regs: Dict[str, Optional[int]]


@dataclass
class MemRecord:
    kind: str
    tid: int
    seq: int
    ip: int
    addr: int
    size: int


@dataclass
class HandlerSummary:
    name: str
    handler_id: int
    ip: int
    call_count: int
    bytecodes: Counter
    bc_sequence: List[int]  # Full sequence for pattern detection


@dataclass
class HandlerSemantics:
    """Triton-extracted handler semantics"""
    ip: int
    name: str
    handler_id: int
    
    # Input/Output analysis
    input_regs: Set[str]
    output_regs: Set[str]
    modified_regs: Set[str]
    
    # Stack operations
    stack_push_count: int
    stack_pop_count: int
    stack_delta: int  # net change
    
    # Memory operations
    mem_reads: List[Tuple[str, int]]  # (address_expr, size)
    mem_writes: List[Tuple[str, int]]
    
    # Symbolic formulas (simplified AST)
    output_formulas: Dict[str, str]  # reg -> formula
    
    # Classification
    operation_class: str  # "arithmetic", "logic", "memory", "control_flow", "const"
    x86_equivalent: Optional[str]  # Best-guess native instruction


@dataclass
class HandlerBCProfile:
    ip: int
    name: str
    handler_id: int
    call_count: int
    distinct_bc: int
    top_bc: Optional[int]
    top_bc_ratio: float
    class_kind: str
    bc_values: List[int]
    bc_seq_prefix: List[int]
    
    # NEW: Enhanced classification
    semantic_class: Optional[str]  # From Triton analysis
    polymorphic_group: Optional[int]  # Handlers with same semantics


def _strip_comment(line: str) -> str:
    line = line.strip()
    if not line:
        return ""
    if line.startswith("#") or line.startswith("//"):
        return ""
    return line


def parse_vmtrace(path: Path) -> List[InstrRecord]:
    res: List[InstrRecord] = []
    auto_seq = 0

    with path.open("r", encoding="latin-1", errors="ignore") as f:
        for raw in f:
            line = _strip_comment(raw)
            if not line:
                continue

            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 3 and parts[0].isdigit():
                try:
                    seq = int(parts[0])
                    ip = int(parts[1], 16)
                    b = bytes.fromhex(parts[2].replace(" ", ""))
                except Exception:
                    continue
            else:
                toks = line.split()
                if len(toks) < 2:
                    continue
                auto_seq += 1
                seq = auto_seq
                try:
                    ip = int(toks[0], 16)
                    b = bytes.fromhex(" ".join(toks[1:]).replace(" ", ""))
                except Exception:
                    continue

            res.append(InstrRecord(seq=seq, ip=ip, bytes=b))

    res.sort(key=lambda r: r.seq)
    return res


def parse_bytecode_log(path: Path) -> List[BCRecord]:
    """Parse vmp_bytecode.csv with NEW format (gax, gbx, gcx, gdx, gsi, gdi, gbp, sp)"""
    res: List[BCRecord] = []
    if not path.exists():
        return res

    with path.open("r", encoding="latin-1", errors="ignore") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            row0 = row[0].strip()
            if not row0:
                continue
            if row0.startswith("#"):
                continue
            if row0.lower() in ("handler", "name"):
                continue
            row = [c.strip() for c in row]
            if len(row) < 7:  # name,id,tid,seq,ip,bc_addr,bc_val
                continue

            name = row[0]
            try:
                handler_id = int(row[1])
            except Exception:
                handler_id = -1
            
            try:
                tid = int(row[2])
            except Exception:
                tid = 0
            
            try:
                seq = int(row[3])
            except Exception:
                seq = 0
            
            try:
                ip = int(row[4], 16)
            except Exception:
                continue

            def hx(s: str) -> Optional[int]:
                s = s.strip()
                if not s or s.upper() == "INVALID":
                    return None
                return int(s, 16)

            bc_addr = hx(row[5]) if len(row) > 5 else None
            bc_val = hx(row[6]) if len(row) > 6 else None

            # NEW: Support both old (eax,ebx,...) and new (gax,gbx,...) formats
            reg_names = ["gax", "gbx", "gcx", "gdx", "gsi", "gdi", "gbp", "sp"]
            regs: Dict[str, Optional[int]] = {}
            for i, rname in enumerate(reg_names, start=7):
                if i >= len(row):
                    break
                regs[rname] = hx(row[i])
            
            # Also provide eax-style aliases for compatibility
            if "gax" in regs:
                regs["eax"] = regs["gax"]
                regs["ebx"] = regs["gbx"]
                regs["ecx"] = regs["gcx"]
                regs["edx"] = regs["gdx"]
                regs["esi"] = regs["gsi"]
                regs["edi"] = regs["gdi"]
                regs["ebp"] = regs["gbp"]
                regs["esp"] = regs["sp"]

            res.append(
                BCRecord(
                    name=name,
                    handler_id=handler_id,
                    tid=tid,
                    seq=seq,
                    ip=ip,
                    bc_addr=bc_addr,
                    bc_val=bc_val,
                    regs=regs,
                )
            )

    return res


def parse_mem_log(path: Path) -> List[MemRecord]:
    res: List[MemRecord] = []
    if not path.exists():
        return res

    auto_seq = 0
    with path.open("r", encoding="latin-1", errors="ignore") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            row0 = row[0].strip()
            if not row0:
                continue
            if row0.startswith("#"):
                continue
            if row0.lower() == "type":
                continue
            row = [c.strip() for c in row]
            if len(row) < 5:
                continue
            try:
                kind = row[0].upper()
                tid = int(row[1])
                seq = int(row[2])
                ip = int(row[3], 16)
                addr = int(row[4], 16)
                size = int(row[5]) if len(row) > 5 else 0
            except Exception:
                continue
            res.append(
                MemRecord(
                    kind=kind,
                    tid=tid,
                    seq=seq,
                    ip=ip,
                    addr=addr,
                    size=size,
                )
            )
    return res


def detect_arch_bits(instrs: List[InstrRecord]) -> int:
    if not instrs:
        return 32
    max_ip = max(r.ip for r in instrs)
    if max_ip > 0xFFFFFFFF:
        return 64
    return 32


def summarize_handlers(bc_list: List[BCRecord]) -> Dict[int, HandlerSummary]:
    """Build enhanced handler summaries with full BC sequences"""
    res: Dict[int, HandlerSummary] = {}
    
    # Group by handler IP
    by_ip: Dict[int, List[BCRecord]] = defaultdict(list)
    for bc in bc_list:
        by_ip[bc.ip].append(bc)
    
    for ip, records in by_ip.items():
        records.sort(key=lambda r: r.seq)
        
        # Extract bytecode sequence
        bc_seq = [r.bc_val for r in records if r.bc_val is not None]
        
        # Count unique bytecodes
        bc_counter = Counter(bc_seq)
        
        res[ip] = HandlerSummary(
            name=records[0].name,
            handler_id=records[0].handler_id,
            ip=ip,
            call_count=len(records),
            bytecodes=bc_counter,
            bc_sequence=bc_seq,
        )
    
    return res


class TritonVMAnalyzer:
    """Enhanced Triton analyzer with semantic extraction"""
    
    def __init__(self, bits: int = 32):
        if not HAS_TRITON:
            raise RuntimeError("triton module not available")
        if bits == 32:
            arch = ARCH.X86
        else:
            arch = ARCH.X86_64
        self.ctx = TritonContext(arch)
        self.bits = bits
        self.ctx.setMode(self.ctx.modes.ALIGNED_MEMORY, True)
        self.ctx.setMode(self.ctx.modes.ONLY_ON_SYMBOLIZED, False)
    
    def analyze_handler_semantics(
        self,
        handler_ip: int,
        trace: List[InstrRecord],
        bc_records: List[BCRecord],
        max_insts: int = 256,
        verbose: bool = False,
    ) -> HandlerSemantics:
        """
        Extract semantic meaning of a handler using symbolic execution
        """
        # Find handler entries in trace
        handler_starts = [i for i, r in enumerate(trace) if r.ip == handler_ip]
        if not handler_starts:
            raise ValueError(f"Handler 0x{handler_ip:08x} not found in trace")
        
        start_idx = handler_starts[0]
        
        # Initialize symbolic registers at handler entry
        if self.bits == 32:
            regs_to_symbolize = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]
        else:
            regs_to_symbolize = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"]
        
        for reg_name in regs_to_symbolize:
            reg = getattr(self.ctx.registers, reg_name)
            self.ctx.symbolizeRegister(reg, f"init_{reg_name}")
        
        # Track state
        input_regs: Set[str] = set()
        output_regs: Set[str] = set()
        modified_regs: Set[str] = set()
        mem_reads: List[Tuple[str, int]] = []
        mem_writes: List[Tuple[str, int]] = []
        stack_ops: List[str] = []
        
        # Execute instructions
        exec_count = 0
        for i in range(start_idx, min(start_idx + max_insts, len(trace))):
            rec = trace[i]
            
            # Stop if we've left the handler (heuristic: return or far jump)
            if exec_count > 0 and rec.ip != handler_ip:
                # Check if it's a return-like pattern
                if len(rec.bytes) > 0 and rec.bytes[0] in [0xc3, 0xc2, 0xca, 0xcb]:  # ret variants
                    break
            
            inst = Instruction()
            inst.setOpcode(rec.bytes)
            inst.setAddress(rec.ip)
            
            # Process instruction
            try:
                self.ctx.processing(inst)
            except Exception as e:
                if verbose:
                    print(f"[!] Triton error at 0x{rec.ip:08x}: {e}")
                break
            
            exec_count += 1
            
            if verbose and exec_count <= 20:
                print(f"  {rec.seq:6d}: 0x{rec.ip:08x}: {inst}")
            
            # Analyze operands
            for op in inst.getOperands():
                if op.getType() == OPERAND.REG:
                    reg_name = op.getName()
                    if self.ctx.isRegisterSymbolized(op):
                        input_regs.add(reg_name)
                    if inst.isWriteBack() or op in inst.getWrittenRegisters():
                        output_regs.add(reg_name)
                        modified_regs.add(reg_name)
                
                elif op.getType() == OPERAND.MEM:
                    addr = op.getAddress()
                    size = op.getSize()
                    addr_expr = str(self.ctx.getMemoryAst(addr)) if self.ctx.isMemorySymbolized(addr) else f"0x{addr:x}"
                    
                    if inst.isMemoryRead():
                        mem_reads.append((addr_expr, size))
                    if inst.isMemoryWrite():
                        mem_writes.append((addr_expr, size))
            
            # Track stack operations
            mnemonic = inst.getDisassembly().split()[0].lower()
            if mnemonic in ["push", "pushad", "pusha"]:
                stack_ops.append("push")
            elif mnemonic in ["pop", "popad", "popa"]:
                stack_ops.append("pop")
        
        # Extract output formulas
        output_formulas: Dict[str, str] = {}
        for reg_name in modified_regs:
            try:
                reg = getattr(self.ctx.registers, reg_name)
                ast = self.ctx.getRegisterAst(reg)
                # Simplify AST to string (limit depth for readability)
                formula = self._simplify_ast(ast, max_depth=3)
                output_formulas[reg_name] = formula
            except:
                pass
        
        # Calculate stack delta
        stack_delta = stack_ops.count("push") - stack_ops.count("pop")
        
        # Classify operation
        operation_class = self._classify_operation(
            inst if exec_count > 0 else None,
            input_regs,
            output_regs,
            mem_reads,
            mem_writes,
            stack_ops
        )
        
        # Guess x86 equivalent
        x86_equiv = self._guess_x86_equivalent(operation_class, output_formulas)
        
        return HandlerSemantics(
            ip=handler_ip,
            name=f"handler_{handler_ip:08x}",
            handler_id=-1,
            input_regs=input_regs,
            output_regs=output_regs,
            modified_regs=modified_regs,
            stack_push_count=stack_ops.count("push"),
            stack_pop_count=stack_ops.count("pop"),
            stack_delta=stack_delta,
            mem_reads=mem_reads,
            mem_writes=mem_writes,
            output_formulas=output_formulas,
            operation_class=operation_class,
            x86_equivalent=x86_equiv,
        )
    
    def _simplify_ast(self, ast, max_depth: int = 3, current_depth: int = 0) -> str:
        """Simplify Triton AST to readable string"""
        if current_depth >= max_depth:
            return "..."
        
        try:
            node_type = ast.getType()
            
            # Leaf nodes
            if node_type == AST_NODE.INTEGER:
                return f"0x{ast.getInteger():x}"
            elif node_type == AST_NODE.VARIABLE:
                return ast.getValue()
            
            # Binary operations
            children = ast.getChildren()
            if node_type == AST_NODE.BVADD and len(children) == 2:
                left = self._simplify_ast(children[0], max_depth, current_depth + 1)
                right = self._simplify_ast(children[1], max_depth, current_depth + 1)
                return f"({left} + {right})"
            elif node_type == AST_NODE.BVSUB and len(children) == 2:
                left = self._simplify_ast(children[0], max_depth, current_depth + 1)
                right = self._simplify_ast(children[1], max_depth, current_depth + 1)
                return f"({left} - {right})"
            elif node_type == AST_NODE.BVMUL and len(children) == 2:
                left = self._simplify_ast(children[0], max_depth, current_depth + 1)
                right = self._simplify_ast(children[1], max_depth, current_depth + 1)
                return f"({left} * {right})"
            elif node_type == AST_NODE.BVXOR and len(children) == 2:
                left = self._simplify_ast(children[0], max_depth, current_depth + 1)
                right = self._simplify_ast(children[1], max_depth, current_depth + 1)
                return f"({left} ^ {right})"
            elif node_type == AST_NODE.BVAND and len(children) == 2:
                left = self._simplify_ast(children[0], max_depth, current_depth + 1)
                right = self._simplify_ast(children[1], max_depth, current_depth + 1)
                return f"({left} & {right})"
            elif node_type == AST_NODE.BVOR and len(children) == 2:
                left = self._simplify_ast(children[0], max_depth, current_depth + 1)
                right = self._simplify_ast(children[1], max_depth, current_depth + 1)
                return f"({left} | {right})"
            
            # Default
            return f"{node_type}"
        except:
            return "<?>"
    
    def _classify_operation(
        self,
        last_inst,
        input_regs: Set[str],
        output_regs: Set[str],
        mem_reads: List,
        mem_writes: List,
        stack_ops: List[str],
    ) -> str:
        """Classify handler operation type"""
        if len(mem_writes) > 0 and len(input_regs) == 0:
            return "const_store"
        if len(stack_ops) > 0 and stack_ops[0] == "push":
            return "stack_push"
        if len(stack_ops) > 0 and stack_ops[0] == "pop":
            return "stack_pop"
        if len(mem_reads) > 0 and len(output_regs) > 0:
            return "memory_load"
        if len(mem_writes) > 0:
            return "memory_store"
        if len(input_regs) >= 2 and len(output_regs) >= 1:
            return "arithmetic"
        if len(output_regs) > 0:
            return "register_op"
        return "control_flow"
    
    def _guess_x86_equivalent(self, op_class: str, formulas: Dict[str, str]) -> Optional[str]:
        """Heuristic: guess native x86 instruction"""
        if op_class == "const_store":
            return "mov [mem], imm"
        elif op_class == "stack_push":
            return "push reg"
        elif op_class == "stack_pop":
            return "pop reg"
        elif op_class == "arithmetic":
            # Check formulas for patterns
            for reg, formula in formulas.items():
                if "+" in formula:
                    return "add"
                elif "-" in formula:
                    return "sub"
                elif "*" in formula:
                    return "imul"
                elif "^" in formula:
                    return "xor"
                elif "&" in formula:
                    return "and"
                elif "|" in formula:
                    return "or"
            return "arithmetic_unknown"
        elif op_class == "memory_load":
            return "mov reg, [mem]"
        elif op_class == "memory_store":
            return "mov [mem], reg"
        return None


def cluster_handlers_by_semantics(
    semantics_map: Dict[int, HandlerSemantics],
) -> Dict[str, List[HandlerSemantics]]:
    """
    Cluster handlers by operation semantics, not bytecode values
    This solves the polymorphic handler problem
    """
    clusters: Dict[str, List[HandlerSemantics]] = defaultdict(list)
    
    for sem in semantics_map.values():
        # Create signature based on semantics
        signature = (
            sem.operation_class,
            tuple(sorted(sem.input_regs)),
            tuple(sorted(sem.output_regs)),
            sem.stack_delta,
            len(sem.mem_reads),
            len(sem.mem_writes),
        )
        key = str(signature)
        clusters[key].append(sem)
    
    return dict(clusters)


def build_bc_profiles(
    hmap: Dict[int, HandlerSummary],
    bc_list: List[BCRecord],
    semantics_map: Optional[Dict[int, HandlerSemantics]] = None,
    seq_prefix_len: int = 8,
) -> Dict[int, HandlerBCProfile]:
    """Enhanced BC profile with semantic classification"""
    by_ip: Dict[int, List[BCRecord]] = {}
    for bc in bc_list:
        by_ip.setdefault(bc.ip, []).append(bc)
    for ip, lst in by_ip.items():
        lst.sort(key=lambda r: r.seq)

    res: Dict[int, HandlerBCProfile] = {}
    for ip, hs in hmap.items():
        total = sum(hs.bytecodes.values())
        seq_vals: List[int] = []
        if ip in by_ip:
            for bc in by_ip[ip]:
                if bc.bc_val is not None:
                    seq_vals.append(bc.bc_val)

        if total <= 0:
            distinct = 0
            top_bc = None
            ratio = 0.0
            bc_values: List[int] = []
            kind = "none"
        else:
            distinct = len(hs.bytecodes)
            top_bc, top_cnt = hs.bytecodes.most_common(1)[0]
            ratio = float(top_cnt) / float(total)
            bc_values = sorted(hs.bytecodes.keys())
            if distinct == 1:
                kind = "pure_const"
            elif distinct <= 3 and ratio >= 0.7:
                kind = "biased_const"
            else:
                kind = "mixed"

        prefix = seq_vals[:seq_prefix_len]
        
        # Add semantic classification
        semantic_class = None
        if semantics_map and ip in semantics_map:
            semantic_class = semantics_map[ip].operation_class

        res[ip] = HandlerBCProfile(
            ip=ip,
            name=hs.name,
            handler_id=hs.handler_id,
            call_count=hs.call_count,
            distinct_bc=distinct,
            top_bc=top_bc,
            top_bc_ratio=ratio,
            class_kind=kind,
            bc_values=bc_values,
            bc_seq_prefix=prefix,
            semantic_class=semantic_class,
            polymorphic_group=None,  # Assigned later
        )
    return res


def cmd_summary(args):
    trace = parse_vmtrace(Path(args.trace))
    bc = parse_bytecode_log(Path(args.bytecode)) if args.bytecode else []
    mem = parse_mem_log(Path(args.mem)) if args.mem else []

    print(f"[+] trace: {len(trace)} insns")
    print(f"[+] bytecode log: {len(bc)} entries")
    print(f"[+] mem log: {len(mem)} entries")

    if trace:
        print(f"    seq: {trace[0].seq} .. {trace[-1].seq}")
        print(
            f"    ip : 0x{min(r.ip for r in trace):08x} .. 0x{max(r.ip for r in trace):08x}"
        )
        bits = detect_arch_bits(trace)
        print(f"    arch guess: x86-{bits}")

    if bc:
        hs = summarize_handlers(bc)
        print(f"    handlers: {len(hs)} unique IPs")
        top = sorted(hs.values(), key=lambda h: h.call_count, reverse=True)[:10]
        for h in top:
            print(
                f"      0x{h.ip:08x} {h.name} id={h.handler_id} "
                f"calls={h.call_count} uniq_bc={len(h.bytecodes)}"
            )

    if args.save_json:
        out = {
            "trace": [asdict(r) | {"bytes": r.bytes.hex()} for r in trace],
            "bytecode": [asdict(b) for b in bc],
            "mem": [asdict(m) for m in mem],
        }
        Path(args.save_json).write_text(json.dumps(out, indent=2), encoding="utf-8")
        print(f"[+] saved json: {args.save_json}")


def cmd_semantics(args):
    """NEW: Extract handler semantics using Triton"""
    if not HAS_TRITON:
        raise SystemExit("[-] triton module not available")
    
    trace = parse_vmtrace(Path(args.trace))
    bc = parse_bytecode_log(Path(args.bytecode)) if args.bytecode else []
    
    if args.arch == "auto":
        bits = detect_arch_bits(trace)
        print(f"[+] auto-detected arch: x86-{bits}")
    elif args.arch == "x86":
        bits = 32
    else:
        bits = 64
    
    analyzer = TritonVMAnalyzer(bits=bits)
    
    # Get handler IPs
    if args.handler_ips:
        handler_ips = [int(h, 16) for h in args.handler_ips]
    else:
        # Auto-detect from bytecode log
        hs_map = summarize_handlers(bc)
        handler_ips = list(hs_map.keys())[:args.max_handlers]
    
    print(f"[+] analyzing {len(handler_ips)} handlers...")
    
    semantics_results = {}
    for i, h_ip in enumerate(handler_ips, 1):
        print(f"\n[{i}/{len(handler_ips)}] Handler 0x{h_ip:08x}")
        try:
            sem = analyzer.analyze_handler_semantics(
                handler_ip=h_ip,
                trace=trace,
                bc_records=bc,
                max_insts=args.max_insts,
                verbose=args.verbose,
            )
            semantics_results[h_ip] = sem
            
            print(f"  Class: {sem.operation_class}")
            print(f"  Input regs: {', '.join(sorted(sem.input_regs)) or 'none'}")
            print