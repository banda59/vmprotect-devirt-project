#include "pin.H"
#include <stdio.h>
#include <string>
#include <map>
#include <set>
#include <vector>
#include <algorithm>

// ----------------------------------------------------------------------
// 공용 포맷 매크로 (32비트 / 64비트 주소 출력 구분)
// ----------------------------------------------------------------------
#ifdef TARGET_IA32E
typedef unsigned long long ADDR_FMT_T;
#  define FMT_ADDR "0x%016llx"
#else
typedef unsigned int       ADDR_FMT_T;
#  define FMT_ADDR "0x%08x"
#endif

#define FMT_VAL  "0x%016llx"

// ----------------------------------------------------------------------
// 메타 정보
// ----------------------------------------------------------------------
static const char* TOOL_NAME = "vmp-devirt-lab";
static const char* TOOL_AUTHOR = "banda";
static const char* TOOL_VERSION = "1.3";

// ----------------------------------------------------------------------
// 상태/자료 구조
// ----------------------------------------------------------------------
enum TRACE_STATE {
    TRACE_IDLE = 0,
    TRACE_RECORDING = 1,
    TRACE_DONE = 2
};

enum CF_TYPE {
    CF_TYPE_CJMP = 0,
    CF_TYPE_JMP = 1,
    CF_TYPE_CALL = 2
};

struct HandlerInfo {
    ADDRINT addr;
    std::string name;
    UINT64 call_count;
    UINT32 id;
    std::set<UINT32> bc_vals;
    BOOL is_auto;
};

struct ThreadState {
    TRACE_STATE state;
    UINT64 seq;
    ADDRINT last_bc_addr;
    UINT32 last_bc;
    BOOL last_bc_valid;
    UINT64 vm_hits;
};

struct CFEdge {
    ADDRINT from;
    ADDRINT to;
    UINT64 count;
    UINT32 type;
};

// ----------------------------------------------------------------------
// 글로벌 변수
// ----------------------------------------------------------------------
FILE* g_trace = 0;
FILE* g_bc = 0;
FILE* g_regs = 0;
FILE* g_mem = 0;
FILE* g_ana = 0;

ADDRINT g_low = 0;
ADDRINT g_high = 0;
BOOL    g_has_main = FALSE;
ADDRINT g_vm_entry = 0;

UINT64 g_total_instr = 0;
UINT64 g_max_instr = 0;
UINT64 g_total_handler_calls = 0;
BOOL   g_stop = FALSE;

std::map< ADDRINT, HandlerInfo > g_handlers;
UINT32 g_next_handler_id = 0;

TLS_KEY g_tls_key;

BOOL g_track_mem = FALSE;
BOOL g_mem_val = FALSE;
BOOL g_verbose = FALSE;
BOOL g_auto_det = FALSE;

std::map< std::pair<ADDRINT, ADDRINT>, CFEdge > g_cf_edges;
std::map< ADDRINT, UINT32 > g_jump_targets;
std::map< ADDRINT, UINT32 > g_call_targets;

UINT64 g_cf_events_total = 0;
UINT64 g_cf_events_cjmp = 0;
UINT64 g_cf_events_jmp = 0;
UINT64 g_cf_events_call = 0;

// ----------------------------------------------------------------------
// KNOBs
// ----------------------------------------------------------------------
KNOB<std::string> KnobTrace(KNOB_MODE_WRITEONCE, "pintool",
    "o", "vmp_trace.txt", "instruction trace output file");

KNOB<std::string> KnobBytecode(KNOB_MODE_WRITEONCE, "pintool",
    "bc", "vmp_bytecode.csv", "bytecode/handler log output file");

KNOB<std::string> KnobRegs(KNOB_MODE_WRITEONCE, "pintool",
    "regs", "vmp_regs.txt", "register snapshot log output file");

KNOB<std::string> KnobMem(KNOB_MODE_WRITEONCE, "pintool",
    "mem", "vmp_mem.csv", "memory access log output file");

KNOB<std::string> KnobAnalysis(KNOB_MODE_WRITEONCE, "pintool",
    "analysis", "vmp_analysis.txt", "aggregate analysis output file");

KNOB<ADDRINT> KnobVMEntry(KNOB_MODE_WRITEONCE, "pintool",
    "entry", "0", "vm entry address (hex)");

KNOB<std::string> KnobHandlers(KNOB_MODE_WRITEONCE, "pintool",
    "handlers", "", "comma separated handler addresses (hex)");

KNOB<UINT64> KnobMaxInstr(KNOB_MODE_WRITEONCE, "pintool",
    "max", "0", "max instructions to record (0 = no limit)");

KNOB<BOOL> KnobTrackMem(KNOB_MODE_WRITEONCE, "pintool",
    "trackmem", "0", "track memory access (0/1)");

KNOB<BOOL> KnobMemVal(KNOB_MODE_WRITEONCE, "pintool",
    "memval", "0", "dump memory value with mem access (0/1)");

KNOB<BOOL> KnobVerbose(KNOB_MODE_WRITEONCE, "pintool",
    "v", "0", "verbose console output (0/1)");

KNOB<BOOL> KnobAutoDetect(KNOB_MODE_WRITEONCE, "pintool",
    "auto", "0", "auto handler candidate detection (0/1)");

KNOB<BOOL> KnobToolHelp(KNOB_MODE_WRITEONCE, "pintool",
    "h_tool", "0", "show vmp-devirt-lab usage and exit");

// ----------------------------------------------------------------------
// 유틸 함수
// ----------------------------------------------------------------------
static ThreadState* GetThreadState(THREADID tid)
{
    return reinterpret_cast<ThreadState*>(PIN_GetThreadData(g_tls_key, tid));
}

static std::string UintToStr(UINT32 v)
{
    char buf[32];
    sprintf(buf, "%u", (unsigned int)v);
    return std::string(buf);
}

static bool IsBCBaseReg(REG r)
{
    // generic regs: IA32/IA32E 공통
    return (r == REG_GSI || r == REG_GBX || r == REG_GDI);
}

static void ParseHandlers(const std::string& s)
{
    if (s.empty())
        return;

    size_t pos = 0;

    while (pos < s.size()) {
        size_t comma = s.find(',', pos);
        std::string token;
        if (comma == std::string::npos) {
            token = s.substr(pos);
            pos = s.size();
        }
        else {
            token = s.substr(pos, comma - pos);
            pos = comma + 1;
        }

        if (token.empty())
            continue;

        unsigned long long tmp = 0;
        if (sscanf(token.c_str(), "%llx", &tmp) != 1)
            continue;

        ADDRINT addr = (ADDRINT)tmp;
        if (addr == 0)
            continue;

        HandlerInfo h;
        h.addr = addr;
        h.id = g_next_handler_id++;
        h.name = std::string("handler") + UintToStr(h.id);
        h.call_count = 0;
        h.bc_vals.clear();
        h.is_auto = FALSE;

        g_handlers[addr] = h;
    }
}

static void DumpRegs(CONTEXT* ctx, FILE* f, const char* p)
{
    if (!f || !ctx)
        return;

    ADDRINT gax = PIN_GetContextReg(ctx, REG_GAX);
    ADDRINT gbx = PIN_GetContextReg(ctx, REG_GBX);
    ADDRINT gcx = PIN_GetContextReg(ctx, REG_GCX);
    ADDRINT gdx = PIN_GetContextReg(ctx, REG_GDX);
    ADDRINT gsi = PIN_GetContextReg(ctx, REG_GSI);
    ADDRINT gdi = PIN_GetContextReg(ctx, REG_GDI);
    ADDRINT gbp = PIN_GetContextReg(ctx, REG_GBP);
    ADDRINT sp = PIN_GetContextReg(ctx, REG_STACK_PTR);
    ADDRINT eflags = PIN_GetContextReg(ctx, REG_EFLAGS);

    fprintf(f, "%sGAX=0x%08x GBX=0x%08x GCX=0x%08x GDX=0x%08x\n",
        p, (unsigned int)gax, (unsigned int)gbx, (unsigned int)gcx, (unsigned int)gdx);
    fprintf(f, "%sGSI=0x%08x GDI=0x%08x GBP=0x%08x SP=0x%08x\n",
        p, (unsigned int)gsi, (unsigned int)gdi, (unsigned int)gbp, (unsigned int)sp);
    fprintf(f, "%sEFLAGS=0x%08x\n", p, (unsigned int)eflags);
}

static void PrintBanner()
{
    fprintf(stderr, "[%s] v%s by %s\n", TOOL_NAME, TOOL_VERSION, TOOL_AUTHOR);
}

static void PrintConfig()
{
    fprintf(stderr, "[%s] entry=" FMT_ADDR " max_instr=%llu trackmem=%d memval=%d verbose=%d auto=%d\n",
        TOOL_NAME,
        (ADDR_FMT_T)g_vm_entry,
        (unsigned long long)g_max_instr,
        (int)g_track_mem,
        (int)g_mem_val,
        (int)g_verbose,
        (int)g_auto_det);

    fprintf(stderr, "[%s] handlers=%zu\n",
        TOOL_NAME,
        g_handlers.size());
}

static void PrintInstr(UINT64 seq, ADDRINT ip, UINT32 size)
{
    if (!g_trace)
        return;

    fprintf(g_trace, "%llu," FMT_ADDR ",",
        (unsigned long long)seq,
        (ADDR_FMT_T)ip);

    unsigned char buf[32];
    UINT32 n = size;
    if (n > sizeof(buf))
        n = (UINT32)sizeof(buf);

    size_t c = PIN_SafeCopy(buf, reinterpret_cast<VOID*>(ip), n);
    for (size_t i = 0; i < c; i++) {
        fprintf(g_trace, "%02x", buf[i]);
        if (i + 1 < c)
            fprintf(g_trace, " ");
    }
    fprintf(g_trace, "\n");
}

// ----------------------------------------------------------------------
// 핸들러 처리
// ----------------------------------------------------------------------
static VOID HandleHandler(THREADID tid, UINT64 seq, ADDRINT ip, CONTEXT* ctx, ThreadState* ts)
{
    std::map<ADDRINT, HandlerInfo>::iterator it = g_handlers.find(ip);
    if (it == g_handlers.end())
        return;

    HandlerInfo& h = it->second;
    h.call_count++;
    g_total_handler_calls++;

    ADDRINT gax = PIN_GetContextReg(ctx, REG_GAX);
    ADDRINT gbx = PIN_GetContextReg(ctx, REG_GBX);
    ADDRINT gcx = PIN_GetContextReg(ctx, REG_GCX);
    ADDRINT gdx = PIN_GetContextReg(ctx, REG_GDX);
    ADDRINT gsi = PIN_GetContextReg(ctx, REG_GSI);
    ADDRINT gdi = PIN_GetContextReg(ctx, REG_GDI);
    ADDRINT gbp = PIN_GetContextReg(ctx, REG_GBP);
    ADDRINT sp = PIN_GetContextReg(ctx, REG_STACK_PTR);

    if (ts->last_bc_valid) {
        h.bc_vals.insert(ts->last_bc);
    }

    if (g_bc) {
        if (ts->last_bc_valid) {
            fprintf(g_bc,
                "%s,%u,%u,%llu," FMT_ADDR "," FMT_ADDR ",0x%08x,"
                "0x%08x,0x%08x,0x%08x,0x%08x,0x%08x,0x%08x,0x%08x,0x%08x\n",
                h.name.c_str(),
                (unsigned int)h.id,
                (unsigned int)tid,
                (unsigned long long)seq,
                (ADDR_FMT_T)ip,
                (ADDR_FMT_T)ts->last_bc_addr,
                (unsigned int)ts->last_bc,
                (unsigned int)gax,
                (unsigned int)gbx,
                (unsigned int)gcx,
                (unsigned int)gdx,
                (unsigned int)gsi,
                (unsigned int)gdi,
                (unsigned int)gbp,
                (unsigned int)sp);
        }
        else {
            fprintf(g_bc,
                "%s,%u,%u,%llu," FMT_ADDR ",INVALID,INVALID,"
                "0x%08x,0x%08x,0x%08x,0x%08x,0x%08x,0x%08x,0x%08x,0x%08x\n",
                h.name.c_str(),
                (unsigned int)h.id,
                (unsigned int)tid,
                (unsigned long long)seq,
                (ADDR_FMT_T)ip,
                (unsigned int)gax,
                (unsigned int)gbx,
                (unsigned int)gcx,
                (unsigned int)gdx,
                (unsigned int)gsi,
                (unsigned int)gdi,
                (unsigned int)gbp,
                (unsigned int)sp);
        }
    }

    if (g_regs) {
        fprintf(g_regs,
            "=== handler %s id=%u tid=%u seq=%llu ip=" FMT_ADDR " auto=%d ===\n",
            h.name.c_str(),
            (unsigned int)h.id,
            (unsigned int)tid,
            (unsigned long long)seq,
            (ADDR_FMT_T)ip,
            (int)h.is_auto);
        if (ts->last_bc_valid) {
            fprintf(g_regs,
                "  bytecode=0x%08x at " FMT_ADDR "\n",
                (unsigned int)ts->last_bc,
                (ADDR_FMT_T)ts->last_bc_addr);
        }
        else {
            fprintf(g_regs, "  bytecode=INVALID\n");
        }
        DumpRegs(ctx, g_regs, "  ");
        fprintf(g_regs, "\n");
    }

    if (g_verbose) {
        if (h.call_count <= 10 || (h.call_count % 20) == 0) {
            fprintf(stderr,
                "[%s] handler %s id=%u tid=%u calls=%llu seq=%llu bc_valid=%d bc=0x%08x\n",
                TOOL_NAME,
                h.name.c_str(),
                (unsigned int)h.id,
                (unsigned int)tid,
                (unsigned long long)h.call_count,
                (unsigned long long)seq,
                (int)ts->last_bc_valid,
                (unsigned int)(ts->last_bc_valid ? ts->last_bc : 0));
        }
    }
}

// ----------------------------------------------------------------------
// 바이트코드 추정용 메모리 read
// ----------------------------------------------------------------------
static VOID RecordBCRead(THREADID tid, ADDRINT ip, ADDRINT addr, UINT32 size)
{
    if (!g_has_main)
        return;

    if (addr < g_low || addr >= g_high)
        return;

    ThreadState* ts = GetThreadState(tid);
    if (!ts)
        return;
    if (ts->state != TRACE_RECORDING)
        return;

    UINT32 v = 0;
    UINT32 n = size;
    if (n > sizeof(v))
        n = (UINT32)sizeof(v);

    size_t c = PIN_SafeCopy(&v, reinterpret_cast<VOID*>(addr), n);
    if (c == 0) {
        ts->last_bc_valid = FALSE;
        return;
    }

    ts->last_bc_addr = addr;
    ts->last_bc = v;
    ts->last_bc_valid = TRUE;
}

// ----------------------------------------------------------------------
// 메모리 access 로깅 (주소/크기 + 선택적 값)
// ----------------------------------------------------------------------
static VOID RecordMemRead(THREADID tid, ADDRINT ip, ADDRINT addr, UINT32 size)
{
    if (!g_mem || !g_track_mem)
        return;

    ThreadState* ts = GetThreadState(tid);
    if (!ts)
        return;
    if (ts->state != TRACE_RECORDING)
        return;

    if (!g_mem_val) {
        fprintf(g_mem,
            "R,%u,%llu," FMT_ADDR "," FMT_ADDR ",%u\n",
            (unsigned int)tid,
            (unsigned long long)ts->seq,
            (ADDR_FMT_T)ip,
            (ADDR_FMT_T)addr,
            (unsigned int)size);
    }
    else {
        UINT64 val = 0;
        UINT32 n = size;
        if (n > 8)
            n = 8;
        size_t c = PIN_SafeCopy(&val, reinterpret_cast<VOID*>(addr), n);
        if (c == 0)
            val = 0;

        fprintf(g_mem,
            "R,%u,%llu," FMT_ADDR "," FMT_ADDR ",%u," FMT_VAL "\n",
            (unsigned int)tid,
            (unsigned long long)ts->seq,
            (ADDR_FMT_T)ip,
            (ADDR_FMT_T)addr,
            (unsigned int)size,
            (unsigned long long)val);
    }
}

static VOID RecordMemWrite(THREADID tid, ADDRINT ip, ADDRINT addr, UINT32 size)
{
    if (!g_mem || !g_track_mem)
        return;

    ThreadState* ts = GetThreadState(tid);
    if (!ts)
        return;
    if (ts->state != TRACE_RECORDING)
        return;

    if (!g_mem_val) {
        fprintf(g_mem,
            "W,%u,%llu," FMT_ADDR "," FMT_ADDR ",%u\n",
            (unsigned int)tid,
            (unsigned long long)ts->seq,
            (ADDR_FMT_T)ip,
            (ADDR_FMT_T)addr,
            (unsigned int)size);
    }
    else {
        UINT64 val = 0;
        UINT32 n = size;
        if (n > 8)
            n = 8;
        size_t c = PIN_SafeCopy(&val, reinterpret_cast<VOID*>(addr), n);
        if (c == 0)
            val = 0;

        fprintf(g_mem,
            "W,%u,%llu," FMT_ADDR "," FMT_ADDR ",%u," FMT_VAL "\n",
            (unsigned int)tid,
            (unsigned long long)ts->seq,
            (ADDR_FMT_T)ip,
            (ADDR_FMT_T)addr,
            (unsigned int)size,
            (unsigned long long)val);
    }
}

// ----------------------------------------------------------------------
// CF-edge 로깅
// ----------------------------------------------------------------------
static VOID RecordCF(ADDRINT from, ADDRINT to, UINT32 t)
{
    if (!g_has_main)
        return;

    if (from < g_low || from >= g_high)
        return;
    if (to < g_low || to >= g_high)
        return;

    g_cf_events_total++;
    if (t == CF_TYPE_CJMP)
        g_cf_events_cjmp++;
    else if (t == CF_TYPE_JMP)
        g_cf_events_jmp++;
    else if (t == CF_TYPE_CALL)
        g_cf_events_call++;

    std::pair<ADDRINT, ADDRINT> key(from, to);
    CFEdge& e = g_cf_edges[key];
    if (e.count == 0) {
        e.from = from;
        e.to = to;
        e.type = t;
    }
    e.count++;

    if (t == CF_TYPE_CALL) {
        g_call_targets[to]++;
    }
    else {
        g_jump_targets[to]++;
    }
}

// ----------------------------------------------------------------------
// VM entry 시점에서만 CONTEXT 사용: 기록 시작 + 레지스터 덤프
// ----------------------------------------------------------------------
static VOID VMEntryNotify(THREADID tid, ADDRINT ip, CONTEXT* ctx)
{
    if (!g_has_main)
        return;
    if (g_stop)
        return;

    if (ip < g_low || ip >= g_high)
        return;

    ThreadState* ts = GetThreadState(tid);
    if (!ts)
        return;

    if (ts->state != TRACE_IDLE)
        return;

    if (g_vm_entry != 0 && ip == g_vm_entry) {
        ts->state = TRACE_RECORDING;
        ts->vm_hits++;

        if (g_trace) {
            fprintf(g_trace,
                "#vm_entry tid=%u ip=" FMT_ADDR "\n",
                (unsigned int)tid,
                (ADDR_FMT_T)ip);
        }

        if (g_regs) {
            fprintf(g_regs,
                "=== vm_entry tid=%u ip=" FMT_ADDR " ===\n",
                (unsigned int)tid,
                (ADDR_FMT_T)ip);
            DumpRegs(ctx, g_regs, "  ");
            fprintf(g_regs, "\n");
        }
    }
}

// ----------------------------------------------------------------------
// 기본 인스트럭션 로깅 (CONTEXT 없이)
// ----------------------------------------------------------------------
static VOID RecordInstrLite(THREADID tid, ADDRINT ip, UINT32 size)
{
    if (!g_has_main)
        return;

    if (g_stop)
        return;

    if (ip < g_low || ip >= g_high)
        return;

    ThreadState* ts = GetThreadState(tid);
    if (!ts)
        return;

    if (ts->state == TRACE_DONE)
        return;

    if (g_max_instr && g_total_instr >= g_max_instr) {
        g_stop = TRUE;
        ts->state = TRACE_DONE;
        return;
    }

    if (ts->state != TRACE_RECORDING)
        return;

    ts->seq++;
    g_total_instr++;

    UINT64 seq = ts->seq;

    PrintInstr(seq, ip, size);
    // 핸들러 처리/레지스터 접근은 별도 HandlerEntry 콜백에서 CONTEXT 사용
}

// ----------------------------------------------------------------------
// 핸들러 엔트리에서만 CONTEXT 사용
// ----------------------------------------------------------------------
static VOID HandlerEntry(THREADID tid, ADDRINT ip, CONTEXT* ctx)
{
    if (!g_has_main)
        return;
    if (g_stop)
        return;

    if (ip < g_low || ip >= g_high)
        return;

    ThreadState* ts = GetThreadState(tid);
    if (!ts)
        return;
    if (ts->state != TRACE_RECORDING)
        return;

    UINT64 seq = ts->seq; // RecordInstrLite에서 이미 증가·동기화됨
    HandleHandler(tid, seq, ip, ctx, ts);
}

// ----------------------------------------------------------------------
// 이미지 로딩 시 메인 exe 범위 기록
// ----------------------------------------------------------------------
static VOID ImageLoad(IMG img, VOID* v)
{
    if (!IMG_IsMainExecutable(img))
        return;

    g_low = IMG_LowAddress(img);
    g_high = IMG_HighAddress(img);
    g_has_main = TRUE;

    if (g_trace) {
        fprintf(g_trace,
            "#image %s " FMT_ADDR " " FMT_ADDR "\n",
            IMG_Name(img).c_str(),
            (ADDR_FMT_T)g_low,
            (ADDR_FMT_T)g_high);
    }
}

// ----------------------------------------------------------------------
// 인스트루먼트: CONTEXT 분리 적용
// ----------------------------------------------------------------------
static VOID Instruction(INS ins, VOID* v)
{
    if (!g_has_main)
        return;

    ADDRINT ip = INS_Address(ins);
    if (ip < g_low || ip >= g_high)
        return;

    // VM entry 에서만 CONTEXT를 받는 콜백
    if (g_vm_entry != 0 && ip == g_vm_entry) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)VMEntryNotify,
            IARG_THREAD_ID,
            IARG_INST_PTR,
            IARG_CONTEXT,
            IARG_END);
    }

    // 모든 인스트럭션에 대해 가벼운 트레이스 (CONTEXT 없음)
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordInstrLite,
        IARG_THREAD_ID,
        IARG_INST_PTR,
        IARG_UINT32, INS_Size(ins),
        IARG_END);

    // 메모리 접근 로깅 (seq는 RecordInstrLite 이후에 증가)
    if (g_track_mem) {
        if (INS_IsMemoryRead(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
                IARG_THREAD_ID,
                IARG_INST_PTR,
                IARG_MEMORYREAD_EA,
                IARG_MEMORYREAD_SIZE,
                IARG_END);
        }
        if (INS_IsMemoryWrite(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
                IARG_THREAD_ID,
                IARG_INST_PTR,
                IARG_MEMORYWRITE_EA,
                IARG_MEMORYWRITE_SIZE,
                IARG_END);
        }
        if (INS_HasMemoryRead2(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
                IARG_THREAD_ID,
                IARG_INST_PTR,
                IARG_MEMORYREAD2_EA,
                IARG_MEMORYREAD_SIZE,
                IARG_END);
        }
    }

    // 바이트코드 후보 메모리 read
    if (INS_IsMemoryRead(ins)) {
        REG base = INS_MemoryBaseReg(ins);
        if (IsBCBaseReg(base)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordBCRead,
                IARG_THREAD_ID,
                IARG_INST_PTR,
                IARG_MEMORYREAD_EA,
                IARG_MEMORYREAD_SIZE,
                IARG_END);
        }
    }

    // CF-edge (분기/콜)
    if (INS_IsCall(ins)) {
        INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)RecordCF,
            IARG_INST_PTR,
            IARG_BRANCH_TARGET_ADDR,
            IARG_UINT32, (UINT32)CF_TYPE_CALL,
            IARG_END);
    }
    else if (INS_IsBranch(ins)) {
        UINT32 t = (UINT32)CF_TYPE_JMP;
        if (INS_HasFallThrough(ins))
            t = (UINT32)CF_TYPE_CJMP;
        INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)RecordCF,
            IARG_INST_PTR,
            IARG_BRANCH_TARGET_ADDR,
            IARG_UINT32, t,
            IARG_END);
    }

    // 수동 지정된 핸들러 주소에만 CONTEXT 콜백 추가
    if (!g_handlers.empty()) {
        if (g_handlers.find(ip) != g_handlers.end()) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)HandlerEntry,
                IARG_THREAD_ID,
                IARG_INST_PTR,
                IARG_CONTEXT,
                IARG_END);
        }
    }
}

// ----------------------------------------------------------------------
// Auto handler 후보 생성 + 분석 출력
// ----------------------------------------------------------------------
static bool CmpAddrScore64(const std::pair<ADDRINT, UINT64>& a,
    const std::pair<ADDRINT, UINT64>& b)
{
    return a.second > b.second;
}

static bool CmpAddrScore32(const std::pair<ADDRINT, UINT32>& a,
    const std::pair<ADDRINT, UINT32>& b)
{
    return a.second > b.second;
}

static void BuildAutoHandlers()
{
    if (!g_auto_det)
        return;
    if (!g_has_main)
        return;

    std::map<ADDRINT, UINT64> score;

    std::map<ADDRINT, UINT32>::const_iterator it1;
    for (it1 = g_jump_targets.begin(); it1 != g_jump_targets.end(); ++it1) {
        score[it1->first] += it1->second;
    }
    std::map<ADDRINT, UINT32>::const_iterator it2;
    for (it2 = g_call_targets.begin(); it2 != g_call_targets.end(); ++it2) {
        score[it2->first] += it2->second;
    }

    std::vector< std::pair<ADDRINT, UINT64> > vec;
    vec.reserve(score.size());
    std::map<ADDRINT, UINT64>::const_iterator it3;
    for (it3 = score.begin(); it3 != score.end(); ++it3) {
        vec.push_back(*it3);
    }

    std::sort(vec.begin(), vec.end(), CmpAddrScore64);

    size_t limit = 64;
    size_t added = 0;

    for (size_t i = 0; i < vec.size() && added < limit; ++i) {
        ADDRINT addr = vec[i].first;
        UINT64 cnt = vec[i].second;
        if (cnt == 0)
            continue;
        if (addr < g_low || addr >= g_high)
            continue;
        if (g_handlers.find(addr) != g_handlers.end())
            continue;

        HandlerInfo h;
        h.addr = addr;
        h.id = g_next_handler_id++;
        h.name = std::string("auto_") + UintToStr(h.id);
        h.call_count = 0;
        h.bc_vals.clear();
        h.is_auto = TRUE;

        g_handlers[addr] = h;
        added++;
    }
}

static void DumpTopTargets(FILE* f, const char* label,
    const std::map<ADDRINT, UINT32>& m, size_t topn)
{
    if (!f)
        return;

    std::vector< std::pair<ADDRINT, UINT32> > v;
    v.reserve(m.size());
    std::map<ADDRINT, UINT32>::const_iterator it;
    for (it = m.begin(); it != m.end(); ++it) {
        v.push_back(*it);
    }

    std::sort(v.begin(), v.end(), CmpAddrScore32);

    fprintf(f, "[%s] top %u targets:\n", label, (unsigned int)topn);
    size_t n = v.size();
    if (n > topn)
        n = topn;
    for (size_t i = 0; i < n; ++i) {
        fprintf(f, "  " FMT_ADDR " : %u\n",
            (ADDR_FMT_T)v[i].first,
            (unsigned int)v[i].second);
    }
    fprintf(f, "\n");
}

static void WriteAnalysis()
{
    if (!g_ana)
        return;

    fprintf(g_ana, "# %s v%s by %s\n", TOOL_NAME, TOOL_VERSION, TOOL_AUTHOR);
    fprintf(g_ana, "# analysis summary\n\n");

    fprintf(g_ana, "summary:\n");
    fprintf(g_ana, "  total_instr=%llu\n", (unsigned long long)g_total_instr);
    fprintf(g_ana, "  total_handler_calls=%llu\n", (unsigned long long)g_total_handler_calls);
    fprintf(g_ana, "  handlers_total=%zu\n", g_handlers.size());
    fprintf(g_ana, "  cf_events_total=%llu\n", (unsigned long long)g_cf_events_total);
    fprintf(g_ana, "  cf_events_cjmp=%llu\n", (unsigned long long)g_cf_events_cjmp);
    fprintf(g_ana, "  cf_events_jmp=%llu\n", (unsigned long long)g_cf_events_jmp);
    fprintf(g_ana, "  cf_events_call=%llu\n", (unsigned long long)g_cf_events_call);
    fprintf(g_ana, "  cf_edges_unique=%zu\n\n", g_cf_edges.size());

    UINT64 uniq_cjmp = 0;
    UINT64 uniq_jmp = 0;
    UINT64 uniq_call = 0;
    std::map< std::pair<ADDRINT, ADDRINT>, CFEdge >::const_iterator it;
    for (it = g_cf_edges.begin(); it != g_cf_edges.end(); ++it) {
        const CFEdge& e = it->second;
        if (e.type == CF_TYPE_CJMP)
            uniq_cjmp++;
        else if (e.type == CF_TYPE_JMP)
            uniq_jmp++;
        else if (e.type == CF_TYPE_CALL)
            uniq_call++;
    }

    fprintf(g_ana, "cf_edges_unique_by_type:\n");
    fprintf(g_ana, "  cjmp=%llu\n", (unsigned long long)uniq_cjmp);
    fprintf(g_ana, "  jmp=%llu\n", (unsigned long long)uniq_jmp);
    fprintf(g_ana, "  call=%llu\n\n", (unsigned long long)uniq_call);

    fprintf(g_ana, "handlers:\n");
    std::map<ADDRINT, HandlerInfo>::const_iterator hit;
    for (hit = g_handlers.begin(); hit != g_handlers.end(); ++hit) {
        const HandlerInfo& h = hit->second;

        UINT32 jt = 0;
        std::map<ADDRINT, UINT32>::const_iterator jt_it = g_jump_targets.find(h.addr);
        if (jt_it != g_jump_targets.end())
            jt = jt_it->second;

        UINT32 ct = 0;
        std::map<ADDRINT, UINT32>::const_iterator ct_it = g_call_targets.find(h.addr);
        if (ct_it != g_call_targets.end())
            ct = ct_it->second;

        fprintf(g_ana,
            "  handler addr=" FMT_ADDR " name=%s id=%u auto=%d "
            "calls=%llu bc_unique=%u jumps=%u calls_to=%u\n",
            (ADDR_FMT_T)h.addr,
            h.name.c_str(),
            (unsigned int)h.id,
            (int)h.is_auto,
            (unsigned long long)h.call_count,
            (unsigned int)h.bc_vals.size(),
            (unsigned int)jt,
            (unsigned int)ct);
    }
    fprintf(g_ana, "\n");

    DumpTopTargets(g_ana, "jump_targets", g_jump_targets, 32);
    DumpTopTargets(g_ana, "call_targets", g_call_targets, 32);

    if (g_auto_det) {
        fprintf(g_ana, "auto_handler_candidates:\n");
        for (hit = g_handlers.begin(); hit != g_handlers.end(); ++hit) {
            const HandlerInfo& h = hit->second;
            if (!h.is_auto)
                continue;

            UINT32 jt = 0;
            std::map<ADDRINT, UINT32>::const_iterator jt_it = g_jump_targets.find(h.addr);
            if (jt_it != g_jump_targets.end())
                jt = jt_it->second;

            UINT32 ct = 0;
            std::map<ADDRINT, UINT32>::const_iterator ct_it = g_call_targets.find(h.addr);
            if (ct_it != g_call_targets.end())
                ct = ct_it->second;

            fprintf(g_ana,
                "  auto addr=" FMT_ADDR " name=%s id=%u jumps=%u calls=%u\n",
                (ADDR_FMT_T)h.addr,
                h.name.c_str(),
                (unsigned int)h.id,
                (unsigned int)jt,
                (unsigned int)ct);
        }

        fprintf(g_ana, "\nrecommended_handlers_option:\n  -handlers ");
        bool first = true;
        for (hit = g_handlers.begin(); hit != g_handlers.end(); ++hit) {
            const HandlerInfo& h = hit->second;
            if (!h.is_auto)
                continue;
            if (!first)
                fprintf(g_ana, ",");
            fprintf(g_ana, FMT_ADDR, (ADDR_FMT_T)h.addr);
            first = false;
        }
        fprintf(g_ana, "\n");
    }
}

// ----------------------------------------------------------------------
// 종료 처리
// ----------------------------------------------------------------------
static VOID Fini(INT32 code, VOID* v)
{
    BuildAutoHandlers();
    WriteAnalysis();

    fprintf(stderr,
        "[%s] done: total_instr=%llu total_handler_calls=%llu handlers=%zu cf_edges=%zu\n",
        TOOL_NAME,
        (unsigned long long)g_total_instr,
        (unsigned long long)g_total_handler_calls,
        g_handlers.size(),
        g_cf_edges.size());

    if (g_trace) {
        fprintf(g_trace,
            "#summary total_instr=%llu total_handler_calls=%llu\n",
            (unsigned long long)g_total_instr,
            (unsigned long long)g_total_handler_calls);
        fclose(g_trace);
        g_trace = 0;
    }

    if (g_bc) {
        fclose(g_bc);
        g_bc = 0;
    }

    if (g_regs) {
        fclose(g_regs);
        g_regs = 0;
    }

    if (g_mem) {
        fclose(g_mem);
        g_mem = 0;
    }

    if (g_ana) {
        fclose(g_ana);
        g_ana = 0;
    }
}

// ----------------------------------------------------------------------
// 스레드 시작/종료
// ----------------------------------------------------------------------
static VOID ThreadStart(THREADID tid, CONTEXT* ctx, INT32 flags, VOID* v)
{
    ThreadState* ts = new ThreadState;
    ts->state = TRACE_IDLE;
    ts->seq = 0;
    ts->last_bc_addr = 0;
    ts->last_bc = 0;
    ts->last_bc_valid = FALSE;
    ts->vm_hits = 0;
    PIN_SetThreadData(g_tls_key, ts, tid);
}

static VOID ThreadFini(THREADID tid, const CONTEXT* ctx, INT32 code, VOID* v)
{
    ThreadState* ts = GetThreadState(tid);
    if (ts) {
        delete ts;
        PIN_SetThreadData(g_tls_key, 0, tid);
    }
}

// ----------------------------------------------------------------------
// 사용법 출력
// ----------------------------------------------------------------------
static void PrintUsage()
{
    fprintf(stderr, "\n%s v%s by %s\n", TOOL_NAME, TOOL_VERSION, TOOL_AUTHOR);
    fprintf(stderr, "Dynamic tracer for VMProtect-style virtual machines.\n\n");
    fprintf(stderr, "Usage (simplified):\n");
    fprintf(stderr, "  pin -t vmp-devirt-lab.dll \\\n");
    fprintf(stderr, "      -entry 0x<vm_entry> \\\n");
    fprintf(stderr, "      -handlers 0x<handler1>,0x<handler2>,... \\\n");
    fprintf(stderr, "      -o trace.txt -bc bc.csv -regs regs.txt \\\n");
    fprintf(stderr, "      [-mem mem.csv -trackmem 1 [-memval 1]] \\\n");
    fprintf(stderr, "      [-analysis vmp_analysis.txt] \\\n");
    fprintf(stderr, "      [-auto 1] [-max N] [-v 1] -- <target.exe> [args]\n\n");
    fprintf(stderr, "Knobs:\n");
    fprintf(stderr, "  -entry      vm entry address (hex, required)\n");
    fprintf(stderr, "  -handlers   comma separated handler addresses (hex)\n");
    fprintf(stderr, "  -o          instruction trace file (default vmp_trace.txt)\n");
    fprintf(stderr, "  -bc         bytecode/handler csv file (default vmp_bytecode.csv)\n");
    fprintf(stderr, "  -regs       register log file (default vmp_regs.txt)\n");
    fprintf(stderr, "  -mem        memory access csv file (default vmp_mem.csv)\n");
    fprintf(stderr, "  -trackmem   track memory access (0/1, default 0)\n");
    fprintf(stderr, "  -memval     dump memory value with access (0/1, default 0)\n");
    fprintf(stderr, "  -analysis   analysis summary file (default vmp_analysis.txt)\n");
    fprintf(stderr, "  -auto       auto handler candidate detection (0/1, default 0)\n");
    fprintf(stderr, "  -max        max instructions to record (0 = no limit)\n");
    fprintf(stderr, "  -v          verbose console output (0/1)\n");
    fprintf(stderr, "  -h_tool 1   show this usage and exit\n\n");
    fprintf(stderr, "Note: use Pin's -h to see all pintool knobs as well.\n\n");
}

// ----------------------------------------------------------------------
// main
// ----------------------------------------------------------------------
int main(int argc, char* argv[])
{
    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) {
        PrintUsage();
        return 1;
    }

    g_vm_entry = KnobVMEntry.Value();
    g_max_instr = KnobMaxInstr.Value();
    g_track_mem = KnobTrackMem.Value();
    g_mem_val = KnobMemVal.Value();
    g_verbose = KnobVerbose.Value();
    g_auto_det = KnobAutoDetect.Value();

    if (KnobToolHelp.Value()) {
        PrintUsage();
        return 0;
    }

    ParseHandlers(KnobHandlers.Value());

    std::string trace_name = KnobTrace.Value();
    if (!trace_name.empty()) {
        g_trace = fopen(trace_name.c_str(), "w");
        if (g_trace) {
            fprintf(g_trace, "# %s v%s by %s\n", TOOL_NAME, TOOL_VERSION, TOOL_AUTHOR);
            fprintf(g_trace, "# seq,ip,bytes\n");
        }
    }

    std::string bc_name = KnobBytecode.Value();
    if (!bc_name.empty()) {
        g_bc = fopen(bc_name.c_str(), "w");
        if (g_bc) {
            fprintf(g_bc, "# %s v%s by %s\n", TOOL_NAME, TOOL_VERSION, TOOL_AUTHOR);
            fprintf(g_bc,
                "name,id,tid,seq,ip,bc_addr,bc_val,"
                "gax,gbx,gcx,gdx,gsi,gdi,gbp,sp\n");
        }
    }

    std::string regs_name = KnobRegs.Value();
    if (!regs_name.empty()) {
        g_regs = fopen(regs_name.c_str(), "w");
        if (g_regs) {
            fprintf(g_regs, "# %s v%s by %s\n", TOOL_NAME, TOOL_VERSION, TOOL_AUTHOR);
        }
    }

    std::string mem_name = KnobMem.Value();
    if (!mem_name.empty()) {
        g_mem = fopen(mem_name.c_str(), "w");
        if (g_mem) {
            fprintf(g_mem, "# %s v%s by %s\n", TOOL_NAME, TOOL_VERSION, TOOL_AUTHOR);
            if (!g_mem_val) {
                fprintf(g_mem, "type,tid,seq,ip,addr,size\n");
            }
            else {
                fprintf(g_mem, "type,tid,seq,ip,addr,size,val\n");
            }
        }
    }

    std::string ana_name = KnobAnalysis.Value();
    if (!ana_name.empty()) {
        g_ana = fopen(ana_name.c_str(), "w");
        if (g_ana) {
            fprintf(g_ana, "# %s v%s by %s\n", TOOL_NAME, TOOL_VERSION, TOOL_AUTHOR);
        }
    }

    g_tls_key = PIN_CreateThreadDataKey(0);

    PrintBanner();
    PrintConfig();

    IMG_AddInstrumentFunction(ImageLoad, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();
    return 0;
}
