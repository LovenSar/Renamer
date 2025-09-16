#!/usr/bin/env python
# -*- coding: utf-8 -*-

from idaapi import *
from idc import *
from idautils import *
import ida_kernwin
import ida_funcs
import ida_hexrays
import ida_lines
import ida_auto
import ida_bytes
import ida_nalt
import idaapi
import time
import os
import sys
import json
import requests
import threading
import asyncio
import random
from collections import defaultdict, deque
import re
import heapq
try:
    import aiohttp
    HAS_AIOHTTP = True
except Exception:
    HAS_AIOHTTP = False
from concurrent.futures import ThreadPoolExecutor, as_completed

# Global LLM hook for data-aware components
renamer_llm = None

# ==================== Configuration ====================
class Config:
    """Configuration"""
    # OpenAI-compatible API configuration
    API_BASE_URL = "Your-api-base-url"  # Your API base URL
    API_KEY = "Your-api-key"  # Your API key
    MODEL_NAME = "Your-model-name"  # Model name
    
    # Analysis configuration
    MAX_CONTEXT_DEPTH = 1  # Context depth (1-layer callers and callees)
    MAX_ASM_LINES = 1000    # Max assembly lines
    MAX_PSEUDOCODE_LINES = 2000  # Max pseudocode lines
    BATCH_SIZE = 10  # Functions per batch
    MAX_WORKERS = 4  # Concurrent LLM request workers
    USE_ASYNC = True  # Use aiohttp async concurrency
    REQUESTS_PER_MIN = 60  # Global rate limit per minute
    MAX_RETRIES = 3  # Retry attempts
    RETRY_BACKOFF_BASE = 0.5  # Retry backoff base seconds

    # Data-aware graph configuration
    DATA_AWARE_ENABLED = True
    MIN_STRING_LEN = 3  # Minimum readable string length
    ZERO_GAP_MAX = 0x20  # Max consecutive 0x00 bytes to consider contiguous string cluster
    INDIRECT_STRING_SCAN_WINDOW = 0x200  # Max backward scan window for finding anchor string
    MAX_INDIRECT_CHECKS_PER_RUN = 50  # Limit LLM checks per run
    DATA_BATCH_SIZE = 5  # Functions per batch for data renaming
    MAX_DATA_PSEUDOCODE_LINES = 600  # Pseudocode lines for data context
    EXPORT_DATA_GRAPH = True
    DATA_MAX_WORKERS = 6  # Concurrent LLM workers for data rename
    # Indirect string array check (batch)
    INDIRECT_BATCH_SIZE = 10  # Contexts per batch for indirect string checks
    INDIRECT_MAX_WORKERS = 6  # Concurrent workers for indirect checks

    # FCG export configuration
    FCG_EXPORT_ENABLED = True
    FCG_OUTPUT_DIR = "fcg_output"  # Output root directory (timestamped subdirectory will be created)
    FCG_EXPORT_FORMATS = ["json", "dot", "txt", "csv"]  # Supported: json/dot/txt/csv
    FCG_SUMMARY_TOPN = 20  # Number of top nodes shown in summary
    
    # Logging configuration
    LOG_ENABLED = True
    LOG_FILE = f"private_func_rename_{time.strftime('%Y%m%d_%H%M%S')}.log"
    DETAILED_LOG_FILE = f"private_func_rename_detailed_{time.strftime('%Y%m%d_%H%M%S')}.jsonl"
    CONSOLE_QUIET = True  # Minimal console output

# ==================== Logging ====================
class Logger:
    """Logger"""
    def __init__(self, enabled=True, log_file=None, detailed_log_file=None, console_quiet=True):
        self.enabled = enabled
        self.log_file = None
        self.console_quiet = console_quiet
        self.detailed_log_path = detailed_log_file
        if enabled and log_file:
            try:
                self.log_file = open(log_file, 'w', encoding='utf-8')
                self.log(f"Log file created: {os.path.abspath(log_file)}")
                if detailed_log_file:
                    # Create an empty JSONL file
                    open(detailed_log_file, 'w', encoding='utf-8').close()
                    self.log(f"Detailed log: {os.path.abspath(detailed_log_file)}")
            except Exception as e:
                print(f"Failed to create log file: {e}")
    
    def log(self, message, level="INFO"):
        """Write log message"""
        if not self.enabled:
            return
        
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"[{timestamp}] [{level}] {message}"
        
        should_print = True
        if self.console_quiet and level not in ["ERROR", "WARNING"]:
            # Print only key progress or start/stop information
            important = any(message.startswith(prefix) for prefix in [
                "Private function renamer",
                "Data-aware Global/Data Renamer",
                "Completed",
                "Progress",
                "Building function call graph",
                "Exporting function call graph",
                "Computing private function density",
                "--- Iteration "
            ])
            should_print = important
        if should_print:
            print(log_msg)
        if self.log_file:
            try:
                self.log_file.write(log_msg + "\n")
                self.log_file.flush()
            except:
                pass
    
    def log_llm_interaction(self, func_ea, func_name, request_data, response_data, duration_seconds):
        """Record detailed LLM interaction into JSONL"""
        if not self.enabled or not self.detailed_log_path:
            return
        record = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "function_ea": f"0x{func_ea:X}",
            "function_name": func_name,
            "duration_seconds": round(duration_seconds, 2),
            "request": request_data,
            "response": response_data
        }
        try:
            with open(self.detailed_log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception as e:
            # Detailed log write failure does not affect the main flow
            pass
    
    def close(self):
        """Close log file"""
        if self.log_file:
            self.log_file.close()

# ==================== Rate limiters ====================
class RateLimiter:
    """Simple per-minute rate limiter (thread-safe)"""
    def __init__(self, requests_per_min):
        self.capacity = max(1, int(requests_per_min))
        self.timestamps = deque()
        self.lock = threading.Lock()
    
    def acquire(self):
        while True:
            with self.lock:
                now = time.monotonic()
                # Cleanup timestamps older than 60s
                while self.timestamps and (now - self.timestamps[0]) >= 60.0:
                    self.timestamps.popleft()
                if len(self.timestamps) < self.capacity:
                    self.timestamps.append(now)
                    return
                # Need to wait until the oldest record expires
                wait = 60.0 - (now - self.timestamps[0])
            time.sleep(max(0.01, wait))

class AsyncRateLimiter:
    """Async per-minute rate limiter"""
    def __init__(self, requests_per_min):
        self.capacity = max(1, int(requests_per_min))
        self.timestamps = deque()
        self.lock = asyncio.Lock()
    
    async def acquire(self):
        while True:
            async with self.lock:
                now = time.monotonic()
                while self.timestamps and (now - self.timestamps[0]) >= 60.0:
                    self.timestamps.popleft()
                if len(self.timestamps) < self.capacity:
                    self.timestamps.append(now)
                    return
                wait = 60.0 - (now - self.timestamps[0])
            await asyncio.sleep(max(0.01, wait))

# ==================== Function Call Graph ====================
class FunctionCallGraph:
    """Function call graph model"""
    def __init__(self, logger=None):
        self.logger = logger or Logger(False)
        self.nodes = {}  # {func_ea: {'name': str, 'is_private': bool}}
        self.edges = defaultdict(set)  # {caller_ea: set(callee_ea, ...)}
        self.reverse_edges = defaultdict(set)  # {callee_ea: set(caller_ea, ...)}
        self.density = {}  # {func_ea: float} density value
        self.in_degree_sum = 0  # total in-degree (sanity equals edges count)
        
    def build_graph(self):
        """Build the full program function call graph"""
        self.logger.log("Building function call graph...")
        # Ensure auto-analysis is complete; otherwise CodeRefs/Xrefs may be incomplete
        try:
            ida_auto.auto_wait()
        except Exception:
            pass
        
        # Iterate over all functions
        for func_ea in Functions():
            func_name = get_func_name(func_ea)
            if not func_name:
                continue
            
            # Private function if name starts with sub_
            is_private = func_name.startswith("sub_")
            
            self.nodes[func_ea] = {
                'name': func_name,
                'is_private': is_private,
                'renamed': False
            }
            
            # Analyze call relationships
            func = get_func(func_ea)
            if not func:
                continue
            
            # Iterate through all instructions
            for head in Heads(func.start_ea, func.end_ea):
                if not is_code(get_full_flags(head)):
                    continue
                # Unified call detection: prefer is_call_insn; fallback to mnemonic match (multi-arch)
                is_call = False
                try:
                    if idaapi.is_call_insn(head):
                        is_call = True
                except Exception:
                    pass
                if not is_call:
                    mnem = (print_insn_mnem(head) or "").lower()
                    if mnem in [
                        "call", "calls",              # x86 etc
                        "jal", "jalr", "bal",        # MIPS
                        "bl", "blx",                  # ARM/Thumb
                        "bctrl", "bsr"                 # PPC / others
                    ]:
                        is_call = True
                if not is_call:
                    continue
                # Use code references to get callee target
                for callee_ea in CodeRefsFrom(head, 0):
                    callee_func = get_func(callee_ea)
                    if callee_func:
                        callee_start = callee_func.start_ea
                        self.edges[func_ea].add(callee_start)
                        self.reverse_edges[callee_start].add(func_ea)
        
        edges_count = sum(len(e) for e in self.edges.values())
        self.logger.log(f"Call graph built: {len(self.nodes)} nodes, {edges_count} edges")
        # Compute and log in-degree sum for diagnostics
        self.in_degree_sum = sum(len(e) for e in self.reverse_edges.values())
        self.logger.log(f"In-degree sum: {self.in_degree_sum}")
        if edges_count == 0:
            self.logger.log(
                "No call edges were found. Auto-analysis may be incomplete or call detection too strict for this CPU."
                " Consider re-analyzing the binary or verifying architecture-specific call patterns.",
                "WARNING"
            )
        
        # Count private functions
        private_count = sum(1 for node in self.nodes.values() if node['is_private'])
        self.logger.log(f"Found {private_count} private functions to rename")
    
    def calculate_density(self):
        """Compute density for each private function node"""
        self.logger.log("Computing private function density...")
        
        for func_ea, node_info in self.nodes.items():
            if not node_info['is_private']:
                continue
            
            # Collect neighbors (inbound + outbound)
            neighbors = set()
            neighbors.update(self.edges.get(func_ea, set()))  # callees
            neighbors.update(self.reverse_edges.get(func_ea, set()))  # callers
            
            if not neighbors:
                self.density[func_ea] = 1.0  # No neighbors, highest density
                continue
            
            # Ratio of official (non-private) neighbors
            official_count = sum(1 for n in neighbors 
                               if n in self.nodes and not self.nodes[n]['is_private'])
            
            # Higher ratio => lower density
            ratio = official_count / len(neighbors)
            self.density[func_ea] = 1.0 - ratio
        
        self.logger.log(f"Density computed for {len(self.density)} private functions")

    def export_call_graph(self, output_dir, formats=("json", "dot", "txt", "csv"), summary_topn=20):
        """Export the call graph into files.
        formats: iterable of 'json' | 'dot' | 'txt' | 'csv'
        """
        try:
            ts = time.strftime('%Y%m%d_%H%M%S')
            root = os.path.join(output_dir, ts)
            os.makedirs(root, exist_ok=True)
            self.logger.log(f"Exporting function call graph to: {os.path.abspath(root)}")

            # Prepare summary
            nodes_count = len(self.nodes)
            edges_count = sum(len(e) for e in self.edges.values())
            private_count = sum(1 for node in self.nodes.values() if node['is_private'])
            summary = {
                'nodes': nodes_count,
                'edges': edges_count,
                'private_functions': private_count,
                'in_degree_sum': sum(len(s) for s in self.reverse_edges.values()),
                'input_file': get_root_filename() if 'get_root_filename' in globals() else '',
                'timestamp': ts
            }

            # Degrees
            in_degrees = {ea: len(self.reverse_edges.get(ea, set())) for ea in self.nodes}
            out_degrees = {ea: len(self.edges.get(ea, set())) for ea in self.nodes}

            # JSON export
            if "json" in formats:
                data = {
                    'summary': summary,
                    'nodes': [
                        {
                            'ea': ea,
                            'ea_hex': f"0x{ea:X}",
                            'name': info['name'],
                            'is_private': info['is_private'],
                            'in_degree': in_degrees.get(ea, 0),
                            'out_degree': out_degrees.get(ea, 0)
                        }
                        for ea, info in self.nodes.items()
                    ],
                    'edges': [
                        {
                            'src': src,
                            'src_hex': f"0x{src:X}",
                            'dst': dst,
                            'dst_hex': f"0x{dst:X}"
                        }
                        for src, dsts in self.edges.items() for dst in sorted(dsts)
                    ]
                }
                with open(os.path.join(root, 'call_graph.json'), 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)

            # DOT export
            if "dot" in formats:
                def esc(label: str) -> str:
                    return label.replace('"', '\"')
                with open(os.path.join(root, 'call_graph.dot'), 'w', encoding='utf-8') as f:
                    f.write('digraph call_graph {\n')
                    f.write('  rankdir=LR;\n  node [shape=box, style=rounded];\n')
                    for ea, info in self.nodes.items():
                        label = f"{info['name']}\\n0x{ea:X}"
                        color = 'lightgray' if not info['is_private'] else 'white'
                        f.write(f'  n{ea} [label="{esc(label)}", fillcolor={color}, style="filled,rounded"];\n')
                    for src, dsts in self.edges.items():
                        for dst in dsts:
                            f.write(f'  n{src} -> n{dst};\n')
                    f.write('}\n')

            # TXT summary
            if "txt" in formats:
                lines = []
                lines.append(f"Nodes: {nodes_count}")
                lines.append(f"Edges: {edges_count}")
                lines.append(f"Private functions: {private_count}")
                lines.append("")
                # Top by out-degree
                top_out = sorted(self.nodes.keys(), key=lambda ea: out_degrees.get(ea, 0), reverse=True)[:summary_topn]
                lines.append(f"Top {summary_topn} by out-degree:")
                for ea in top_out:
                    lines.append(f"  0x{ea:X} {self.nodes[ea]['name']}  out={out_degrees.get(ea,0)}  in={in_degrees.get(ea,0)}")
                lines.append("")
                # Top by in-degree
                top_in = sorted(self.nodes.keys(), key=lambda ea: in_degrees.get(ea, 0), reverse=True)[:summary_topn]
                lines.append(f"Top {summary_topn} by in-degree:")
                for ea in top_in:
                    lines.append(f"  0x{ea:X} {self.nodes[ea]['name']}  in={in_degrees.get(ea,0)}  out={out_degrees.get(ea,0)}")
                with open(os.path.join(root, 'call_graph_summary.txt'), 'w', encoding='utf-8') as f:
                    f.write("\n".join(lines))

            # CSV edges
            if "csv" in formats:
                with open(os.path.join(root, 'call_graph_edges.csv'), 'w', encoding='utf-8') as f:
                    f.write("src_ea_hex,src_name,dst_ea_hex,dst_name\n")
                    for src, dsts in self.edges.items():
                        for dst in dsts:
                            f.write(f"0x{src:X},{self.nodes[src]['name']},0x{dst:X},{self.nodes[dst]['name']}\n")

            self.logger.log("FCG export completed")
        except Exception as e:
            self.logger.log(f"FCG export failed: {e}", "ERROR")
    
    # Removed: get_lowest_density_functions (now inlined in run)
    
    def mark_function_renamed(self, func_ea):
        """Mark function as renamed and refresh neighbors' density"""
        if func_ea in self.nodes:
            self.nodes[func_ea]['is_private'] = False
            self.nodes[func_ea]['renamed'] = True
        if func_ea in self.density:
            del self.density[func_ea]
        
        # Recompute density for affected neighbors
        neighbors = set()
        neighbors.update(self.edges.get(func_ea, set()))
        neighbors.update(self.reverse_edges.get(func_ea, set()))
        
        for neighbor in neighbors:
            if neighbor in self.nodes and self.nodes[neighbor]['is_private']:
                # Recompute neighbor density
                all_neighbors = set()
                all_neighbors.update(self.edges.get(neighbor, set()))
                all_neighbors.update(self.reverse_edges.get(neighbor, set()))
                
                if all_neighbors:
                    official_count = sum(1 for n in all_neighbors 
                                       if n in self.nodes and not self.nodes[n]['is_private'])
                    self.density[neighbor] = 1.0 - (official_count / len(all_neighbors))

# ==================== Code Analyzer ====================
class CodeAnalyzer:
    """Analyzer for assembly, pseudocode and context"""
    def __init__(self, logger=None):
        self.logger = logger or Logger(False)
    
    def get_assembly_code(self, func_ea, max_lines=100):
        """Return assembly listing of the function"""
        try:
            func = get_func(func_ea)
            if not func:
                return ""
            
            asm_lines = []
            line_count = 0
            
            for head in Heads(func.start_ea, func.end_ea):
                if line_count >= max_lines:
                    asm_lines.append("... (more assembly truncated)")
                    break
                
                if is_code(get_full_flags(head)):
                    disasm = generate_disasm_line(head, 0)
                    if disasm:
                        # Remove ANSI tags
                        clean_disasm = ida_lines.tag_remove(disasm)
                        asm_lines.append(f"0x{head:X}: {clean_disasm}")
                        line_count += 1
            
            return "\n".join(asm_lines)
        except Exception as e:
            self.logger.log(f"Failed to get assembly: {e}", "ERROR")
            return ""
    
    def get_pseudocode(self, func_ea, max_lines=200):
        """Return Hex-Rays pseudocode of the function"""
        try:
            # Try to decompile
            cfunc = None
            try:
                cfunc = ida_hexrays.decompile(func_ea)
            except:
                self.logger.log(f"Function 0x{func_ea:X} cannot be decompiled", "WARNING")
                return ""
            
            if not cfunc:
                return ""
            
            # Get pseudocode text
            pseudocode = str(cfunc)
            lines = pseudocode.split('\n')
            
            if len(lines) > max_lines:
                lines = lines[:max_lines]
                lines.append("... (more pseudocode truncated)")
            
            return "\n".join(lines)
        except Exception as e:
            self.logger.log(f"Failed to get pseudocode: {e}", "ERROR")
            return ""

    def get_bytes_preview(self, ea, size=32):
        try:
            data = ida_bytes.get_bytes(ea, min(size, 64))
            if not data:
                return ""
            return " ".join(f"{b:02X}" for b in data)
        except Exception:
            return ""

    def get_string_preview(self, ea, max_chars=256):
        try:
            s = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C)
            if s:
                try:
                    return s.decode('utf-8', errors='ignore')[:max_chars]
                except Exception:
                    return str(s)[:max_chars]
            s2 = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C_16)
            if s2:
                try:
                    return s2.decode('utf-16le', errors='ignore')[:max_chars]
                except Exception:
                    return str(s2)[:max_chars]
        except Exception:
            pass
        return ""

# ==================== LLM Interface ====================
class LLMInterface:
    """LLM interface for analysis and naming"""
    def __init__(self, base_url, api_key, model_name, logger=None, rate_limiter=None, max_retries=3, retry_backoff_base=0.5, use_async=False):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.model_name = model_name
        self.logger = logger or Logger(False)
        self.rate_limiter = rate_limiter or RateLimiter(60)
        self.max_retries = max_retries
        self.retry_backoff_base = retry_backoff_base
        self.use_async = use_async
    
    def analyze_function(self, func_info):
        """Analyze the function and produce a recommended name"""
        start_time = time.time()
        try:
            # Build prompt
            prompt = self._build_prompt(func_info)
            
            # Call API
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            data = {
                "model": self.model_name,
            "messages": [
                {"role": "system", "content": "You are a reverse engineering expert for compiled binaries."},
                {"role": "user", "content": prompt}
            ],
                "temperature": 0.3,
                "max_tokens": 500
            }
            
            # Rate limit + retries
            attempt = 0
            last_exc = None
            while attempt < self.max_retries:
                attempt += 1
                try:
                    self.rate_limiter.acquire()
                    response = requests.post(
                        f"{self.base_url}/chat/completions",
                        headers=headers,
                        json=data,
                        timeout=30
                    )
                    # Retry on 429/5xx
                    if response.status_code in (429, 500, 502, 503, 504):
                        raise requests.HTTPError(f"HTTP {response.status_code}: {response.text[:2000]}")
                    break
                except Exception as e:
                    last_exc = e
                    # Exponential backoff
                    backoff = self.retry_backoff_base * (2 ** (attempt - 1)) * (1.0 + random.random() * 0.2)
                    time.sleep(backoff)
                    response = None
            if response is None:
                raise last_exc if last_exc else RuntimeError("Unknown error")
            
            if response.status_code == 200:
                result = response.json()
                content = result['choices'][0]['message']['content']
                duration = time.time() - start_time
                # Detailed logging
                request_info = {
                    "endpoint": f"{self.base_url}/chat/completions",
                    "model": self.model_name,
                    "temperature": 0.3,
                    "max_tokens": 500,
                    "prompt_chars": len(prompt),
                    "prompt": prompt
                }
                response_info = {
                    "status_code": response.status_code,
                    "content": content,
                    "usage": result.get('usage', {})
                }
                if self.logger:
                    self.logger.log_llm_interaction(
                        func_info['ea'],
                        func_info['current_name'],
                        request_info,
                        response_info,
                        duration
                    )
                return self._parse_response(content)
            else:
                duration = time.time() - start_time
                request_info = {
                    "endpoint": f"{self.base_url}/chat/completions",
                    "model": self.model_name,
                    "temperature": 0.3,
                    "max_tokens": 500,
                    "prompt_chars": len(prompt)
                }
                response_info = {
                    "status_code": response.status_code,
                    "error": response.text[:2000]
                }
                if self.logger:
                    self.logger.log_llm_interaction(
                        func_info['ea'],
                        func_info['current_name'],
                        request_info,
                        response_info,
                        duration
                    )
                self.logger.log(f"API call failed: {response.status_code} - {response.text}", "ERROR")
                return None
                
        except Exception as e:
            duration = time.time() - start_time
            if self.logger:
                request_info = {
                    "endpoint": f"{self.base_url}/chat/completions",
                    "model": self.model_name
                }
                response_info = {
                    "exception": str(e)
                }
                self.logger.log_llm_interaction(
                    func_info.get('ea', 0),
                    func_info.get('current_name', ''),
                    request_info,
                    response_info,
                    duration
                )
            self.logger.log(f"LLM analysis failed: {e}", "ERROR")
            return None

    async def _analyze_batch_async(self, func_infos, max_workers=8, requests_per_min=60):
        rate = AsyncRateLimiter(requests_per_min)
        results = {}
        connector = aiohttp.TCPConnector(limit=max_workers)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self._analyze_single_async(fi, session, rate) for fi in func_infos]
            for coro in asyncio.as_completed(tasks):
                ea, res = await coro
                results[ea] = res
        return results

    def analyze_functions(self, func_infos, max_workers=8, requests_per_min=60):
        """Analyze a batch of functions concurrently. Uses async if enabled/available, else threads."""
        if not func_infos:
            return {}
        if self.use_async and HAS_AIOHTTP:
            # Only call asyncio.run when there's no running loop to avoid 'never awaited'
            has_running_loop = False
            try:
                asyncio.get_running_loop()
                has_running_loop = True
            except RuntimeError:
                has_running_loop = False
            if not has_running_loop:
                return asyncio.run(self._analyze_batch_async(func_infos, max_workers, requests_per_min))
        # Thread pool fallback
        results = {}
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ea = {executor.submit(self.analyze_function, fi): fi['ea'] for fi in func_infos}
            for future in as_completed(future_to_ea):
                ea = future_to_ea[future]
                try:
                    results[ea] = future.result()
                except Exception as e:
                    self.logger.log(f"Concurrent analysis error 0x{ea:X}: {e}", "ERROR")
                    results[ea] = None
        return results

    async def _analyze_single_async(self, func_info, session, rate: AsyncRateLimiter):
        start_time = time.time()
        prompt = self._build_prompt(func_info)
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": "You are a reverse engineering expert for compiled binaries."},
                {"role": "user", "content": prompt}
            ],
            "messages": [
                {"role": "system", "content": "You are a reverse engineering expert for compiled binaries."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,
            "max_tokens": 500
        }
        attempt = 0
        last_exc = None
        while attempt < self.max_retries:
            attempt += 1
            try:
                await rate.acquire()
                async with session.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=data,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    status = resp.status
                    text = await resp.text()
                    if status != 200:
                        raise aiohttp.ClientResponseError(
                            request_info=resp.request_info,
                            history=resp.history,
                            status=status,
                            message=text[:2000]
                        )
                    result = json.loads(text)
                content = result['choices'][0]['message']['content']
                duration = time.time() - start_time
                request_info = {
                    "endpoint": f"{self.base_url}/chat/completions",
                    "model": self.model_name,
                    "temperature": 0.3,
                    "max_tokens": 500,
                    "prompt_chars": len(prompt),
                    "prompt": prompt
                }
                response_info = {
                    "status_code": 200,
                    "content": content,
                    "usage": result.get('usage', {})
                }
                if self.logger:
                    self.logger.log_llm_interaction(
                        func_info['ea'], func_info['current_name'],
                        request_info, response_info, duration
                    )
                return func_info['ea'], self._parse_response(content)
            except Exception as e:
                last_exc = e
                await asyncio.sleep(self.retry_backoff_base * (2 ** (attempt - 1)))
        # Failure record
        duration = time.time() - start_time
        if self.logger:
            self.logger.log_llm_interaction(
                func_info['ea'], func_info['current_name'],
                {"endpoint": f"{self.base_url}/chat/completions", "model": self.model_name},
                {"exception": str(last_exc)},
                duration
            )
        self.logger.log(f"Async LLM analysis failed 0x{func_info['ea']:X}: {last_exc}", "ERROR")
        return func_info['ea'], None
    
    def _build_prompt(self, func_info):
        """Build the analysis prompt"""
        prompt = "Please analyze the following unnamed function in a compiled binary and infer its purpose and a suitable name.\n\n"
        
        # Current function info
        prompt += f"=== Function EA: 0x{func_info['ea']:X} ===\n"
        prompt += f"Current name: {func_info['current_name']}\n\n"
        
        # Assembly
        if func_info.get('assembly'):
            prompt += "=== Assembly ===\n"
            prompt += func_info['assembly'][:1000] + "\n\n"
        
        # Pseudocode
        if func_info.get('pseudocode'):
            prompt += "=== Pseudocode ===\n"
            prompt += func_info['pseudocode'][:1500] + "\n\n"
        
        # Callers
        if func_info.get('callers'):
            prompt += "=== Callers ===\n"
            for caller in func_info['callers'][:3]:
                prompt += f"- {caller['name']}:\n"
                if caller.get('pseudocode'):
                    prompt += caller['pseudocode'][:300] + "\n"
            prompt += "\n"
        
        # Callees
        if func_info.get('callees'):
            prompt += "=== Callees ===\n"
            for callee in func_info['callees'][:5]:
                prompt += f"- {callee['name']}\n"
            prompt += "\n"
        
        # Instructions
        prompt += """
Based on the above, infer the function's purpose and propose a suitable function name.

Requirements:
1. The name should reflect the primary behavior.
2. Follow common naming conventions (camelCase or snake_case).
3. Use prefixes when applicable (e.g., init_, handle_, process_).

Return strictly in this JSON format:
{
    "function_name": "proposed_name",
    "confidence": "high/medium/low",
    "reason": "brief rationale for the name",
    "function_type": "e.g., initialization/handler/utility/driver etc."
}
"""
        return prompt
    
    def _parse_response(self, content):
        """Parse LLM response"""
        try:
            # Try to extract JSON block(s)
            import re
            json_pattern = r'\{[^{}]*\}'
            matches = re.findall(json_pattern, content, re.DOTALL)
            
            if matches:
                # Try the last JSON block first
                for match in reversed(matches):
                    try:
                        result = json.loads(match)
                        if 'function_name' in result:
                            return result
                    except:
                        continue
            
            # Fallback: try to extract a line that looks like function_name
            lines = content.split('\n')
            for line in lines:
                if 'function_name' in line:
                    # Try to extract the name after colon
                    parts = line.split(':')
                    if len(parts) > 1:
                        name = parts[1].strip().strip('"').strip("'").strip()
                        if name and not name.startswith('sub_'):
                            return {
                                'function_name': name,
                                'confidence': 'low',
                                'reason': 'extracted from response text',
                                'function_type': 'unknown'
                            }
            
            return None
            
        except Exception as e:
            self.logger.log(f"Failed to parse LLM response: {e}", "ERROR")
            return None

    # ==================== Data-aware helpers moved here ====================
    def build_indirect_string_prompt(self, ctx):
        lines = []
        lines.append("You are analyzing a function to determine if it accesses a string indirectly via an array/table of strings.")
        lines.append(f"Function 0x{ctx['func_ea']:X} ({ctx['func_name']})")
        if ctx.get('assembly'):
            lines.append("=== Assembly ===")
            lines.append(ctx['assembly'][:1000])
        if ctx.get('pseudocode'):
            lines.append("=== Pseudocode ===")
            lines.append(ctx['pseudocode'][:1200])
        lines.append("=== String A (candidate, higher address, possibly unreferenced) ===")
        lines.append(f"EA: 0x{ctx['string_a_ea']:X}")
        lines.append(f"Preview: {ctx.get('string_a_preview', '')[:256]}")
        lines.append("=== Anchor String B (lower address, directly referenced) ===")
        lines.append(f"EA: 0x{ctx['string_b_ea']:X}")
        lines.append(f"Preview: {ctx.get('string_b_preview', '')[:256]}")
        lines.append("Question: Does the function likely access String A via an array/table that includes String B (e.g., by indexing into a contiguous array)?")
        lines.append("Return strictly JSON only, with: {\"is_array\": bool, \"confidence\": number, \"reason\": string}")
        return "\n".join(lines)

    def parse_indirect_string_response(self, content):
        try:
            import re
            json_pattern = r'\{[^{}]*\}'
            matches = re.findall(json_pattern, content, re.DOTALL)
            for match in reversed(matches):
                try:
                    obj = json.loads(match)
                    if isinstance(obj, dict) and 'is_array' in obj:
                        return obj
                except:
                    continue
        except Exception as e:
            self.logger.log(f"parse_indirect_string_response error: {e}", "ERROR")
        return None

    def check_indirect_string_array(self, ctx):
        start_time = time.time()
        try:
            prompt = self.build_indirect_string_prompt(ctx)
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            data = {
                "model": self.model_name,
                "messages": [
                    {"role": "system", "content": "You are a reverse engineering assistant for compiled binaries."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.2,
                "max_tokens": 200
            }
            attempt = 0
            last_exc = None
            while attempt < self.max_retries:
                attempt += 1
                try:
                    self.rate_limiter.acquire()
                    response = requests.post(
                        f"{self.base_url}/chat/completions",
                        headers=headers, json=data, timeout=30
                    )
                    if response.status_code in (429, 500, 502, 503, 504):
                        raise requests.HTTPError(f"HTTP {response.status_code}: {response.text[:2000]}")
                    break
                except Exception as e:
                    last_exc = e
                    time.sleep(self.retry_backoff_base * (2 ** (attempt - 1)))
                    response = None
            if response is None:
                raise last_exc if last_exc else RuntimeError("Unknown error")
            content = None
            if response.status_code == 200:
                result = response.json()
                content = result['choices'][0]['message']['content']
            else:
                self.logger.log(f"LLM indirect check failed: {response.status_code} {response.text[:500]}", "ERROR")
                return None
            duration = time.time() - start_time
            self.logger.log_llm_interaction(
                ctx.get('func_ea', 0), ctx.get('func_name', ''),
                {"endpoint": f"{self.base_url}/chat/completions", "prompt_chars": len(prompt)},
                {"status_code": 200, "content": content}, duration
            )
            return self.parse_indirect_string_response(content)
        except Exception as e:
            self.logger.log(f"check_indirect_string_array error: {e}", "ERROR")
            return None

    # ===== Batch indirect-string checks =====
    async def _check_indirect_single_async(self, ctx, session, rate: AsyncRateLimiter):
        start_time = time.time()
        prompt = self.build_indirect_string_prompt(ctx)
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": "You are a reverse engineering assistant for compiled binaries."},
                {"role": "user", "content": prompt}
            ],
            "messages": [
                {"role": "system", "content": "You are a reverse engineering assistant for compiled binaries."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2,
            "max_tokens": 200
        }
        attempt = 0
        last_exc = None
        while attempt < self.max_retries:
            attempt += 1
            try:
                await rate.acquire()
                async with session.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers, json=data,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    status = resp.status
                    text = await resp.text()
                    if status != 200:
                        raise aiohttp.ClientResponseError(
                            request_info=resp.request_info,
                            history=resp.history,
                            status=status,
                            message=text[:2000]
                        )
                    result = json.loads(text)
                    content = result['choices'][0]['message']['content']
                    parsed = self.parse_indirect_string_response(content)
                    return (ctx.get('func_ea'), ctx.get('string_a_ea'), ctx.get('string_b_ea')), parsed
            except Exception as e:
                last_exc = e
                await asyncio.sleep(self.retry_backoff_base * (2 ** (attempt - 1)))
        return (ctx.get('func_ea'), ctx.get('string_a_ea'), ctx.get('string_b_ea')), None

    def check_indirect_string_array_batch(self, contexts, max_workers=6, requests_per_min=60):
        if not contexts:
            return {}
        if self.use_async and HAS_AIOHTTP:
            async def runner(contexts):
                rate = AsyncRateLimiter(requests_per_min)
                connector = aiohttp.TCPConnector(limit=max_workers)
                results = {}
                async with aiohttp.ClientSession(connector=connector) as session:
                    tasks = [self._check_indirect_single_async(ctx, session, rate) for ctx in contexts]
                    for coro in asyncio.as_completed(tasks):
                        key, res = await coro
                        results[key] = res
                return results
            try:
                has_running_loop = False
                try:
                    asyncio.get_running_loop()
                    has_running_loop = True
                except RuntimeError:
                    has_running_loop = False
                if not has_running_loop:
                    return asyncio.run(runner(contexts))
            except Exception as e:
                self.logger.log(f"check_indirect_string_array_batch async failed: {e}", "ERROR")
        # Threaded fallback
        results = {}
        def worker(ctx):
            try:
                return (ctx.get('func_ea'), ctx.get('string_a_ea'), ctx.get('string_b_ea')), self.check_indirect_string_array(ctx)
            except Exception:
                return (ctx.get('func_ea'), ctx.get('string_a_ea'), ctx.get('string_b_ea')), None
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {ex.submit(worker, c): c for c in contexts}
            for fut in as_completed(futs):
                key, res = fut.result()
                results[key] = res
        return results

    def build_data_rename_prompt(self, payload):
        lines = []
        lines.append("You are an expert assisting in naming global/static data in a compiled binary.")
        lines.append(f"Function 0x{payload['func_ea']:X} ({payload['func_name']})")
        if payload.get('assembly'):
            lines.append("=== Assembly ===")
            lines.append(payload['assembly'][:1200])
        if payload.get('pseudocode'):
            lines.append("=== Pseudocode ===")
            lines.append(payload['pseudocode'][:1600])
        if payload.get('official_apis'):
            lines.append("=== Official APIs (known functions) ===")
            lines.append(", ".join(sorted(payload['official_apis'])[:50]))
        if payload.get('callers'):
            lines.append("=== 1-hop Callers (pseudocode snippets) ===")
            for c in payload['callers'][:3]:
                lines.append(f"- {c['name']}")
                if c.get('pseudocode'):
                    lines.append(c['pseudocode'][:300])
        if payload.get('callees'):
            lines.append("=== 1-hop Callees (pseudocode snippets) ===")
            for c in payload['callees'][:5]:
                lines.append(f"- {c['name']}")
                if c.get('pseudocode'):
                    lines.append(c['pseudocode'][:220])
        if payload.get('strings'):
            lines.append("=== Linked Strings ===")
            for s in payload['strings'][:50]:
                lines.append(f"- 0x{s['ea']:X}: {s.get('preview','')[:200]}")
        if payload.get('datas'):
            lines.append("=== Linked Unnamed Data ===")
            for d in payload['datas'][:50]:
                sz = d.get('size', 0)
                lines.append(f"- 0x{d['ea']:X} name={d.get('name','')} size={sz}")
                if d.get('bytes_preview'):
                    lines.append(d['bytes_preview'][:120])
        lines.append("Task: Propose meaningful names for the listed unnamed data (global/static/struct fields), reflecting their roles.")
        lines.append("IMPORTANT: Only propose renames for non-string global/static data (tables, buffers, structs, arrays). Do NOT propose renaming any direct strings; strings are context only.")
        lines.append("Return strictly JSON only:\n{\n  \"rename\": [\n    {\n      \"ea\": \"0x...\",\n      \"proposed_name\": \"string\",\n      \"kind\": \"global|data\",\n      \"confidence\": 0.0,\n      \"reason\": \"...\"\n    }\n  ]\n}")
        return "\n".join(lines)

    def parse_data_rename_response(self, content):
        """Robustly parse LLM data-rename JSON (handles ```json fences and nested braces)."""
        try:
            text = (content or '').strip()
            # Step 1: Extract fenced code block if present
            fenced = re.findall(r"```(?:json)?\s*([\s\S]*?)```", text, re.IGNORECASE)
            candidate = fenced[-1].strip() if fenced else text
            # Step 2: Try direct JSON parse
            try:
                obj = json.loads(candidate)
                if isinstance(obj, dict) and isinstance(obj.get('rename'), list):
                    try:
                        self.logger.log(f"[DataAware] Parse direct JSON ok: items={len(obj.get('rename', []))}")
                    except Exception:
                        pass
                    return obj
            except Exception:
                pass
            # Step 3: Extract rename array and wrap
            m = re.search(r'"rename"\s*:\s*\[(.*?)\]', candidate, re.DOTALL)
            if m:
                arr_str = m.group(1)
                wrapped = '{"rename":[' + arr_str + ']}'
                try:
                    obj = json.loads(wrapped)
                    if isinstance(obj, dict) and isinstance(obj.get('rename'), list):
                        try:
                            self.logger.log(f"[DataAware] Parse wrapped rename-array ok: items={len(obj.get('rename', []))}")
                        except Exception:
                            pass
                        return obj
                except Exception:
                    pass
            # Step 4: Fallback - regex extract minimal items to salvage
            items = []
            for m in re.finditer(r'\{[\s\S]*?\"ea\"\s*:\s*(\"0x[0-9A-Fa-f]+\"|\d+)[\s\S]*?\"proposed_name\"\s*:\s*\"([^\"]+)\"([\s\S]*?)\}', candidate):
                try:
                    ea_raw = m.group(1)
                    name = m.group(2)
                    tail = m.group(3)
                    conf_m = re.search(r'\"confidence\"\s*:\s*([0-9]+(?:\.[0-9]+)?)', tail)
                    rsn_m = re.search(r'\"reason\"\s*:\s*\"([^\"]*)\"', tail)
                    conf = float(conf_m.group(1)) if conf_m else 0.0
                    reason = rsn_m.group(1) if rsn_m else ''
                    if isinstance(ea_raw, str) and ea_raw.startswith('"'):
                        ea_raw = ea_raw.strip('"')
                    items.append({
                        'ea': ea_raw,
                        'proposed_name': name,
                        'kind': 'data',
                        'confidence': conf,
                        'reason': reason
                    })
                except Exception:
                    continue
            if items:
                try:
                    self.logger.log(f"[DataAware] Parse fallback extracted items={len(items)}")
                except Exception:
                    pass
                return {'rename': items}
        except Exception as e:
            self.logger.log(f"parse_data_rename_response error: {e}", "ERROR")
        return None

    def parse_data_renames_safe(self, content):
        obj = self.parse_data_rename_response(content)
        if not obj:
            try:
                self.logger.log("[DataAware] Parse result: None (no valid JSON with 'rename')")
            except Exception:
                pass
            return None
        out = []
        for item in obj.get('rename', []):
            try:
                ea_str = item.get('ea') or item.get('addr') or item.get('address')
                if isinstance(ea_str, int):
                    ea_val = ea_str
                else:
                    # Accept hex string like 0x.... or decimal string
                    s = str(ea_str).strip()
                    ea_val = int(s, 16) if s.lower().startswith('0x') else int(s)
                name = item.get('proposed_name') or item.get('name')
                if not name:
                    continue
                kind = item.get('kind', 'data')
                conf = float(item.get('confidence', 0.0))
                reason = item.get('reason', '')
                out.append({'ea': ea_val, 'proposed_name': name, 'kind': kind, 'confidence': conf, 'reason': reason})
            except Exception as e:
                try:
                    self.logger.log(f"[DataAware] Parse item skipped due to error: {e}")
                except Exception:
                    pass
                continue
        try:
            self.logger.log(f"[DataAware] Parse normalized: items={len(out)}")
        except Exception:
            pass
        return {'rename': out}

    def propose_data_renames(self, payload):
        start_time = time.time()
        try:
            prompt = self.build_data_rename_prompt(payload)
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            data = {
                "model": self.model_name,
                "messages": [
                    {"role": "system", "content": "You precisely return JSON only."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.3,
                "max_tokens": 700
            }
            attempt = 0
            last_exc = None
            while attempt < self.max_retries:
                attempt += 1
                try:
                    self.rate_limiter.acquire()
                    response = requests.post(
                        f"{self.base_url}/chat/completions",
                        headers=headers, json=data, timeout=45
                    )
                    if response.status_code in (429, 500, 502, 503, 504):
                        raise requests.HTTPError(f"HTTP {response.status_code}: {response.text[:2000]}")
                    break
                except Exception as e:
                    last_exc = e
                    time.sleep(self.retry_backoff_base * (2 ** (attempt - 1)))
                    response = None
            if response is None:
                raise last_exc if last_exc else RuntimeError("Unknown error")
            if response.status_code != 200:
                self.logger.log(f"propose_data_renames failed: {response.status_code} {response.text[:500]}", "ERROR")
                return None
            result = response.json()
            content = result['choices'][0]['message']['content']
            duration = time.time() - start_time
            self.logger.log_llm_interaction(
                payload['func_ea'], payload['func_name'],
                {"endpoint": f"{self.base_url}/chat/completions", "prompt_chars": len(prompt)},
                {"status_code": 200, "content": content}, duration
            )
            return self.parse_data_renames_safe(content)
        except Exception as e:
            self.logger.log(f"propose_data_renames error: {e}", "ERROR")
            return None

    async def _propose_single_data_async(self, payload, session, rate: AsyncRateLimiter):
        prompt = self.build_data_rename_prompt(payload)
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": "You precisely return JSON only."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,
            "max_tokens": 700
        }
        attempt = 0
        last_exc = None
        while attempt < self.max_retries:
            attempt += 1
            try:
                await rate.acquire()
                async with session.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers, json=data,
                    timeout=aiohttp.ClientTimeout(total=45)
                ) as resp:
                    status = resp.status
                    text = await resp.text()
                    if status != 200:
                        raise aiohttp.ClientResponseError(
                            request_info=resp.request_info,
                            history=resp.history,
                            status=status,
                            message=text[:2000]
                        )
                    result = json.loads(text)
                    content = result['choices'][0]['message']['content']
                    parsed = self.parse_data_renames_safe(content)
                    return payload['func_ea'], parsed
            except Exception as e:
                last_exc = e
                await asyncio.sleep(self.retry_backoff_base * (2 ** (attempt - 1)))
        return payload['func_ea'], None

    def propose_data_renames_batch(self, payloads, max_workers=6, requests_per_min=60):
        if not payloads:
            return {}
        if self.use_async and HAS_AIOHTTP:
            async def runner(payloads):
                rate = AsyncRateLimiter(requests_per_min)
                connector = aiohttp.TCPConnector(limit=max_workers)
                results = {}
                async with aiohttp.ClientSession(connector=connector) as session:
                    tasks = [self._propose_single_data_async(p, session, rate) for p in payloads]
                    for coro in asyncio.as_completed(tasks):
                        fea, res = await coro
                        results[fea] = res
                return results
            try:
                has_running_loop = False
                try:
                    asyncio.get_running_loop()
                    has_running_loop = True
                except RuntimeError:
                    has_running_loop = False
                if not has_running_loop:
                    return asyncio.run(runner(payloads))
            except Exception as e:
                self.logger.log(f"propose_data_renames_batch async failed: {e}", "ERROR")
        # Fallback threads
        results = {}
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futs = {executor.submit(self.propose_data_renames, p): p['func_ea'] for p in payloads}
            for fut in as_completed(futs):
                fea = futs[fut]
                try:
                    results[fea] = fut.result()
                except Exception as e:
                    self.logger.log(f"propose_data_renames_batch error fea=0x{fea:X}: {e}", "ERROR")
                    results[fea] = None
        return results

# ==================== Data-aware Graph ====================
class DataAwareGraph:
    """Collect function->string/data links and compute metrics for data-aware ranking."""
    def __init__(self, func_graph: FunctionCallGraph, logger=None, analyzer: CodeAnalyzer=None, config: Config=None):
        self.graph = func_graph
        self.logger = logger or Logger(False)
        self.analyzer = analyzer or CodeAnalyzer(self.logger)
        self.config = config or Config()
        self.func_to_strings = defaultdict(set)
        self.func_to_data = defaultdict(set)
        self.string_nodes = {}  # ea -> {text, type, has_direct_xref}
        self.data_nodes = {}    # ea -> {name, size}
        self.string_to_funcs = defaultdict(set)
        self.renamed_data = set()
        self.metrics = {}

    def _is_code_ea(self, ea):
        try:
            return is_code(get_full_flags(ea))
        except Exception:
            return False

    def _is_string_at(self, ea):
        try:
            s = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C)
            if s and len(s) >= self.config.MIN_STRING_LEN:
                return 'utf8'
            s2 = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C_16)
            if s2 and len(s2) >= self.config.MIN_STRING_LEN * 2:
                return 'utf16'
        except Exception:
            pass
        return None

    def _get_item_size(self, ea):
        try:
            sz = ida_bytes.get_item_size(ea)
            if not sz or sz <= 0:
                return 1
            return sz
        except Exception:
            return 1

    def _is_generic_data_name(self, name):
        if not name:
            return True
        name = name.lower()
        return any(name.startswith(p) for p in [
            'off_', 'unk_', 'byte_', 'word_', 'dword_', 'qword_',
            'asc_', 'wstr_', 'dbl_', 'flt_', 'stru_', 'tbl_',
            'dat_', 'data_'
        ])

    def enumerate_strings(self):
        try:
            strings = list(Strings())
        except Exception:
            strings = []
        for s in strings:
            try:
                ea = int(s.ea)
                txt = str(s)
                if txt and len(txt) >= self.config.MIN_STRING_LEN:
                    self.string_nodes[ea] = {
                        'text': txt,
                        'type': 'utf8' if getattr(s, 'type', 0) == 0 else 'utf16',
                        'has_direct_xref': False
                    }
            except Exception:
                continue

    def build_edges(self):
        self.logger.log("Building data-aware edges (strings & data)...")
        try:
            ida_auto.auto_wait()
        except Exception:
            pass
        self.enumerate_strings()
        for func_ea in self.graph.nodes.keys():
            func = get_func(func_ea)
            if not func:
                continue
            for head in Heads(func.start_ea, func.end_ea):
                try:
                    for dref in DataRefsFrom(head):
                        if self._is_code_ea(dref):
                            continue
                        stype = self._is_string_at(dref)
                        if stype:
                            self.func_to_strings[func_ea].add(dref)
                            self.string_to_funcs[dref].add(func_ea)
                            if dref not in self.string_nodes:
                                self.string_nodes[dref] = {
                                    'text': self.analyzer.get_string_preview(dref, 256),
                                    'type': stype,
                                    'has_direct_xref': True
                                }
                            else:
                                self.string_nodes[dref]['has_direct_xref'] = True
                        else:
                            self.func_to_data[func_ea].add(dref)
                            if dref not in self.data_nodes:
                                nm = get_name(dref) or ''
                                self.data_nodes[dref] = {'name': nm, 'size': self._get_item_size(dref)}
                except Exception:
                    continue
        self.logger.log(f"Data-aware edges built: strings={len(self.string_nodes)}, data={len(self.data_nodes)}")

    def _count_zero_gap(self, start_ea, end_ea):
        try:
            size = max(0, end_ea - start_ea)
            if size <= 0 or size > 0x10000:
                return 0xFFFFFFFF
            data = ida_bytes.get_bytes(start_ea, size) or b''
            max_run = 0
            cur = 0
            for b in data:
                if b == 0:
                    cur += 1
                    max_run = max(max_run, cur)
                else:
                    cur = 0
            return max_run
        except Exception:
            return 0xFFFFFFFF

    def _find_prev_string_with_xref(self, ea):
        cand = None
        best_delta = None
        for se in sorted(self.string_nodes.keys()):
            if se >= ea:
                break
            if ea - se > self.config.INDIRECT_STRING_SCAN_WINDOW:
                continue
            sn = self.string_nodes[se]
            if sn.get('has_direct_xref'):
                gap = self._count_zero_gap(se + max(1, len(sn.get('text',''))), ea)
                if gap <= self.config.ZERO_GAP_MAX:
                    delta = ea - se
                    if best_delta is None or delta < best_delta:
                        cand = se
                        best_delta = delta
        return cand

    def link_indirect_strings_via_llm(self, max_checks=None):
        if max_checks is None:
            max_checks = self.config.MAX_INDIRECT_CHECKS_PER_RUN
        # Collect candidate (Z, A, B) contexts and process concurrently in batches
        contexts = []
        seen_a = set()
        for a_ea, ainfo in self.string_nodes.items():
            if ainfo.get('has_direct_xref'):
                continue
            if a_ea in seen_a:
                continue
            b_ea = self._find_prev_string_with_xref(a_ea)
            if not b_ea:
                continue
            for z_ea in list(self.string_to_funcs.get(b_ea, [])):
                ctx = {
                    'func_ea': z_ea,
                    'func_name': get_func_name(z_ea) or f"sub_{z_ea:X}",
                    'assembly': self.analyzer.get_assembly_code(z_ea, 400),
                    'pseudocode': self.analyzer.get_pseudocode(z_ea, 200),
                    'string_a_ea': a_ea,
                    'string_a_preview': (ainfo.get('text') or self.analyzer.get_string_preview(a_ea, 128)) or '',
                    'string_b_ea': b_ea,
                    'string_b_preview': self.string_nodes[b_ea].get('text','')[:128]
                }
                contexts.append(ctx)
                seen_a.add(a_ea)
                if len(contexts) >= max_checks:
                    break
            if len(contexts) >= max_checks:
                break
        # Send in batches
        if not contexts:
            try:
                self.logger.log("[DataAware] Indirect linking: no contexts collected; skip this phase")
            except Exception:
                pass
            return
        batch_size = max(1, int(getattr(self.config, 'INDIRECT_BATCH_SIZE', 10)))
        max_workers = int(getattr(self.config, 'INDIRECT_MAX_WORKERS', 6))
        idx = 0
        while idx < len(contexts):
            batch = contexts[idx: idx + batch_size]
            idx += batch_size
            try:
                self.logger.log(f"[DataAware] Indirect linking: processing batch size={len(batch)} (batch_size={batch_size}, max_workers={max_workers})")
            except Exception:
                pass
            results = {}
            try:
                results = renamer_llm.check_indirect_string_array_batch(
                    batch,
                    max_workers=max_workers,
                    requests_per_min=self.config.REQUESTS_PER_MIN
                ) or {}
            except Exception as e:
                self.logger.log(f"batch indirect check failed: {e}", "ERROR")
                # Fallback to per-item requests
                results = {}
                for ctx in batch:
                    key = (ctx.get('func_ea'), ctx.get('string_a_ea'), ctx.get('string_b_ea'))
                    try:
                        results[key] = renamer_llm.check_indirect_string_array(ctx)
                    except Exception:
                        results[key] = None
            # Apply results
            for key, res in results.items():
                z_ea, a_ea, b_ea = key
                if res and res.get('is_array'):
                    self.func_to_strings[z_ea].add(a_ea)
                    self.string_to_funcs[a_ea].add(z_ea)
                    self.logger.log(f"Indirect string linked: Z=0x{z_ea:X} A=0x{a_ea:X} via B=0x{b_ea:X}")

    def compute_metrics(self):
        self.metrics = {}
        for fea in self.graph.nodes.keys():
            X = len(self.func_to_data.get(fea, set()))
            Y = len(self.func_to_strings.get(fea, set()))
            callers = self.graph.reverse_edges.get(fea, set())
            callees = self.graph.edges.get(fea, set())
            deg_total = len(callers) + len(callees)
            renamed_neighbors = 0
            for n in callers:
                if self.graph.nodes.get(n, {}).get('renamed'):
                    renamed_neighbors += 1
            for n in callees:
                if self.graph.nodes.get(n, {}).get('renamed'):
                    renamed_neighbors += 1
            Z = (renamed_neighbors / deg_total) if deg_total > 0 else 0.0
            denom = X + Y
            R = (Z * (X / denom)) if denom > 0 else 1.0
            YZ = Y + Z
            self.metrics[fea] = {'X': X, 'Y': Y, 'Z': Z, 'R': R, 'YZ': YZ}
        return self.metrics

    def export_data_graph(self, output_dir_root):
        if not self.config.EXPORT_DATA_GRAPH:
            return
        try:
            ts = time.strftime('%Y%m%d_%H%M%S')
            root = os.path.join(output_dir_root or 'fcg_output', ts)
            os.makedirs(root, exist_ok=True)
            data = {
                'strings': [
                    {'ea': ea, 'ea_hex': f"0x{ea:X}", 'has_direct_xref': info.get('has_direct_xref', False), 'text': (info.get('text','')[:120])}
                    for ea, info in self.string_nodes.items()
                ],
                'data_nodes': [
                    {'ea': ea, 'ea_hex': f"0x{ea:X}", 'name': info.get('name',''), 'size': info.get('size',0)}
                    for ea, info in self.data_nodes.items()
                ],
                'func_to_strings': [
                    {'func_ea': fea, 'func_ea_hex': f"0x{fea:X}", 'strings': sorted([f"0x{x:X}" for x in lst])}
                    for fea, lst in self.func_to_strings.items()
                ],
                'func_to_data': [
                    {'func_ea': fea, 'func_ea_hex': f"0x{fea:X}", 'data': sorted([f"0x{x:X}" for x in lst])}
                    for fea, lst in self.func_to_data.items()
                ]
            }
            with open(os.path.join(root, 'data_aware_graph.json'), 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            self.logger.log(f"Data-aware graph exported to: {os.path.abspath(root)}")
        except Exception as e:
            self.logger.log(f"Export data graph failed: {e}", "ERROR")
    # ==================== Data-aware prompts & parsers ====================
    def build_indirect_string_prompt(self, ctx):
        return renamer_llm.build_indirect_string_prompt(ctx)

    def parse_indirect_string_response(self, content):
        return renamer_llm.parse_indirect_string_response(content)

    def check_indirect_string_array(self, ctx):
        return renamer_llm.check_indirect_string_array(ctx)

    def build_data_rename_prompt(self, payload):
        return renamer_llm.build_data_rename_prompt(payload)

    def parse_data_rename_response(self, content):
        return renamer_llm.parse_data_rename_response(content)

    def parse_data_renames_safe(self, content):
        return renamer_llm.parse_data_renames_safe(content)

    def propose_data_renames(self, payload):
        return renamer_llm.propose_data_renames(payload)

    async def _propose_single_data_async(self, payload, session, rate: AsyncRateLimiter):
        prompt = self.build_data_rename_prompt(payload)
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": "You precisely return JSON only."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,
            "max_tokens": 700
        }
        attempt = 0
        last_exc = None
        while attempt < self.max_retries:
            attempt += 1
            try:
                await rate.acquire()
                async with session.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers, json=data,
                    timeout=aiohttp.ClientTimeout(total=45)
                ) as resp:
                    status = resp.status
                    text = await resp.text()
                    if status != 200:
                        raise aiohttp.ClientResponseError(
                            request_info=resp.request_info,
                            history=resp.history,
                            status=status,
                            message=text[:2000]
                        )
                    result = json.loads(text)
                    content = result['choices'][0]['message']['content']
                    parsed = self.parse_data_renames_safe(content)
                    return payload['func_ea'], parsed
            except Exception as e:
                last_exc = e
                await asyncio.sleep(self.retry_backoff_base * (2 ** (attempt - 1)))
        return payload['func_ea'], None

    def propose_data_renames_batch(self, payloads, max_workers=6, requests_per_min=60):
        return renamer_llm.propose_data_renames_batch(payloads, max_workers=max_workers, requests_per_min=requests_per_min)

# ==================== Renaming engine ====================
class PrivateFunctionRenamer:
    """Private function renaming engine"""
    def __init__(self, config=None):
        self.config = config or Config()
        self.logger = Logger(
            self.config.LOG_ENABLED,
            self.config.LOG_FILE,
            self.config.DETAILED_LOG_FILE,
            console_quiet=self.config.CONSOLE_QUIET
        )
        self.graph = FunctionCallGraph(self.logger)
        self.analyzer = CodeAnalyzer(self.logger)
        self.llm = LLMInterface(
            self.config.API_BASE_URL,
            self.config.API_KEY,
            self.config.MODEL_NAME,
            self.logger,
            rate_limiter=RateLimiter(self.config.REQUESTS_PER_MIN),
            max_retries=self.config.MAX_RETRIES,
            retry_backoff_base=self.config.RETRY_BACKOFF_BASE,
            use_async=self.config.USE_ASYNC
        )
        self.renamed_count = 0
        self.failed_count = 0
    
    def run(self):
        """Run the renaming workflow"""
        self.logger.log("=" * 60)
        self.logger.log("Private function renamer (FCG export) started")
        self.logger.log("=" * 60)
        
        try:
            # 1) Build call graph
            self.graph.build_graph()
            # Log in-degree sum and current renamed count for tracking
            self.logger.log(f"In-degree sum: {self.graph.in_degree_sum}")
            self.logger.log(f"Current renamed functions: {self.renamed_count}")

            # 1.5) Export call graph for tracking
            if self.config.FCG_EXPORT_ENABLED:
                out_dir = self.config.FCG_OUTPUT_DIR or "fcg_output"
                self.graph.export_call_graph(out_dir, self.config.FCG_EXPORT_FORMATS, self.config.FCG_SUMMARY_TOPN)
            
            # 2) Compute density
            self.graph.calculate_density()
            
            # 3) Batch iterations
            iteration = 0
            while self.graph.density:
                iteration += 1
                self.logger.log(f"\n--- Iteration {iteration} (batch) ---")
                # Selection strategy: sort by known neighbors (non-private callers+callees) desc; tie-break by density asc
                if not self.graph.density:
                    break
                scored = []  # (ea, density, known_neighbors_count)
                for ea, dens in self.graph.density.items():
                    neighbors = set()
                    neighbors.update(self.graph.edges.get(ea, set()))
                    neighbors.update(self.graph.reverse_edges.get(ea, set()))
                    known_cnt = sum(1 for n in neighbors if n in self.graph.nodes and not self.graph.nodes[n]['is_private'])
                    scored.append((ea, dens, known_cnt))
                # Sorting: prioritize more known neighbors; if equal, smaller density first
                scored.sort(key=lambda t: (-t[2], t[1], t[0]))
                batch = scored[:min(self.config.BATCH_SIZE, len(scored))]
                if not batch:
                    break
                # Prepare function info on main thread (IDA APIs)
                func_infos = []
                for func_ea, density, known_cnt in batch:
                    current_node = self.graph.nodes.get(func_ea, {})
                    current_name = current_node.get('name', f'sub_{func_ea:X}')
                    # Per-node degrees, renamed neighbors, known neighbors
                    callees = self.graph.edges.get(func_ea, set())
                    callers = self.graph.reverse_edges.get(func_ea, set())
                    deg_out = len(callees)
                    deg_in = len(callers)
                    renamed_callers = sum(1 for x in callers if self.graph.nodes.get(x, {}).get('renamed'))
                    renamed_callees = sum(1 for x in callees if self.graph.nodes.get(x, {}).get('renamed'))
                    renamed_total = renamed_callers + renamed_callees
                    self.logger.log(
                        f"Prepare: {current_name} (0x{func_ea:X}), density: {density:.3f}, "
                        f"deg_out: {deg_out}, deg_in: {deg_in}, known_neighbors: {known_cnt}, "
                        f"renamed_neighbors: {renamed_total} (callers: {renamed_callers}, callees: {renamed_callees})"
                    )
                    func_info = self.prepare_function_info(func_ea)
                    if func_info:
                        func_infos.append(func_info)
                    else:
                        # Preparation failed; drop it to avoid stalling
                        self.failed_count += 1
                        if func_ea in self.graph.density:
                            del self.graph.density[func_ea]
                
                # Concurrent LLM analysis (async optional)
                results_map = self.llm.analyze_functions(
                    func_infos,
                    max_workers=self.config.MAX_WORKERS,
                    requests_per_min=self.config.REQUESTS_PER_MIN
                )
                
                # Apply renames (main thread)
                for fi in func_infos:
                    ea = fi['ea']
                    result = results_map.get(ea)
                    if result and result.get('function_name'):
                        new_name = result['function_name']
                        confidence = result.get('confidence', 'unknown')
                        reason = result.get('reason', '')
                        if self.apply_rename(ea, fi['current_name'], new_name, reason, confidence, result.get('function_type', 'unknown')):
                            self.renamed_count += 1
                            self.graph.mark_function_renamed(ea)
                        else:
                            self.failed_count += 1
                            if ea in self.graph.density:
                                del self.graph.density[ea]
                    else:
                        self.failed_count += 1
                        if ea in self.graph.density:
                            del self.graph.density[ea]
                
                total_processed = self.renamed_count + self.failed_count
                if total_processed % 5 == 0:
                    self.logger.log(
                        f"Progress: processed {total_processed}, success {self.renamed_count}, failed {self.failed_count}"
                    )
            
            # Final stats
            self.logger.log("\n" + "=" * 60)
            self.logger.log("Completed!")
            self.logger.log(f"Total processed: {self.renamed_count + self.failed_count}")
            self.logger.log(f"Renamed: {self.renamed_count}")
            self.logger.log(f"Failed: {self.failed_count}")
            self.logger.log("=" * 60)
            
            # Info message
            ida_kernwin.info(f"Private function renaming finished!\n"
                            f"Success: {self.renamed_count}\n"
                            f"Failed: {self.failed_count}\n"
                            f"Log: {os.path.abspath(self.config.LOG_FILE)}")
            
        except Exception as e:
            self.logger.log(f"Runtime error: {e}", "ERROR")
            ida_kernwin.warning(f"Processing failed: {str(e)}")
        
        finally:
            self.logger.close()
    
    # Removed: analyze_and_rename_function (redundant to batch flow)

    def prepare_function_info(self, func_ea):
        """Prepare function info (must be called on main thread for IDA APIs)"""
        try:
            current_name = get_func_name(func_ea)
            # Inline per-node metrics for downstream prompt/debug (optional)
            callees = self.graph.edges.get(func_ea, set())
            callers = self.graph.reverse_edges.get(func_ea, set())
            deg_out = len(callees)
            deg_in = len(callers)
            renamed_callers = sum(1 for ea in callers if self.graph.nodes.get(ea, {}).get('renamed'))
            renamed_callees = sum(1 for ea in callees if self.graph.nodes.get(ea, {}).get('renamed'))
            renamed_total = renamed_callers + renamed_callees
            # 1) Assembly
            asm_code = self.analyzer.get_assembly_code(func_ea, self.config.MAX_ASM_LINES)
            # 2) Pseudocode
            pseudocode = self.analyzer.get_pseudocode(func_ea, self.config.MAX_PSEUDOCODE_LINES)
            # 3) Consistency check (inline)
            consistency_warning = None
            if not asm_code and not pseudocode:
                consistency_warning = "Both assembly and pseudocode are empty"
            elif not asm_code:
                consistency_warning = "Assembly is empty"
            elif not pseudocode:
                consistency_warning = "Pseudocode is empty"
            else:
                asm_lines = len(asm_code.split('\n'))
                pseudo_lines = len(pseudocode.split('\n'))
                if asm_lines > 20 and pseudo_lines < 5:
                    consistency_warning = "Assembly is complex but pseudocode is too short"
            if consistency_warning:
                self.logger.log(f"Inconsistency: {consistency_warning}", "WARNING")
                try:
                    ida_funcs.reanalyze_function(get_func(func_ea))
                    pseudocode = self.analyzer.get_pseudocode(func_ea, self.config.MAX_PSEUDOCODE_LINES)
                except:
                    pass
            # 4) Context (inline 1-hop)
            context = {'callers': [], 'callees': []}
            if func_ea in self.graph.reverse_edges:
                for caller_ea in self.graph.reverse_edges[func_ea]:
                    if caller_ea in self.graph.nodes:
                        context['callers'].append({
                            'ea': caller_ea,
                            'name': self.graph.nodes[caller_ea]['name'],
                            'pseudocode': self.analyzer.get_pseudocode(caller_ea, max_lines=50)
                        })
            if func_ea in self.graph.edges:
                for callee_ea in self.graph.edges[func_ea]:
                    if callee_ea in self.graph.nodes:
                        context['callees'].append({
                            'ea': callee_ea,
                            'name': self.graph.nodes[callee_ea]['name'],
                            'pseudocode': self.analyzer.get_pseudocode(callee_ea, max_lines=50)
                        })
            # 5) Assemble payload
            func_info = {
                'ea': func_ea,
                'current_name': current_name,
                'assembly': asm_code,
                'pseudocode': pseudocode,
                'deg_out': deg_out,
                'deg_in': deg_in,
                'renamed_neighbors_total': renamed_total,
                'renamed_callers': renamed_callers,
                'renamed_callees': renamed_callees,
                'callers': context['callers'],
                'callees': context['callees']
            }
            return func_info
        except Exception as e:
            self.logger.log(f"Failed to prepare function info 0x{func_ea:X}: {e}", "ERROR")
            return None
    
    def apply_rename(self, func_ea, old_name, new_name, reason, confidence, function_type):
        """Apply rename and write function comment.
        Conflict fallback: if the proposed name fails, fallback to f"{new_name}_{func_ea:X}".
        """
        try:
            # Inline validation (keep consistent with original checks)
            if (not new_name or new_name.startswith("sub_") or
                not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', new_name) or
                len(new_name) > 255):
                self.logger.log(f"Rename rejected due to invalid name: {new_name}", "WARNING")
                return False

            # Try proposed name first
            applied = set_name(func_ea, new_name, SN_CHECK | SN_NOWARN)
            new_applied_name = new_name if applied else None

            # If failed then fallback to {new_name}_{EA}
            if not applied:
                suffix = f"_{func_ea:X}"
                base = new_name
                max_len = 255 - len(suffix)
                if len(base) > max_len:
                    base = base[:max_len]
                fallback = f"{base}{suffix}"
                if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', fallback):
                    # If truncated leading char is not letter/underscore, add a prefix
                    fallback = f"f_{fallback}"
                applied = set_name(func_ea, fallback, SN_CHECK | SN_NOWARN)
                new_applied_name = fallback if applied else None

            if not applied or not new_applied_name:
                self.logger.log(f"Rename failed (both primary and fallback): {new_name}", "ERROR")
                return False

            self.logger.log(f"Renamed: {old_name} -> {new_applied_name}")
            # Update graph name
            if func_ea in self.graph.nodes:
                self.graph.nodes[func_ea]['name'] = new_applied_name
            # Add function comment
            comment_lines = [
                "[Auto-renamed by LLM]",
                f"Old name: {old_name}",
                f"New name: {new_applied_name}",
                f"Type: {function_type}",
                f"Confidence: {confidence}",
                f"Reason: {reason}",
                f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}"
            ]
            set_func_cmt(func_ea, "\n".join(comment_lines), 0)
            return True
        except Exception as e:
            self.logger.log(f"Error applying rename 0x{func_ea:X}: {e}", "ERROR")
            return False

# ==================== Data-aware Renamer ====================
class DataAwareRenamer:
    def __init__(self, config=None):
        self.config = config or Config()
        self.logger = Logger(
            self.config.LOG_ENABLED,
            self.config.LOG_FILE,
            self.config.DETAILED_LOG_FILE,
            console_quiet=self.config.CONSOLE_QUIET
        )
        self.graph = FunctionCallGraph(self.logger)
        self.analyzer = CodeAnalyzer(self.logger)
        self.llm = LLMInterface(
            self.config.API_BASE_URL,
            self.config.API_KEY,
            self.config.MODEL_NAME,
            self.logger,
            rate_limiter=RateLimiter(self.config.REQUESTS_PER_MIN),
            max_retries=self.config.MAX_RETRIES,
            retry_backoff_base=self.config.RETRY_BACKOFF_BASE,
            use_async=self.config.USE_ASYNC
        )
        global renamer_llm
        renamer_llm = self.llm
        self.data_graph = DataAwareGraph(self.graph, self.logger, self.analyzer, self.config)
        self.success_count = 0
        self.fail_count = 0

    def _is_default_data_name(self, name):
        return self.data_graph._is_generic_data_name(name)

    def _collect_official_apis(self, func_ea):
        apis = []
        for callee in self.graph.edges.get(func_ea, set()):
            if callee in self.graph.nodes and not self.graph.nodes[callee]['is_private']:
                apis.append(self.graph.nodes[callee]['name'])
        return sorted(set(apis))

    def _prepare_payload_for_function(self, func_ea):
        name = get_func_name(func_ea) or f"sub_{func_ea:X}"
        asm = self.analyzer.get_assembly_code(func_ea, self.config.MAX_ASM_LINES)
        pseudo = self.analyzer.get_pseudocode(func_ea, self.config.MAX_DATA_PSEUDOCODE_LINES)
        callers = []
        for ce in self.graph.reverse_edges.get(func_ea, set()):
            callers.append({'ea': ce, 'name': self.graph.nodes.get(ce, {}).get('name', f"sub_{ce:X}"), 'pseudocode': self.analyzer.get_pseudocode(ce, 80)})
        callees = []
        for ce in self.graph.edges.get(func_ea, set()):
            callees.append({'ea': ce, 'name': self.graph.nodes.get(ce, {}).get('name', f"sub_{ce:X}"), 'pseudocode': self.analyzer.get_pseudocode(ce, 80)})
        strings = []
        for se in sorted(self.data_graph.func_to_strings.get(func_ea, set())):
            strings.append({'ea': se, 'preview': self.analyzer.get_string_preview(se, 200) or self.data_graph.string_nodes.get(se, {}).get('text','')[:200]})
        datas = []
        for de in sorted(self.data_graph.func_to_data.get(func_ea, set())):
            nm = get_name(de) or ''
            if not self._is_default_data_name(nm):
                continue
            datas.append({'ea': de, 'name': nm, 'size': self.data_graph._get_item_size(de), 'bytes_preview': self.analyzer.get_bytes_preview(de, 32)})
        if not datas:
            return None
        payload = {
            'func_ea': func_ea,
            'func_name': name,
            'assembly': asm,
            'pseudocode': pseudo,
            'callers': callers,
            'callees': callees,
            'strings': strings,
            'datas': datas,
            'official_apis': self._collect_official_apis(func_ea),
            'platform': 'generic'
        }
        return payload

    def _apply_data_rename(self, ea, new_name, reason, confidence):
        try:
            # Detailed record before applying rename (log-file only)
            try:
                old_name_snapshot = get_name(ea) or ''
                self.logger.log(
                    f"[DataAware] Applying rename for data EA=0x{ea:X} old='{old_name_snapshot}' proposed='{new_name}' conf={confidence} reason='{reason}'"
                )
            except Exception:
                pass
            # Adjust EA to item head to avoid renaming a non-head address
            try:
                head = ida_bytes.get_item_head(ea)
                if isinstance(head, int) and head != ea:
                    try:
                        self.logger.log(f"[DataAware] Adjust EA to item head: 0x{ea:X} -> 0x{head:X}")
                    except Exception:
                        pass
                    ea = head
            except Exception:
                pass
            if not new_name or not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', new_name) or len(new_name) > 255:
                try:
                    self.logger.log(
                        f"[DataAware] Reject proposed name for EA=0x{ea:X}: invalid format/length ('{new_name}')"
                    )
                except Exception:
                    pass
                return False
            applied = set_name(ea, new_name, SN_CHECK | SN_NOWARN)
            applied_name = new_name if applied else None
            if not applied:
                try:
                    self.logger.log(
                        f"[DataAware] Primary rename failed (maybe conflict): EA=0x{ea:X} name='{new_name}', trying fallback"
                    )
                except Exception:
                    pass
                suffix = f"_{ea:X}"
                base = new_name
                max_len = 255 - len(suffix)
                if len(base) > max_len:
                    base = base[:max_len]
                fallback = base + suffix
                if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', fallback):
                    fallback = f"g_{fallback}"
                applied = set_name(ea, fallback, SN_CHECK | SN_NOWARN)
                applied_name = fallback if applied else None
                # Record whether fallback name was used
                try:
                    self.logger.log(
                        f"[DataAware] Fallback rename used for EA=0x{ea:X} -> '{applied_name or ''}'"
                    )
                except Exception:
                    pass
            if not applied or not applied_name:
                return False
            try:
                set_cmt(ea, f"[Auto data-rename] func=0x{get_func_attr(get_func(ea), FUNCATTR_START):X} new={applied_name} conf={confidence} reason={reason}", 1)
            except Exception:
                pass
            self.data_graph.renamed_data.add(ea)
            if ea in self.data_graph.data_nodes:
                self.data_graph.data_nodes[ea]['name'] = applied_name
            self.success_count += 1
            self.logger.log(f"Data renamed: 0x{ea:X} -> {applied_name}")
            return True
        except Exception as e:
            self.fail_count += 1
            self.logger.log(f"apply data rename error 0x{ea:X}: {e}", "ERROR")
            return False

    def run(self):
        self.logger.log("=" * 60)
        self.logger.log("Data-aware Global/Data Renamer started")
        self.logger.log("=" * 60)
        try:
            self.graph.build_graph()
            self.data_graph.build_edges()
            if self.config.DATA_AWARE_ENABLED:
                try:
                    self.data_graph.link_indirect_strings_via_llm()
                except Exception as e:
                    self.logger.log(f"Indirect strings linking skipped: {e}", "WARNING")
            if self.config.FCG_EXPORT_ENABLED:
                self.graph.export_call_graph(self.config.FCG_OUTPUT_DIR, self.config.FCG_EXPORT_FORMATS, self.config.FCG_SUMMARY_TOPN)
                self.data_graph.export_data_graph(self.config.FCG_OUTPUT_DIR)
            iteration = 0
            while True:
                iteration += 1
                self.logger.log(f"\n--- Data Iteration {iteration} ---")
                metrics = self.data_graph.compute_metrics()
                items = []
                for fea, m in metrics.items():
                    unnamed_present = False
                    for de in self.data_graph.func_to_data.get(fea, set()):
                        nm = get_name(de) or ''
                        if self._is_default_data_name(nm):
                            unnamed_present = True
                            break
                    if not unnamed_present:
                        continue
                    items.append((fea, m['YZ'], m['R']))
                try:
                    self.logger.log(
                        f"[DataAware] Iter{iteration}: metrics_funcs={len(metrics)} items_with_unnamed={len(items)}"
                    )
                except Exception:
                    pass
                if not items:
                    try:
                        self.logger.log(f"[DataAware] Iter{iteration}: no functions contain generic/unnamed data; stopping")
                    except Exception:
                        pass
                    break
                items.sort(key=lambda t: (-t[1], t[2], t[0]))
                batch = items[:min(self.config.DATA_BATCH_SIZE, len(items))]
                payloads = []
                iter_start_success = self.success_count
                for fea, yz, r in batch:
                    # Record candidate nodes and metrics (log-file only)
                    try:
                        m = metrics.get(fea, {})
                        func_name = get_func_name(fea) or f"sub_{fea:X}"
                        x_val = m.get('X', 0)
                        y_val = m.get('Y', 0)
                        z_val = float(m.get('Z', 0)) if m.get('Z', 0) is not None else 0.0
                        r_val = float(m.get('R', 0)) if m.get('R', 0) is not None else 0.0
                        yz_val = float(m.get('YZ', 0)) if m.get('YZ', 0) is not None else 0.0
                        self.logger.log(
                            f"[DataAware] Candidate FCG node 0x{fea:X} ({func_name}) metrics: X={x_val} Y={y_val} Z={z_val:.3f} R={r_val:.3f} YZ={yz_val:.3f}"
                        )
                    except Exception:
                        pass
                    payload = self._prepare_payload_for_function(fea)
                    if payload:
                        payloads.append(payload)
                        # Record the unnamed data list within this payload
                        try:
                            func_name = payload.get('func_name', get_func_name(fea) or f"sub_{fea:X}")
                            self.logger.log(
                                f"[DataAware] Payload for 0x{fea:X} ({func_name}): strings={len(payload.get('strings', []))}, unnamed_datas={len(payload.get('datas', []))}, official_apis={len(payload.get('official_apis', []))}"
                            )
                            for d in payload.get('datas', []):
                                de = d.get('ea')
                                cur_nm = get_name(de) or d.get('name', '') or ''
                                sz = d.get('size', 0)
                                bp = (d.get('bytes_preview', '') or '')
                                self.logger.log(
                                    f"[DataAware]   - Data EA=0x{de:X} old_name='{cur_nm}' size={sz} bytes_preview='{bp}'"
                                )
                        except Exception:
                            pass
                try:
                    total_unnamed = sum(len(p.get('datas', [])) for p in payloads)
                    self.logger.log(
                        f"[DataAware] Iter{iteration}: payloads={len(payloads)} total_unnamed_datas={total_unnamed}"
                    )
                except Exception:
                    pass
                if not payloads:
                    try:
                        self.logger.log(f"[DataAware] Iter{iteration}: no payloads generated; stopping")
                    except Exception:
                        pass
                    break
                # Prefer async batch when available
                results_map = {}
                if hasattr(self.llm, 'propose_data_renames_batch'):
                    results_map = self.llm.propose_data_renames_batch(
                        payloads,
                        max_workers=self.config.DATA_MAX_WORKERS,
                        requests_per_min=self.config.REQUESTS_PER_MIN
                    ) or {}
                    try:
                        # Summarize parsed LLM responses per function in logs
                        for p in payloads:
                            fea = p['func_ea']
                            res = results_map.get(fea)
                            cnt = len(res.get('rename', [])) if res and isinstance(res, dict) else 0
                            self.logger.log(f"[DataAware] Parse result for func=0x{fea:X} ({p.get('func_name','')}): items={cnt}")
                    except Exception:
                        pass
                else:
                    # fallback per-item calls with thread pool
                    try:
                        # Compatibility for older sessions: prefer self.llm.propose_data_renames,
                        # otherwise fallback to class local _propose_data_renames_fallback.
                        call_fn = getattr(self.llm, 'propose_data_renames', None)
                        if call_fn is None:
                            self.logger.log("propose_data_renames not found on LLMInterface; using local fallback", "WARNING")
                            call_fn = self._propose_data_renames_fallback
                        with ThreadPoolExecutor(max_workers=self.config.DATA_MAX_WORKERS) as ex:
                            futs = {ex.submit(call_fn, p): p['func_ea'] for p in payloads}
                            for fut in as_completed(futs):
                                fea = futs[fut]
                                try:
                                    results_map[fea] = fut.result()
                                except Exception as e:
                                    self.logger.log(f"fallback propose batch error fea=0x{fea:X}: {e}", "ERROR")
                                    results_map[fea] = None
                        try:
                            for p in payloads:
                                fea = p['func_ea']
                                res = results_map.get(fea)
                                cnt = len(res.get('rename', [])) if res and isinstance(res, dict) else 0
                                self.logger.log(f"[DataAware] Parse result for func=0x{fea:X} ({p.get('func_name','')}): items={cnt}")
                            
                        except Exception:
                            pass
                    except Exception as e:
                        self.logger.log(f"fallback propose batch setup failed: {e}", "ERROR")
                try:
                    suggestions_count = 0
                    for res in results_map.values():
                        if res and isinstance(res, dict):
                            suggestions_count += len(res.get('rename', []))
                    self.logger.log(
                        f"[DataAware] Iter{iteration}: llm_responses={len(results_map)} suggestions={suggestions_count}"
                    )
                except Exception:
                    pass
                # Apply results
                for p in payloads:
                    res = results_map.get(p['func_ea'])
                    if not res:
                        continue
                    for item in res.get('rename', []):
                        ea = item['ea']
                        new_name = item['proposed_name']
                        reason = item.get('reason', '')
                        conf = item.get('confidence', 0)
                        # Only rename non-string data: skip direct strings or addresses confirmed as strings
                        try:
                            kind = str(item.get('kind', 'data')).lower()
                            if kind == 'string' or self.data_graph._is_string_at(ea):
                                self.logger.log(
                                    f"[DataAware] Skip string rename EA=0x{ea:X} (func=0x{p['func_ea']:X} {p.get('func_name','')}) proposed='{new_name}' reason='{reason}'"
                                )
                                continue
                        except Exception:
                            pass
                        # Record LLM suggestion before applying (old name, proposed, confidence, reason)
                        try:
                            old_nm = get_name(ea) or ''
                            self.logger.log(
                                f"[DataAware] Will rename data EA=0x{ea:X} (func=0x{p['func_ea']:X} {p.get('func_name','')}) old='{old_nm}' -> new='{new_name}' conf={conf} reason='{reason}'"
                            )
                        except Exception:
                            pass
                        self._apply_data_rename(ea, new_name, reason, conf)
                try:
                    applied_this_iter = self.success_count - iter_start_success
                    self.logger.log(f"[DataAware] Iter{iteration}: applied={applied_this_iter}")
                except Exception:
                    pass
                self.logger.log(f"Progress: data renamed {self.success_count}, failed {self.fail_count}")
            self.logger.log("\n" + "=" * 60)
            self.logger.log("Data-aware renaming completed!")
            self.logger.log(f"Renamed: {self.success_count}")
            self.logger.log(f"Failed: {self.fail_count}")
            self.logger.log("=" * 60)
            ida_kernwin.info(f"Data-aware renaming finished!\nSuccess: {self.success_count}\nFailed: {self.fail_count}\nLog: {os.path.abspath(self.config.LOG_FILE)}")
        except Exception as e:
            self.logger.log(f"Runtime error (data-aware): {e}", "ERROR")
            ida_kernwin.warning(f"Data-aware processing failed: {str(e)}")
        finally:
            self.logger.close()

    # ===== Fallbacks if running in an IDA session that hasn't reloaded LLMInterface =====
    def _build_data_rename_prompt_local(self, payload):
        lines = []
        lines.append("You are an expert assisting in naming global/static data in a compiled binary.")
        lines.append(f"Function 0x{payload['func_ea']:X} ({payload['func_name']})")
        if payload.get('assembly'):
            lines.append("=== Assembly ===")
            lines.append(payload['assembly'][:1200])
        if payload.get('pseudocode'):
            lines.append("=== Pseudocode ===")
            lines.append(payload['pseudocode'][:1600])
        if payload.get('official_apis'):
            lines.append("=== Official APIs (known functions) ===")
            lines.append(", ".join(sorted(payload['official_apis'])[:50]))
        if payload.get('callers'):
            lines.append("=== 1-hop Callers (pseudocode snippets) ===")
            for c in payload['callers'][:3]:
                lines.append(f"- {c['name']}")
                if c.get('pseudocode'):
                    lines.append(c['pseudocode'][:300])
        if payload.get('callees'):
            lines.append("=== 1-hop Callees (pseudocode snippets) ===")
            for c in payload['callees'][:5]:
                lines.append(f"- {c['name']}")
                if c.get('pseudocode'):
                    lines.append(c['pseudocode'][:220])
        if payload.get('strings'):
            lines.append("=== Linked Strings ===")
            for s in payload['strings'][:50]:
                lines.append(f"- 0x{s['ea']:X}: {s.get('preview','')[:200]}")
        if payload.get('datas'):
            lines.append("=== Linked Unnamed Data ===")
            for d in payload['datas'][:50]:
                sz = d.get('size', 0)
                lines.append(f"- 0x{d['ea']:X} name={d.get('name','')} size={sz}")
                if d.get('bytes_preview'):
                    lines.append(d['bytes_preview'][:120])
        lines.append("Task: Propose meaningful names for the listed unnamed data (global/static/struct fields), reflecting their roles.")
        lines.append("IMPORTANT: Only propose renames for non-string global/static data (tables, buffers, structs, arrays). Do NOT propose renaming any direct strings; strings are context only.")
        lines.append("Return strictly JSON only:\n{\n  \"rename\": [\n    {\n      \"ea\": \"0x...\",\n      \"proposed_name\": \"string\",\n      \"kind\": \"global|data\",\n      \"confidence\": 0.0,\n      \"reason\": \"...\"\n    }\n  ]\n}")
        return "\n".join(lines)

    def _parse_data_renames_local(self, content):
        try:
            import re
            json_pattern = r'\{[^{}]*\}'
            matches = re.findall(json_pattern, content, re.DOTALL)
            for match in reversed(matches):
                try:
                    obj = json.loads(match)
                    if isinstance(obj, dict) and 'rename' in obj and isinstance(obj['rename'], list):
                        out = []
                        for item in obj.get('rename', []):
                            try:
                                ea_str = item.get('ea') or item.get('addr') or item.get('address')
                                if isinstance(ea_str, int):
                                    ea_val = ea_str
                                else:
                                    ea_val = int(str(ea_str), 16)
                                name = item.get('proposed_name') or item.get('name')
                                if not name:
                                    continue
                                kind = item.get('kind', 'data')
                                conf = float(item.get('confidence', 0.0))
                                reason = item.get('reason', '')
                                out.append({'ea': ea_val, 'proposed_name': name, 'kind': kind, 'confidence': conf, 'reason': reason})
                            except Exception:
                                continue
                        return {'rename': out}
                except Exception:
                    continue
        except Exception:
            pass
        return None

    def _propose_data_renames_fallback(self, payload):
        # Use LLMInterface transport but build/parse locally
        try:
            prompt = self._build_data_rename_prompt_local(payload)
            headers = {
                "Authorization": f"Bearer {self.llm.api_key}",
                "Content-Type": "application/json"
            }
            data = {
                "model": self.llm.model_name,
                "messages": [
                    {"role": "system", "content": "You precisely return JSON only."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.3,
                "max_tokens": 700
            }
            attempt = 0
            last_exc = None
            while attempt < self.llm.max_retries:
                attempt += 1
                try:
                    self.llm.rate_limiter.acquire()
                    response = requests.post(
                        f"{self.llm.base_url}/chat/completions",
                        headers=headers, json=data, timeout=45
                    )
                    if response.status_code in (429, 500, 502, 503, 504):
                        raise requests.HTTPError(f"HTTP {response.status_code}: {response.text[:2000]}")
                    break
                except Exception as e:
                    last_exc = e
                    time.sleep(self.llm.retry_backoff_base * (2 ** (attempt - 1)))
                    response = None
            if response is None:
                raise last_exc if last_exc else RuntimeError("Unknown error")
            if response.status_code != 200:
                self.logger.log(f"fallback propose_data_renames failed: {response.status_code} {response.text[:500]}", "ERROR")
                return None
            result = response.json()
            content = result['choices'][0]['message']['content']
            return self._parse_data_renames_local(content)
        except Exception as e:
            self.logger.log(f"fallback propose_data_renames error: {e}", "ERROR")
            return None
# ==================== Configuration loader ====================
def load_config():
    """Load configuration"""
    # Prefer user-defined llmsss_config.json; fallback to llm_config.json
    primary = "llmsss_config.json"
    fallback = "llm_config.json"
    config_file = primary if os.path.exists(primary) else (fallback if os.path.exists(fallback) else fallback)
    config = Config()
    
    # Try loading from file
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                config.API_BASE_URL = data.get('api_base_url', config.API_BASE_URL)
                config.API_KEY = data.get('api_key', config.API_KEY)
                config.MODEL_NAME = data.get('model_name', config.MODEL_NAME)
                config.MAX_CONTEXT_DEPTH = data.get('max_context_depth', config.MAX_CONTEXT_DEPTH)
                config.MAX_ASM_LINES = data.get('max_asm_lines', config.MAX_ASM_LINES)
                config.MAX_PSEUDOCODE_LINES = data.get('max_pseudocode_lines', config.MAX_PSEUDOCODE_LINES)
                config.BATCH_SIZE = data.get('batch_size', config.BATCH_SIZE)
                config.MAX_WORKERS = data.get('max_workers', config.MAX_WORKERS)
                config.USE_ASYNC = data.get('use_async', config.USE_ASYNC)
                config.REQUESTS_PER_MIN = data.get('requests_per_min', config.REQUESTS_PER_MIN)
                config.MAX_RETRIES = data.get('max_retries', config.MAX_RETRIES)
                config.RETRY_BACKOFF_BASE = data.get('retry_backoff_base', config.RETRY_BACKOFF_BASE)
                # Optional detailed log path (support "auto" to generate timestamped file)
                dlf = data.get('detailed_log_file', None)
                if not dlf or (isinstance(dlf, str) and dlf.strip().lower() == "auto"):
                    config.DETAILED_LOG_FILE = f"private_func_rename_detailed_{time.strftime('%Y%m%d_%H%M%S')}.jsonl"
                else:
                    config.DETAILED_LOG_FILE = dlf
                config.CONSOLE_QUIET = data.get('console_quiet', config.CONSOLE_QUIET)
                # FCG export options (optional override)
                config.FCG_EXPORT_ENABLED = data.get('fcg_export_enabled', config.FCG_EXPORT_ENABLED)
                config.FCG_OUTPUT_DIR = data.get('fcg_output_dir', config.FCG_OUTPUT_DIR)
                config.FCG_EXPORT_FORMATS = data.get('fcg_export_formats', config.FCG_EXPORT_FORMATS)
                config.FCG_SUMMARY_TOPN = data.get('fcg_summary_topn', config.FCG_SUMMARY_TOPN)
                # Data-aware overrides
                config.DATA_AWARE_ENABLED = data.get('data_aware_enabled', config.DATA_AWARE_ENABLED)
                config.MIN_STRING_LEN = data.get('min_string_len', config.MIN_STRING_LEN)
                config.ZERO_GAP_MAX = data.get('zero_gap_max', config.ZERO_GAP_MAX)
                config.INDIRECT_STRING_SCAN_WINDOW = data.get('indirect_string_scan_window', config.INDIRECT_STRING_SCAN_WINDOW)
                config.MAX_INDIRECT_CHECKS_PER_RUN = data.get('max_indirect_checks_per_run', config.MAX_INDIRECT_CHECKS_PER_RUN)
                config.DATA_BATCH_SIZE = data.get('data_batch_size', config.DATA_BATCH_SIZE)
                config.MAX_DATA_PSEUDOCODE_LINES = data.get('max_data_pseudocode_lines', config.MAX_DATA_PSEUDOCODE_LINES)
                config.EXPORT_DATA_GRAPH = data.get('export_data_graph', config.EXPORT_DATA_GRAPH)
                # Indirect batch configs
                config.INDIRECT_BATCH_SIZE = data.get('indirect_batch_size', getattr(config, 'INDIRECT_BATCH_SIZE', 10))
                config.INDIRECT_MAX_WORKERS = data.get('indirect_max_workers', getattr(config, 'INDIRECT_MAX_WORKERS', 6))
                print(f"Config loaded: {config_file}")
        except Exception as e:
            print(f"Failed to load config: {e}")
    else:
        # Create default config file
        try:
            default_config = {
                'api_base_url': config.API_BASE_URL,
                'api_key': config.API_KEY,
                'model_name': config.MODEL_NAME,
                'max_context_depth': config.MAX_CONTEXT_DEPTH,
                'max_asm_lines': config.MAX_ASM_LINES,
                'max_pseudocode_lines': config.MAX_PSEUDOCODE_LINES,
                'batch_size': config.BATCH_SIZE,
                'max_workers': config.MAX_WORKERS,
                'use_async': config.USE_ASYNC,
                'requests_per_min': config.REQUESTS_PER_MIN,
                'max_retries': config.MAX_RETRIES,
                'retry_backoff_base': config.RETRY_BACKOFF_BASE,
                'detailed_log_file': "auto",
                'console_quiet': config.CONSOLE_QUIET,
                'fcg_export_enabled': config.FCG_EXPORT_ENABLED,
                'fcg_output_dir': config.FCG_OUTPUT_DIR,
                'fcg_export_formats': config.FCG_EXPORT_FORMATS,
                'fcg_summary_topn': config.FCG_SUMMARY_TOPN,
                'data_aware_enabled': config.DATA_AWARE_ENABLED,
                'min_string_len': config.MIN_STRING_LEN,
                'zero_gap_max': config.ZERO_GAP_MAX,
                'indirect_string_scan_window': config.INDIRECT_STRING_SCAN_WINDOW,
                'max_indirect_checks_per_run': config.MAX_INDIRECT_CHECKS_PER_RUN,
                'data_batch_size': config.DATA_BATCH_SIZE,
                'max_data_pseudocode_lines': config.MAX_DATA_PSEUDOCODE_LINES,
                'export_data_graph': config.EXPORT_DATA_GRAPH
                ,
                'indirect_batch_size': getattr(config, 'INDIRECT_BATCH_SIZE', 10),
                'indirect_max_workers': getattr(config, 'INDIRECT_MAX_WORKERS', 6)
            }
            with open(fallback, 'w', encoding='utf-8') as f:
                json.dump(default_config, f, indent=2, ensure_ascii=False)
            print(f"Created default config: {fallback}")
            print("Please edit the config file with your API settings")
        except:
            pass
    
    return config

# ==================== Main ====================
def main():
    """Main entry point"""
    print("\n" + "=" * 60)
    print("Private Function & Data-aware Smart Renamer v2.0")
    print("For IDA Pro 9.1")
    print("=" * 60 + "\n")
    
    # Ensure running inside IDA
    if 'idaapi' not in sys.modules:
        print("Error: This script must be run inside IDA Pro!")
        return
    
    # Ensure Hex-Rays is available
    if not ida_hexrays.init_hexrays_plugin():
        print("Error: Hex-Rays decompiler is required!")
        ida_kernwin.warning("Hex-Rays decompiler is required!")
        return
    
    # Load config
    config = load_config()
    
    # Confirm
    msg = ("Choose task:\n"
           "1) Rename private functions (FCG export)\n"
           "2) Rename unnamed global/data (Data-aware FCG)\n\n"
           f"API: {config.API_BASE_URL}\n"
           f"Model: {config.MODEL_NAME}\n\n"
           "Enter 1 or 2 (default 1)?")
    
    choice = ida_kernwin.ask_str("1", 0, msg)
    if not choice:
        choice = "1"
    
    if choice.strip() == "2":
        renamer = DataAwareRenamer(config)
        renamer.run()
    else:
        renamer = PrivateFunctionRenamer(config)
        renamer.run()

# Entry point
if __name__ == "__main__":
    main()


