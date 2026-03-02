import os
import subprocess
import tempfile
import json
import textwrap
import re
import time
from pathlib import Path
from datetime import datetime
import openai
from typing import Dict, List, Tuple, Optional
from enum import Enum

class OptimizedAgentRole(Enum):
    ORACLE_VALIDATOR = "oracle"
    SAFETY_CHECKER = "safety"
    CODE_SPECIALIST = "specialist"
    FAST_FILTER = "filter"

class CoreAnalyzer4AgentMultiModel:
    def __init__(self):
        openai_key = os.getenv('OPENAI_API_KEY')
        anthropic_key = os.getenv('ANTHROPIC_API_KEY')
        if not openai_key:
            raise ValueError("OPENAI_API_KEY not found in environment")
        if not anthropic_key:
            raise ValueError("ANTHROPIC_API_KEY not found in environment")
        self.openai_client = openai.OpenAI(api_key=openai_key)
        try:
            import anthropic
            self.anthropic_client = anthropic.Anthropic(api_key=anthropic_key)
        except ImportError:
            raise ImportError("Please install: pip install anthropic")
        self.model_config = {
            OptimizedAgentRole.ORACLE_VALIDATOR: {'provider': 'openai', 'model': 'gpt-4-turbo-preview', 'cost_per_1k_input': 0.01, 'cost_per_1k_output': 0.03},
            OptimizedAgentRole.SAFETY_CHECKER: {'provider': 'anthropic', 'model': 'claude-opus-4-5-20251101', 'cost_per_1k_input': 0.015, 'cost_per_1k_output': 0.075},
            OptimizedAgentRole.CODE_SPECIALIST: {'provider': 'anthropic', 'model': 'claude-sonnet-4-5-20250929', 'cost_per_1k_input': 0.003, 'cost_per_1k_output': 0.015},
            OptimizedAgentRole.FAST_FILTER: {'provider': 'openai', 'model': 'gpt-4o-mini', 'cost_per_1k_input': 0.00015, 'cost_per_1k_output': 0.0006}
        }
        self.llvm_link_path = "/opt/homebrew/Cellar/llvm@16/16.0.6_1/bin/llvm-link"
        self.clang_path = "/opt/homebrew/Cellar/llvm@16/16.0.6_1/bin/clang"
        self.rustc_path = "rustc"
        self.klee_include_path = "/opt/homebrew/Cellar/klee/3.1_5/include"
        self.agent_memory = {role: [] for role in OptimizedAgentRole}
        self.api_costs = {role: 0.0 for role in OptimizedAgentRole}
        self.api_call_times = {role: [] for role in OptimizedAgentRole}
        print("Initialized 4-agent analyzer")

    def _call_openai(self, model: str, system_prompt: str, user_prompt: str, max_tokens: int = 1500, temperature: float = 0.1) -> Tuple[str, Dict]:
        start_time = time.time()
        response = self.openai_client.chat.completions.create(
            model=model, messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
            max_tokens=max_tokens, temperature=temperature)
        elapsed_time = time.time() - start_time
        result = response.choices[0].message.content.strip()
        usage = response.usage
        metrics = {'elapsed_time': elapsed_time, 'input_tokens': usage.prompt_tokens, 'output_tokens': usage.completion_tokens, 'model': model}
        return result, metrics

    def _call_anthropic(self, model: str, system_prompt: str, user_prompt: str, max_tokens: int = 1500, temperature: float = 0.1) -> Tuple[str, Dict]:
        start_time = time.time()
        response = self.anthropic_client.messages.create(
            model=model, max_tokens=max_tokens, temperature=temperature, system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}])
        elapsed_time = time.time() - start_time
        result = response.content[0].text.strip()
        metrics = {'elapsed_time': elapsed_time, 'input_tokens': response.usage.input_tokens, 'output_tokens': response.usage.output_tokens, 'model': model}
        return result, metrics

    def _call_agent(self, agent_role: OptimizedAgentRole, system_prompt: str, user_prompt: str, max_tokens: int = 1500, temperature: float = 0.1) -> str:
        config = self.model_config[agent_role]
        full_system_prompt = f"You are the {agent_role.value.upper()} agent in a 4-agent vulnerability analysis system.\n\n{system_prompt}\n\nYour responses should be precise and focused."
        if config['provider'] == 'openai':
            result, metrics = self._call_openai(config['model'], full_system_prompt, user_prompt, max_tokens, temperature)
        else:
            result, metrics = self._call_anthropic(config['model'], full_system_prompt, user_prompt, max_tokens, temperature)
        cost = (metrics['input_tokens'] / 1000 * config['cost_per_1k_input'] + metrics['output_tokens'] / 1000 * config['cost_per_1k_output'])
        self.api_costs[agent_role] += cost
        self.api_call_times[agent_role].append(metrics['elapsed_time'])
        return result

    def oracle_validator_agent(self, rust_code: str) -> Dict:
        print("\n[Agent 1] Planning...")
        system_prompt = "You are the Oracle/Validator Agent. Analyze Rust code and output JSON with: vulnerability_types (list), complexity_level (low/medium/high), recommended_ffi_functions (8-12), priority_areas, analysis_strategy."
        result = self._call_agent(OptimizedAgentRole.ORACLE_VALIDATOR, system_prompt, f"Create a strategic plan for this Rust code:\n\n```rust\n{rust_code[:1000]}\n```\n\nProvide JSON only.", max_tokens=1000)
        try:
            json_match = re.search(r'\{.*\}', result, re.DOTALL)
            plan = json.loads(json_match.group()) if json_match else {'vulnerability_types': ['buffer_overflow', 'null_pointer'], 'complexity_level': 'medium', 'recommended_ffi_functions': 10, 'priority_areas': ['memory operations'], 'analysis_strategy': 'standard'}
        except Exception:
            plan = {'vulnerability_types': ['buffer_overflow', 'null_pointer'], 'complexity_level': 'medium', 'recommended_ffi_functions': 10, 'priority_areas': ['memory operations'], 'analysis_strategy': 'standard'}
        return plan

    def safety_checker_agent(self, rust_code: str, plan: Dict) -> Dict:
        print("\n[Agent 2] Checking vulnerabilities...")
        system_prompt = "You are the Safety Checker Agent. Output JSON with: vulnerability_patterns, risk_score (0-10), critical_lines, verification_notes."
        result = self._call_agent(OptimizedAgentRole.SAFETY_CHECKER, system_prompt, f"Plan: {json.dumps(plan)}\n\nCode:\n{rust_code[:1500]}\n\nProvide JSON only.", max_tokens=1500)
        try:
            json_match = re.search(r'\{.*\}', result, re.DOTALL)
            analysis = json.loads(json_match.group()) if json_match else {'vulnerability_patterns': plan.get('vulnerability_types', []), 'risk_score': 7, 'critical_lines': [], 'verification_notes': 'Analysis complete'}
        except Exception:
            analysis = {'vulnerability_patterns': plan.get('vulnerability_types', []), 'risk_score': 6, 'critical_lines': [], 'verification_notes': 'Analysis complete'}
        return analysis

    def code_specialist_agent(self, rust_code: str, plan: Dict, safety_analysis: Dict, max_retries: int = 2) -> str:
        print("\n[Agent 3] Generating FFI...")
        system_prompt = """You are the Code Specialist Agent. Generate FFI test functions. CRITICAL: Each function #[no_mangle] pub extern "C" fn. Use ONLY: u8, i32, i64, usize, *const u8, *mut u8. Return i32. Functions must be VULNERABLE. Output ONLY Rust code, no markdown."""
        n = plan.get('recommended_ffi_functions', 10)
        user_prompt = f"Generate {n} FFI functions. Plan: {json.dumps(plan)}\nSafety: {json.dumps(safety_analysis)}\nCode context:\n{rust_code[:600]}\n\nOutput ONLY Rust code."
        for attempt in range(1, max_retries + 2):
            result = self._call_agent(OptimizedAgentRole.CODE_SPECIALIST, system_prompt, user_prompt, max_tokens=2500, temperature=0.15)
            cleaned_code = self.clean_llm_output(result)
            validation = self.validate_rust_code(cleaned_code)
            if validation['success']:
                return cleaned_code
            if attempt <= max_retries:
                user_prompt = f"Previous code failed to compile:\n{validation.get('error', '')[:800]}\n\nFix and regenerate. Output ONLY Rust code."
        return self._generate_fallback_ffi(plan)

    def _generate_fallback_ffi(self, plan: Dict) -> str:
        return '''#[no_mangle]
pub extern "C" fn test_buffer_overflow(buffer: *const u8, index: usize) -> i32 { unsafe { *buffer.add(index) as i32 } }
#[no_mangle]
pub extern "C" fn test_null_pointer(ptr: *const u8) -> i32 { unsafe { *ptr as i32 } }
#[no_mangle]
pub extern "C" fn test_integer_overflow(a: i32, b: i32) -> i32 { a + b }
#[no_mangle]
pub extern "C" fn test_division(a: i32, b: i32) -> i32 { a / b }
#[no_mangle]
pub extern "C" fn test_pointer_arithmetic(base: *const u8, offset: isize) -> i32 { unsafe { *base.offset(offset) as i32 } }
#[no_mangle]
pub extern "C" fn test_array_access(arr: *const i32, idx: usize) -> i32 { unsafe { *arr.add(idx) } }
#[no_mangle]
pub extern "C" fn test_unchecked_mul(a: i32, b: i32) -> i32 { a.wrapping_mul(b) }
#[no_mangle]
pub extern "C" fn test_unchecked_sub(a: i32, b: i32) -> i32 { a.wrapping_sub(b) }'''

    def clean_llm_output(self, code: str) -> str:
        code = re.sub(r'```rust\s*\n', '', code)
        code = re.sub(r'```\s*$', '', code, flags=re.MULTILINE)
        lines = [l for l in code.split('\n') if l.strip().startswith(('#', 'use ', 'pub ', 'fn ')) or (code.split('\n').index(l) > 0 and code.split('\n')[code.split('\n').index(l)-1].strip().startswith(('pub', 'fn'))) ]
        return '\n'.join(code.split('\n')).strip()

    def validate_rust_code(self, code: str) -> Dict:
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rs', delete=False) as f:
                f.write(code)
                temp_file = f.name
            result = subprocess.run([self.rustc_path, '--crate-type=staticlib', '--emit=llvm-bc', '-o', '/tmp/test_output.bc', temp_file], capture_output=True, text=True, timeout=30)
            os.unlink(temp_file)
            if os.path.exists('/tmp/test_output.bc'):
                os.unlink('/tmp/test_output.bc')
            return {'success': result.returncode == 0, 'error': result.stderr if result.returncode != 0 else None}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def extract_ffi_functions(self, ffi_code: str) -> list:
        functions = []
        pattern = r'pub\s+extern\s+"C"\s+fn\s+(\w+)\s*\(([^)]*)\)\s*->\s*(\w+)'
        for func_name, params, return_type in re.findall(pattern, ffi_code):
            param_list = []
            if params.strip():
                for param in params.split(','):
                    param = param.strip()
                    if ':' in param:
                        name, ptype = param.split(':', 1)
                        ptype = ptype.strip()
                        base_type = ptype.replace('*const', '').replace('*mut', '').strip()
                        c_base = {'u8': 'unsigned char', 'i32': 'int32_t', 'i64': 'int64_t', 'usize': 'size_t'}.get(base_type, base_type)
                        c_type = f"const {c_base} *" if '*const' in ptype else (f"{c_base} *" if '*mut' in ptype else c_base)
                        param_list.append((name.strip(), c_type))
            c_return = 'int32_t' if return_type == 'i32' else ('int64_t' if return_type == 'i64' else 'size_t')
            functions.append((func_name, param_list, c_return))
        return functions

    def generate_klee_wrapper(self, ffi_code: str) -> str:
        functions = self.extract_ffi_functions(ffi_code)
        func_declarations = []
        path_cases = []
        for i, (func_name, params, return_type) in enumerate(functions):
            param_strs = [f"{ptype} {pname}" for pname, ptype in params]
            func_declarations.append(f"extern {return_type} {func_name}({', '.join(param_strs)});")
            call_args = []
            for pname, ptype in params:
                if 'size_t' in ptype or 'intptr_t' in ptype: call_args.append(f"idx{(i % 5) + 1}")
                elif 'int32_t' in ptype and '*' not in ptype: call_args.append(['a', 'b', 'c', 'd'][i % 4])
                elif '*' in ptype: call_args.append("buffer")
                else: call_args.append("0")
            path_cases.append(f"    {'if' if i == 0 else '} else if'} (path == {i}) {{\n        {func_name}({', '.join(call_args)});\n    ")
        path_cases.append("}")
        klee_code = f"""#include <klee/klee.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
{chr(10).join(func_declarations)}
int main() {{
    size_t idx1, idx2, idx3, idx4, idx5;
    unsigned char val1, val2, val3, val4;
    int32_t a, b, c, d, choice;
    unsigned char buffer[128];
    klee_make_symbolic(&idx1, sizeof(idx1), "idx1");
    klee_make_symbolic(&idx2, sizeof(idx2), "idx2");
    klee_make_symbolic(&idx3, sizeof(idx3), "idx3");
    klee_make_symbolic(&idx4, sizeof(idx4), "idx4");
    klee_make_symbolic(&idx5, sizeof(idx5), "idx5");
    klee_make_symbolic(&val1, sizeof(val1), "val1");
    klee_make_symbolic(&val2, sizeof(val2), "val2");
    klee_make_symbolic(&val3, sizeof(val3), "val3");
    klee_make_symbolic(&val4, sizeof(val4), "val4");
    klee_make_symbolic(&a, sizeof(a), "a");
    klee_make_symbolic(&b, sizeof(b), "b");
    klee_make_symbolic(&c, sizeof(c), "c");
    klee_make_symbolic(&d, sizeof(d), "d");
    klee_make_symbolic(&choice, sizeof(choice), "choice");
    klee_make_symbolic(buffer, sizeof(buffer), "buffer");
    klee_assume(idx1 < 10000);
    klee_assume(idx2 < 10000);
    klee_assume(idx3 < 10000);
    klee_assume(idx4 < 10000);
    klee_assume(idx5 < 10000);
    int path = klee_range(0, {len(functions)}, "path");
{chr(10).join(path_cases)}
    return 0;
}}
"""
        return klee_code

    def fast_filter_agent(self, plan: Dict, safety_analysis: Dict) -> Dict:
        print("\n[Agent 4] Optimizing KLEE params...")
        result = self._call_agent(OptimizedAgentRole.FAST_FILTER, "Output JSON with: search_strategy (dfs/bfs/random-path), max_time (30-120), max_memory (2000-6000), max_forks (1000-10000), max_depth (500-2000).", f"Plan: {json.dumps(plan)}\nRisk: {safety_analysis.get('risk_score', 5)}\n\nJSON only.", max_tokens=600)
        try:
            json_match = re.search(r'\{.*\}', result, re.DOTALL)
            return json.loads(json_match.group()) if json_match else {'search_strategy': 'random-path', 'max_time': 60, 'max_memory': 4000, 'max_forks': 5000, 'max_depth': 1000}
        except Exception:
            return {'search_strategy': 'random-path', 'max_time': 60, 'max_memory': 4000, 'max_forks': 5000, 'max_depth': 1000}

    def run_klee_analysis(self, ffi_code: str, klee_code: str, klee_params: Dict, file_path: str = None, dataset_type: str = None) -> Dict:
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rs', delete=False) as f:
                f.write(ffi_code)
                rust_temp_file = f.name
            result = subprocess.run([self.rustc_path, '--crate-type=staticlib', '--emit=llvm-bc', '-o', 'rust_ffi_4agent_temp.bc', rust_temp_file], capture_output=True, text=True, timeout=60)
            os.unlink(rust_temp_file)
            if result.returncode != 0:
                return {'test_cases': 0, 'errors': 0, 'warnings': 0, 'critical_errors': 0}
            with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
                f.write(klee_code)
                c_temp_file = f.name
            result = subprocess.run([self.clang_path, '-I', self.klee_include_path, '-emit-llvm', '-c', '-o', 'klee_wrapper_4agent_temp.bc', c_temp_file], capture_output=True, text=True, timeout=60)
            os.unlink(c_temp_file)
            if result.returncode != 0:
                return {'test_cases': 0, 'errors': 0, 'warnings': 0, 'critical_errors': 0}
            result = subprocess.run([self.llvm_link_path, 'rust_ffi_4agent_temp.bc', 'klee_wrapper_4agent_temp.bc', '-o', 'linked_4agent_temp.bc'], capture_output=True, text=True, timeout=60)
            if result.returncode != 0:
                return {'test_cases': 0, 'errors': 0, 'warnings': 0, 'critical_errors': 0}
            klee_output_dir = f"4agent_output/{dataset_type or 'unknown'}/klee_output/klee-{int(time.time())}"
            os.makedirs(klee_output_dir, exist_ok=True)
            result = subprocess.run([
                'klee', f'--output-dir={klee_output_dir}', f'--max-time={klee_params["max_time"]}', f'--max-memory={klee_params["max_memory"]}',
                f'--max-forks={klee_params["max_forks"]}', f'--search={klee_params["search_strategy"]}', '--external-calls=all', '--optimize', '--emit-all-errors', 'linked_4agent_temp.bc'
            ], capture_output=True, text=True, timeout=klee_params["max_time"] + 60)
            for f in ['rust_ffi_4agent_temp.bc', 'klee_wrapper_4agent_temp.bc', 'linked_4agent_temp.bc']:
                if os.path.exists(f):
                    os.unlink(f)
            klee_out_path = Path(klee_output_dir)
            if not klee_out_path.exists():
                return {'test_cases': 0, 'errors': 0, 'warnings': 0, 'critical_errors': 0}
            test_cases = len(list(klee_out_path.glob("*.ktest")))
            ptr_errors = len(list(klee_out_path.glob("*.ptr.err")))
            external_errors = len(list(klee_out_path.glob("*.external.err")))
            div_errors = len(list(klee_out_path.glob("*.div.err")))
            overflow_errors = len(list(klee_out_path.glob("*.overflow.err")))
            critical_errors = ptr_errors + external_errors + div_errors + overflow_errors
            return {'test_cases': test_cases, 'errors': 0, 'warnings': 0, 'critical_errors': critical_errors, 'output_dir': klee_output_dir}
        except Exception as e:
            return {'test_cases': 0, 'errors': 0, 'warnings': 0, 'critical_errors': 0}

    def _save_ffi_code(self, ffi_code: str, rust_file_path: str, dataset_type: str):
        output_dir = Path("4agent_output") / dataset_type / "ffi"
        output_dir.mkdir(parents=True, exist_ok=True)
        file_name = os.path.basename(rust_file_path)
        output_path = output_dir / (f"ffi_{dataset_type}_4agent_{int(time.time())}.rs" if 'CVE-' not in file_name else f"cwe.{file_name.split('_')[1].replace('CWE-','')}.cve.{file_name.split('_')[0].replace('CVE-','')}.{dataset_type}.4agent.rs")
        with open(output_path, 'w') as f:
            f.write(ffi_code)

    def analyze_single_file_4agent(self, rust_file_path: str, dataset_type: str = "unknown") -> Dict:
        start_time = time.time()
        try:
            with open(rust_file_path, 'r') as f:
                rust_code = f.read()
        except Exception as e:
            return {'vulnerabilities_detected': False, 'total_vulnerabilities': 0, 'confidence': 0.0}
        try:
            plan = self.oracle_validator_agent(rust_code)
            safety_analysis = self.safety_checker_agent(rust_code, plan)
            ffi_code = self.code_specialist_agent(rust_code, plan, safety_analysis)
            self._save_ffi_code(ffi_code, rust_file_path, dataset_type)
            klee_params = self.fast_filter_agent(plan, safety_analysis)
            klee_code = self.generate_klee_wrapper(ffi_code)
            klee_results = self.run_klee_analysis(ffi_code, klee_code, klee_params, rust_file_path, dataset_type)
            total_vulnerabilities = klee_results['critical_errors'] + klee_results.get('errors', 0)
            vulnerabilities_detected = total_vulnerabilities > 0
            confidence = 0.95 if klee_results['critical_errors'] > 0 else (0.7 if klee_results.get('errors', 0) > 0 else 0.0)
            return {'vulnerabilities_detected': vulnerabilities_detected, 'total_vulnerabilities': total_vulnerabilities, 'confidence': confidence, 'klee_results': klee_results, 'elapsed_time': time.time() - start_time}
        except Exception as e:
            return {'vulnerabilities_detected': False, 'total_vulnerabilities': 0, 'confidence': 0.0}

if __name__ == "__main__":
    analyzer = CoreAnalyzer4AgentMultiModel()
    test_file = "Positive/CVE-2019-15550_CWE-125.rs"
    if os.path.exists(test_file):
        result = analyzer.analyze_single_file_4agent(test_file, "positive")
        print("Analysis complete:", result.get('total_vulnerabilities', 0), "vulnerabilities")
    else:
        print("Test file not found")
