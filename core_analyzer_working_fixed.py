# Single-agent Rust vulnerability analyzer (one LLM per run).
# Supports: gpt4-turbo, gpt4o-mini, gpt5.2, claude-opus, claude-sonnet, gemini-2, gemini-3.

import os
import subprocess
import tempfile
import json
import re
import time
from pathlib import Path
from typing import Dict, Tuple
import openai

class CoreAnalyzerWorking:
    def __init__(self, model_name: str = "gpt4o-mini"):
        if os.path.exists('.env'):
            with open('.env') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        k, v = line.split('=', 1)
                        os.environ[k.strip()] = v.strip()
        self.model_config = {
            'gpt4-turbo': {'provider': 'openai', 'model': 'gpt-4-turbo-preview', 'cost_per_1k_input': 0.01, 'cost_per_1k_output': 0.03},
            'gpt4o-mini': {'provider': 'openai', 'model': 'gpt-4o-mini', 'cost_per_1k_input': 0.00015, 'cost_per_1k_output': 0.0006},
            'gpt5.2': {'provider': 'openai', 'model': 'gpt-5.2-2025-12-11', 'cost_per_1k_input': 0.02, 'cost_per_1k_output': 0.06},
            'claude-opus': {'provider': 'anthropic', 'model': 'claude-opus-4-5-20251101', 'cost_per_1k_input': 0.015, 'cost_per_1k_output': 0.075},
            'claude-sonnet': {'provider': 'anthropic', 'model': 'claude-sonnet-4-5-20250929', 'cost_per_1k_input': 0.003, 'cost_per_1k_output': 0.015},
            'gemini-2': {'provider': 'google', 'model': 'gemini-2.0-flash', 'cost_per_1k_input': 0.0, 'cost_per_1k_output': 0.0},
            'gemini-3': {'provider': 'google', 'model': 'gemini-3-flash-preview', 'cost_per_1k_input': 0.0, 'cost_per_1k_output': 0.0}
        }
        if model_name not in self.model_config:
            raise ValueError("Unsupported model: %s" % model_name)
        self.model_name = model_name
        cfg = self.model_config[model_name]
        self.provider = cfg['provider']
        self.api_model = cfg['model']
        self.output_base_dir = "%s_output" % model_name
        if self.provider == 'openai':
            self.openai_client = openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
        elif self.provider == 'anthropic':
            import anthropic
            self.anthropic_client = anthropic.Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))
        elif self.provider == 'google':
            import google.generativeai as genai
            genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
            self.gemini_model = genai.GenerativeModel(self.api_model)
        self.klee_include_path = "/opt/homebrew/Cellar/klee/3.1_5/include"
        self.llvm_link_path = "/opt/homebrew/Cellar/llvm@16/16.0.6_1/bin/llvm-link"
        self.clang_path = "/opt/homebrew/Cellar/llvm@16/16.0.6_1/bin/clang"
        self.rustc_path = "rustc"

    def _call_llm(self, system_prompt: str, user_prompt: str, max_tokens: int = 1500, temperature: float = 0.1) -> str:
        if self.provider == 'openai':
            kw = {"model": self.api_model, "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}], "temperature": temperature}
            if 'gpt-5' in self.api_model:
                kw["max_completion_tokens"] = max_tokens
            else:
                kw["max_tokens"] = max_tokens
            r = self.openai_client.chat.completions.create(**kw)
            return r.choices[0].message.content.strip()
        elif self.provider == 'anthropic':
            r = self.anthropic_client.messages.create(model=self.api_model, max_tokens=max_tokens, temperature=temperature, system=system_prompt, messages=[{"role": "user", "content": user_prompt}])
            return r.content[0].text.strip()
        elif self.provider == 'google':
            full = system_prompt + "\n\n" + user_prompt
            r = self.gemini_model.generate_content(full, generation_config={"temperature": temperature, "max_output_tokens": max_tokens})
            if hasattr(r, 'text') and r.text:
                return r.text.strip()
            if r.candidates and r.candidates[0].content.parts:
                return r.candidates[0].content.parts[0].text.strip()
            raise ValueError("Empty response from Gemini")
        raise ValueError("Unsupported provider")

    def clean_llm_output(self, code: str) -> str:
        code = re.sub(r'```rust\s*\n', '', code)
        code = re.sub(r'```\s*$', '', code, flags=re.MULTILINE)
        return code.strip()

    def generate_rust_ffi_wrapper(self, rust_code: str, max_retries: int = 3) -> str:
        system = "You are an expert FFI code generator. Generate EXACTLY 10 functions. Each: #[no_mangle] pub extern \"C\" fn. Use ONLY: u8, i32, i64, usize, *const u8, *mut u8. Return i32. Functions must be VULNERABLE. Output ONLY Rust code, no markdown."
        user = "Generate 10 FFI test functions based on this code:\n\n%s\n\nOutput ONLY Rust code." % rust_code[:600]
        last_error = None
        for attempt in range(max_retries):
            try:
                code = self._call_llm(system, user if attempt == 0 else (user + "\n\nPREVIOUS ERROR:\n" + str(last_error) + "\n\nFIX and output ONLY Rust code."), max_tokens=2500, temperature=0.1 if attempt == 0 else 0.2)
                cleaned = self.clean_llm_output(code)
                v = self.validate_rust_code(cleaned)
                if v['success']:
                    return cleaned
                last_error = v.get('error', 'unknown')
            except Exception as e:
                last_error = str(e)
        raise Exception("FFI generation failed: %s" % last_error)

    def validate_rust_code(self, code: str) -> Dict:
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rs', delete=False) as f:
                f.write(code)
                path = f.name
            r = subprocess.run([self.rustc_path, '--crate-type=staticlib', '--emit=llvm-bc', '-o', '/tmp/test_output.bc', path], capture_output=True, text=True, timeout=30)
            os.unlink(path)
            if os.path.exists('/tmp/test_output.bc'):
                os.unlink('/tmp/test_output.bc')
            return {'success': r.returncode == 0, 'error': r.stderr if r.returncode != 0 else None}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def extract_ffi_functions(self, ffi_code: str) -> list:
        functions = []
        for func_name, params, return_type in re.findall(r'pub\s+extern\s+"C"\s+fn\s+(\w+)\s*\(([^)]*)\)\s*->\s*(\w+)', ffi_code):
            param_list = []
            if params.strip():
                for p in params.split(','):
                    p = p.strip()
                    if ':' in p:
                        name, ptype = p.split(':', 1)
                        ptype = ptype.strip()
                        base = ptype.replace('*const', '').replace('*mut', '').strip()
                        c_base = {'u8': 'unsigned char', 'i32': 'int32_t', 'i64': 'int64_t', 'usize': 'size_t'}.get(base, base)
                        c_type = ("const %s *" % c_base) if '*const' in ptype else (("%s *" % c_base) if '*mut' in ptype else c_base)
                        param_list.append((name.strip(), c_type))
            c_ret = 'int32_t' if return_type == 'i32' else ('int64_t' if return_type == 'i64' else 'size_t')
            functions.append((func_name, param_list, c_ret))
        return functions

    def generate_klee_wrapper(self, ffi_code: str) -> str:
        functions = self.extract_ffi_functions(ffi_code)
        decls = ["extern %s %s(%s);" % (rt, fn, ", ".join("%s %s" % (t, n) for n, t in params)) for fn, params, rt in functions]
        cases = []
        for i, (fn, params, _) in enumerate(functions):
            args = []
            for n, t in params:
                if 'size_t' in t or 'intptr_t' in t: args.append("idx%d" % ((i % 5) + 1))
                elif 'int32_t' in t and '*' not in t: args.append(['a','b','c','d'][i % 4])
                elif '*' in t: args.append("buffer")
                else: args.append("0")
            cases.append("    %s (path == %d) { %s(%s);\n    " % ("if" if i == 0 else "} else if", i, fn, ", ".join(args)))
        cases.append("}")
        return """#include <klee/klee.h>
#include <stdint.h>
%s
int main() {
    size_t idx1,idx2,idx3,idx4,idx5;
    unsigned char val1,val2,val3,val4;
    int32_t a,b,c,d,choice;
    unsigned char buffer[128];
    klee_make_symbolic(&idx1,sizeof(idx1),"idx1");
    klee_make_symbolic(&idx2,sizeof(idx2),"idx2");
    klee_make_symbolic(&idx3,sizeof(idx3),"idx3");
    klee_make_symbolic(&idx4,sizeof(idx4),"idx4");
    klee_make_symbolic(&idx5,sizeof(idx5),"idx5");
    klee_make_symbolic(&val1,sizeof(val1),"val1");
    klee_make_symbolic(&val2,sizeof(val2),"val2");
    klee_make_symbolic(&val3,sizeof(val3),"val3");
    klee_make_symbolic(&val4,sizeof(val4),"val4");
    klee_make_symbolic(&a,sizeof(a),"a");
    klee_make_symbolic(&b,sizeof(b),"b");
    klee_make_symbolic(&c,sizeof(c),"c");
    klee_make_symbolic(&d,sizeof(d),"d");
    klee_make_symbolic(&choice,sizeof(choice),"choice");
    klee_make_symbolic(buffer,sizeof(buffer),"buffer");
    klee_assume(idx1<10000); klee_assume(idx2<10000); klee_assume(idx3<10000); klee_assume(idx4<10000); klee_assume(idx5<10000);
    int path = klee_range(0, %d, "path");
%s
    return 0;
}
""" % ("\n".join(decls), len(functions), "\n".join(cases))

    def run_working_klee_analysis(self, rust_code: str, ffi_code: str, klee_code: str, file_path: str = None, dataset_type: str = None) -> Dict:
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rs', delete=False) as f:
                f.write(ffi_code)
                rp = f.name
            r = subprocess.run([self.rustc_path, '--crate-type=staticlib', '--emit=llvm-bc', '-o', 'rust_ffi.bc', rp], capture_output=True, text=True, timeout=60)
            os.unlink(rp)
            if r.returncode != 0:
                return {'returncode': -1, 'test_cases': 0, 'errors': 0, 'warnings': 0, 'critical_errors': 0}
            with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
                f.write(klee_code)
                cp = f.name
            r = subprocess.run([self.clang_path, '-I', self.klee_include_path, '-emit-llvm', '-c', '-o', 'klee_wrapper.bc', cp], capture_output=True, text=True, timeout=60)
            os.unlink(cp)
            if r.returncode != 0:
                return {'returncode': -1, 'test_cases': 0, 'errors': 0, 'warnings': 0, 'critical_errors': 0}
            r = subprocess.run([self.llvm_link_path, 'rust_ffi.bc', 'klee_wrapper.bc', '-o', 'linked.bc'], capture_output=True, text=True, timeout=60)
            if r.returncode != 0:
                return {'returncode': -1, 'test_cases': 0, 'errors': 0, 'warnings': 0, 'critical_errors': 0}
            out_dir = str(Path(self.output_base_dir) / (dataset_type or "unknown") / "klee_output" / ("klee-%d" % int(time.time())))
            os.makedirs(out_dir, exist_ok=True)
            r = subprocess.run(['klee', '--output-dir='+out_dir, '--max-time=120', '--max-memory=4000', '--external-calls=all', '--optimize', '--emit-all-errors', 'linked.bc'], capture_output=True, text=True, timeout=300)
            p = Path(out_dir)
            if not p.exists():
                return {'returncode': -1, 'test_cases': 0, 'errors': 0, 'warnings': 0, 'critical_errors': 0}
            tc = len(list(p.glob("*.ktest")))
            ptr_e = len(list(p.glob("*.ptr.err")))
            ext_e = len(list(p.glob("*.external.err")))
            div_e = len(list(p.glob("*.div.err")))
            ov_e = len(list(p.glob("*.overflow.err")))
            crit = ptr_e + ext_e + div_e + ov_e
            return {'returncode': r.returncode, 'test_cases': tc, 'errors': 0, 'warnings': 0, 'critical_errors': crit}
        except Exception:
            return {'returncode': -1, 'test_cases': 0, 'errors': 0, 'warnings': 0, 'critical_errors': 0}

    def _save_ffi_code(self, ffi_code: str, rust_file_path: str, dataset_type: str):
        d = Path(self.output_base_dir) / dataset_type / "ffi"
        d.mkdir(parents=True, exist_ok=True)
        name = os.path.basename(rust_file_path)
        if '_' in name and 'CVE-' in name and 'CWE-' in name:
            parts = name.replace('.rs','').split('_')
            out = d / ("cwe.%s.cve.%s.%s.%s.rs" % (parts[1].replace('CWE-',''), parts[0].replace('CVE-',''), dataset_type, self.model_name))
        else:
            out = d / ("ffi_%s_%s_%d.rs" % (dataset_type, self.model_name, int(time.time())))
        with open(out, 'w') as f:
            f.write(ffi_code)

    def _save_c_wrapper(self, c_code: str, rust_file_path: str, dataset_type: str):
        d = Path(self.output_base_dir) / dataset_type / "wrappers"
        d.mkdir(parents=True, exist_ok=True)
        name = os.path.basename(rust_file_path)
        if '_' in name and 'CVE-' in name and 'CWE-' in name:
            parts = name.replace('.rs','').split('_')
            out = d / ("cwe.%s.cve.%s.%s.%s.c" % (parts[1].replace('CWE-',''), parts[0].replace('CVE-',''), dataset_type, self.model_name))
        else:
            out = d / ("wrapper_%s_%s_%d.c" % (dataset_type, self.model_name, int(time.time())))
        with open(out, 'w') as f:
            f.write(c_code)

    def analyze_single_file_working(self, rust_file_path: str, dataset_type: str = "unknown") -> Dict:
        try:
            with open(rust_file_path, 'r') as f:
                rust_code = f.read()
        except Exception:
            return {'vulnerabilities_detected': False, 'total_vulnerabilities': 0, 'confidence': 0.0}
        try:
            ffi_code = self.generate_rust_ffi_wrapper(rust_code)
            self._save_ffi_code(ffi_code, rust_file_path, dataset_type)
            klee_code = self.generate_klee_wrapper(ffi_code)
            self._save_c_wrapper(klee_code, rust_file_path, dataset_type)
            kr = self.run_working_klee_analysis(rust_code, ffi_code, klee_code, rust_file_path, dataset_type)
            crit = kr['critical_errors'] + kr.get('errors', 0)
            return {
                'vulnerabilities_detected': crit > 0,
                'total_vulnerabilities': crit,
                'confidence': 0.95 if kr['critical_errors'] > 0 else (0.7 if kr.get('errors',0) > 0 else 0.0),
                'klee_results': kr
            }
        except Exception:
            return {'vulnerabilities_detected': False, 'total_vulnerabilities': 0, 'confidence': 0.0}

if __name__ == "__main__":
    analyzer = CoreAnalyzerWorking(model_name="gpt4o-mini")
    test_file = "Positive_Memory/CVE-2019-15550_CWE-125.rs"
    if os.path.exists(test_file):
        analyzer.analyze_single_file_working(test_file, "positive")
