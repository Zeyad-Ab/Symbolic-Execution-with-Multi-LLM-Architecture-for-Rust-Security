#!/usr/bin/env python3
"""
Enhanced Comprehensive Analyzer
Implements sophisticated vulnerability detection for Rust code
"""

import os
import re
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import concurrent.futures
from threading import Lock

@dataclass
class ComprehensiveAnalysisConfig:
    """Configuration for comprehensive analysis"""
    max_parallel_workers: int = 4
    confidence_threshold: float = 0.3
    early_termination_threshold: float = 0.5
    enable_llm_analysis: bool = True
    enable_pattern_matching: bool = True
    enable_confidence_scoring: bool = True

class EnhancedComprehensiveAnalyzer:
    """Enhanced comprehensive analyzer with sophisticated vulnerability detection"""
    
    def __init__(self, config: ComprehensiveAnalysisConfig = None):
        self.config = config or ComprehensiveAnalysisConfig()
        self.lock = Lock()
        
        # Load vulnerability patterns from config
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        
    def _load_vulnerability_patterns(self) -> Dict[str, List[str]]:
        """Load vulnerability patterns"""
        # Enhanced vulnerability patterns
        enhanced_patterns = {
                'buffer_overflow': [
                    r'unsafe\s*\{[^}]*ptr::[^}]*\}',
                    r'std::ptr::(write|read|copy|copy_nonoverlapping)',
                    r'std::slice::from_raw_parts',
                    r'std::mem::(transmute|forget|uninitialized)',
                    r'std::ptr::(offset|add|sub)',
                ],
                'integer_overflow': [
                    r'\.wrapping_add\(',
                    r'\.wrapping_sub\(',
                    r'\.wrapping_mul\(',
                    r'std::num::Wrapping',
                    r'\.checked_add\(',
                    r'\.checked_sub\(',
                ],
                'use_after_free': [
                    r'std::ptr::(drop_in_place|read)',
                    r'std::mem::(forget|drop)',
                    r'Box::from_raw',
                    r'std::rc::Rc::new',
                    r'std::sync::Arc::new',
                ],
                'null_pointer_dereference': [
                    r'\.unwrap\(\)',
                    r'\.expect\(',
                    r'std::ptr::null',
                    r'std::ptr::null_mut',
                    r'Option::None',
                ],
                'memory_leak': [
                    r'std::mem::forget',
                    r'std::rc::Rc::new',
                    r'std::sync::Arc::new',
                    r'Box::leak',
                    r'std::mem::ManuallyDrop',
                ],
                'unsafe_pointer_operations': [
                    r'unsafe\s*\{[^}]*\*[^}]*\}',
                    r'std::ptr::(as_ref|as_mut)',
                    r'std::ptr::(offset|add|sub)',
                    r'std::ptr::(write|read)',
                ],
                'string_vulnerabilities': [
                    r'std::str::from_utf8_unchecked',
                    r'std::str::from_utf8_lossy',
                    r'std::ffi::(CString|CStr)::from_raw',
                    r'std::ffi::(CString|CStr)::as_ptr',
                ],
                'concurrency_issues': [
                    r'std::sync::(Mutex|RwLock)::new',
                    r'std::thread::spawn',
                    r'std::sync::atomic',
                    r'std::sync::(Arc|Rc)::new',
                ],
                'path_traversal': [
                    r'std::fs::(read|write|create)',
                    r'std::path::Path::(join|parent)',
                    r'\.\./',
                    r'\.\.\\',
                ],
                'sql_injection': [
                    r'format!\(',
                    r'println!\(',
                    r'print!\(',
                    r'eprintln!\(',
                ],
                'weak_crypto': [
                    r'std::collections::hash_map::DefaultHasher',
                    r'md5::',
                    r'sha1::',
                    r'std::hash::Hash',
                ]
        }
        
        return enhanced_patterns
    
    def analyze_single_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze a single Rust file with enhanced vulnerability detection"""
        try:
            with open(file_path, 'r') as f:
                rust_code = f.read()
            
            # Enhanced vulnerability detection
            vulnerabilities = 0
            vulnerability_types = []
            confidence_scores = []
            
            # Pattern-based detection
            for vuln_type, patterns in self.vulnerability_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, rust_code, re.IGNORECASE | re.MULTILINE)
                    if matches:
                        vulnerabilities += len(matches)
                        vulnerability_types.append(vuln_type)
                        confidence_scores.append(min(1.0, len(matches) * 0.2))
            
            # Advanced analysis
            advanced_analysis = self._perform_advanced_analysis(rust_code)
            vulnerabilities += advanced_analysis['vulnerabilities']
            vulnerability_types.extend(advanced_analysis['types'])
            confidence_scores.extend(advanced_analysis['confidence_scores'])
            
            # Calculate overall confidence
            overall_confidence = self._calculate_confidence(vulnerabilities, vulnerability_types, confidence_scores)
            
            # Determine if file is vulnerable
            is_vulnerable = vulnerabilities > 0 and overall_confidence > self.config.confidence_threshold
            
            return {
                'file_path': file_path,
                'file_name': Path(file_path).name,
                'total_vulnerabilities': vulnerabilities,
                'vulnerabilities_detected': is_vulnerable,
                'vulnerability_types': list(set(vulnerability_types)),
                'confidence': overall_confidence,
                'success': True,
                'analysis_details': advanced_analysis
            }
            
        except Exception as e:
            return {
                'file_path': file_path,
                'file_name': Path(file_path).name,
                'error': str(e),
                'success': False
            }
    
    def _perform_advanced_analysis(self, rust_code: str) -> Dict[str, Any]:
        """Perform advanced analysis on Rust code"""
        vulnerabilities = 0
        types = []
        confidence_scores = []
        
        lines = rust_code.split('\n')
        
        # Analyze unsafe blocks
        unsafe_blocks = self._analyze_unsafe_blocks(rust_code)
        vulnerabilities += unsafe_blocks['count']
        types.extend(unsafe_blocks['types'])
        confidence_scores.extend(unsafe_blocks['confidence_scores'])
        
        # Analyze function complexity
        complexity_analysis = self._analyze_complexity(rust_code)
        vulnerabilities += complexity_analysis['count']
        types.extend(complexity_analysis['types'])
        confidence_scores.extend(complexity_analysis['confidence_scores'])
        
        # Analyze error handling
        error_analysis = self._analyze_error_handling(rust_code)
        vulnerabilities += error_analysis['count']
        types.extend(error_analysis['types'])
        confidence_scores.extend(error_analysis['confidence_scores'])
        
        return {
            'vulnerabilities': vulnerabilities,
            'types': types,
            'confidence_scores': confidence_scores
        }
    
    def _analyze_unsafe_blocks(self, rust_code: str) -> Dict[str, Any]:
        """Analyze unsafe blocks for vulnerabilities"""
        vulnerabilities = 0
        types = []
        confidence_scores = []
        
        # Find unsafe blocks
        unsafe_pattern = r'unsafe\s*\{[^}]*\}'
        unsafe_blocks = re.findall(unsafe_pattern, rust_code, re.MULTILINE | re.DOTALL)
        
        for block in unsafe_blocks:
            # Check for dangerous operations
            dangerous_ops = ['ptr::', 'mem::', 'transmute', 'forget', 'uninitialized']
            dangerous_count = sum(block.count(op) for op in dangerous_ops)
            
            if dangerous_count > 0:
                vulnerabilities += 1
                types.append('unsafe_block')
                confidence_scores.append(min(1.0, dangerous_count * 0.3))
        
        return {
            'count': vulnerabilities,
            'types': types,
            'confidence_scores': confidence_scores
        }
    
    def _analyze_complexity(self, rust_code: str) -> Dict[str, Any]:
        """Analyze code complexity for potential vulnerabilities"""
        vulnerabilities = 0
        types = []
        confidence_scores = []
        
        # Count nested structures
        nested_count = rust_code.count('{') - rust_code.count('}')
        if nested_count > 5:  # High nesting
            vulnerabilities += 1
            types.append('high_complexity')
            confidence_scores.append(0.3)
        
        # Count function parameters
        function_pattern = r'fn\s+\w+\s*\([^)]*\)'
        functions = re.findall(function_pattern, rust_code)
        for func in functions:
            param_count = func.count(',') + 1
            if param_count > 5:  # Too many parameters
                vulnerabilities += 1
                types.append('high_parameter_count')
                confidence_scores.append(0.2)
        
        return {
            'count': vulnerabilities,
            'types': types,
            'confidence_scores': confidence_scores
        }
    
    def _analyze_error_handling(self, rust_code: str) -> Dict[str, Any]:
        """Analyze error handling patterns"""
        vulnerabilities = 0
        types = []
        confidence_scores = []
        
        # Count unwrap/expect calls
        unwrap_count = rust_code.count('.unwrap()')
        expect_count = rust_code.count('.expect(')
        
        if unwrap_count > 3:
            vulnerabilities += 1
            types.append('excessive_unwrap')
            confidence_scores.append(min(1.0, unwrap_count * 0.2))
        
        if expect_count > 2:
            vulnerabilities += 1
            types.append('excessive_expect')
            confidence_scores.append(min(1.0, expect_count * 0.3))
        
        return {
            'count': vulnerabilities,
            'types': types,
            'confidence_scores': confidence_scores
        }
    
    def _calculate_confidence(self, vulnerabilities: int, types: List[str], scores: List[float]) -> float:
        """Calculate overall confidence score"""
        if vulnerabilities == 0:
            return 0.0
        
        # Base confidence from vulnerability count
        base_confidence = min(0.6, vulnerabilities * 0.1)
        
        # Boost for high-risk types
        high_risk_types = ['buffer_overflow', 'use_after_free', 'unsafe_pointer_operations']
        high_risk_count = sum(1 for t in types if t in high_risk_types)
        risk_boost = min(0.3, high_risk_count * 0.15)
        
        # Boost for multiple vulnerability types
        diversity_boost = min(0.1, len(set(types)) * 0.05)
        
        # Average of individual confidence scores
        avg_confidence = sum(scores) / len(scores) if scores else 0.0
        
        return min(1.0, base_confidence + risk_boost + diversity_boost + avg_confidence * 0.2)
    
    def run_enhanced_analysis(self, positive_folder: str, negative_folder: str) -> Dict[str, Any]:
        """Run enhanced analysis on both positive and negative datasets"""
        print("Running enhanced comprehensive analysis...")
        
        # Find all Rust files
        positive_files = list(Path(positive_folder).rglob("*.rs"))
        negative_files = list(Path(negative_folder).rglob("*.rs"))
        
        print(f"Found {len(positive_files)} positive files and {len(negative_files)} negative files")
        
        # Analyze files in parallel
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_parallel_workers) as executor:
            # Submit positive files
            positive_futures = {
                executor.submit(self.analyze_single_file, str(file_path)): str(file_path)
                for file_path in positive_files
            }
            
            # Submit negative files
            negative_futures = {
                executor.submit(self.analyze_single_file, str(file_path)): str(file_path)
                for file_path in negative_files
            }
            
            # Collect results
            positive_results = {}
            for future in concurrent.futures.as_completed(positive_futures):
                file_path = positive_futures[future]
                try:
                    result = future.result()
                    positive_results[file_path] = result
                except Exception as e:
                    positive_results[file_path] = {
                        'file_path': file_path,
                        'error': str(e),
                        'success': False
                    }
            
            negative_results = {}
            for future in concurrent.futures.as_completed(negative_futures):
                file_path = negative_futures[future]
                try:
                    result = future.result()
                    negative_results[file_path] = result
                except Exception as e:
                    negative_results[file_path] = {
                        'file_path': file_path,
                        'error': str(e),
                        'success': False
                    }
        
        analysis_time = time.time() - start_time
        
        return {
            'positive': positive_results,
            'negative': negative_results,
            'analysis_time': analysis_time,
            'config': self.config
        }
