#!/usr/bin/env python3
"""
Graph-based KLEE Output Analyzer
Converts KLEE symbolic execution results into a Neo4j graph database
for advanced vulnerability pattern analysis.
"""

import os
import re
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import logging

# Neo4j imports
try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False
    print("Warning: neo4j package not found. Install with: pip install neo4j")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class TestCase:
    """Represents a KLEE test case"""
    id: str
    status: str  # 'error', 'success', 'timeout'
    error_type: Optional[str] = None
    error_subtype: Optional[str] = None
    stack_trace: List[str] = None
    symbolic_vars: Dict[str, Any] = None
    execution_path: List[str] = None

@dataclass
class MemoryError:
    """Represents a memory error found by KLEE"""
    error_type: str  # 'memory_error', 'external_call', 'assertion'
    subtype: str     # 'object_read_only', 'out_of_bound_pointer', etc.
    location: str
    stack_trace: List[str]
    test_case_id: str

@dataclass
class Function:
    """Represents a function in the execution trace"""
    name: str
    function_type: str  # 'vulnerable', 'entry', 'helper'
    parameters: Dict[str, str]
    return_type: Optional[str] = None

class KLEEGraphParser:
    """Parses KLEE output and builds graph database"""
    
    def __init__(self, neo4j_uri: str = "bolt://localhost:7687", 
                 neo4j_user: str = "neo4j", neo4j_password: str = "",
                 neo4j_database: str = "neo4j"):
        self.neo4j_uri = neo4j_uri
        self.neo4j_user = neo4j_user
        self.neo4j_password = neo4j_password
        self.neo4j_database = neo4j_database
        self.driver = None
        self.graph_data = {}  # Store graph data in memory
        
        if NEO4J_AVAILABLE:
            try:
                self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
                # Test connection
                try:
                    with self.driver.session(database=self.neo4j_database) as session:
                        session.run("RETURN 1")
                    logger.info(f"Connected to Neo4j at {neo4j_uri}, db='{self.neo4j_database}'")
                except Exception as inner:
                    # Fallback: try default 'neo4j' database (Community edition)
                    logger.warning(f"Failed to open database '{self.neo4j_database}': {inner}")
                    if self.neo4j_database != "neo4j":
                        try:
                            with self.driver.session(database="neo4j") as session:
                                session.run("RETURN 1")
                            logger.info("Connected to default 'neo4j' database (fallback)")
                            self.neo4j_database = "neo4j"
                        except Exception as inner2:
                            raise inner2
            except Exception as e:
                logger.warning(f"Neo4j server not available: {e}")
                logger.info("Running in memory-only mode")
                self.driver = None
        else:
            logger.warning("Neo4j not available - running in analysis mode only")
    
    def parse_klee_output(self, klee_output_dir: str) -> Dict[str, Any]:
        """Parse KLEE output directory and extract structured data"""
        klee_path = Path(klee_output_dir)
        if not klee_path.exists():
            raise FileNotFoundError(f"KLEE output directory not found: {klee_output_dir}")
        
        logger.info(f"Parsing KLEE output from: {klee_output_dir}")
        
        # Parse main info file
        info_data = self._parse_info_file(klee_path)
        
        # Parse messages for errors
        messages_data = self._parse_messages_file(klee_path)
        
        # Parse test cases
        test_cases = self._parse_test_cases(klee_path)
        
        # Parse error files
        memory_errors = self._parse_error_files(klee_path)
        
        # Parse execution paths
        execution_paths = self._parse_execution_paths(klee_path)
        
        return {
            'info': info_data,
            'messages': messages_data,
            'test_cases': test_cases,
            'memory_errors': memory_errors,
            'execution_paths': execution_paths,
            'total_tests': len(test_cases),
            'total_errors': len(memory_errors)
        }
    
    def _parse_info_file(self, klee_path: Path) -> Dict[str, Any]:
        """Parse KLEE info file for execution statistics"""
        info_file = klee_path / "info"
        if not info_file.exists():
            return {}
        
        info_data = {}
        with open(info_file, 'r') as f:
            for line in f:
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().replace('KLEE: done:', '').strip()
                    value = value.strip()
                    
                    # Parse numeric values
                    if value.isdigit():
                        info_data[key] = int(value)
                    else:
                        info_data[key] = value
        
        return info_data
    
    def _parse_messages_file(self, klee_path: Path) -> List[Dict[str, str]]:
        """Parse KLEE messages file for error information"""
        messages_file = klee_path / "messages.txt"
        if not messages_file.exists():
            return []
        
        messages = []
        with open(messages_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('KLEE: ERROR:'):
                    error_msg = line.replace('KLEE: ERROR:', '').strip()
                    messages.append({
                        'type': 'error',
                        'message': error_msg,
                        'timestamp': datetime.now().isoformat()
                    })
                elif line.startswith('KLEE: NOTE:'):
                    note_msg = line.replace('KLEE: NOTE:', '').strip()
                    messages.append({
                        'type': 'note',
                        'message': note_msg,
                        'timestamp': datetime.now().isoformat()
                    })
        
        return messages
    
    def _parse_test_cases(self, klee_path: Path) -> List[TestCase]:
        """Parse KLEE test case files"""
        test_cases = []
        
        # Find all .ktest files
        ktest_files = list(klee_path.glob("test*.ktest"))
        logger.info(f"Found {len(ktest_files)} test case files")
        
        for ktest_file in ktest_files:
            test_id = ktest_file.stem
            test_case = TestCase(
                id=test_id,
                status='success',  # Default status
                symbolic_vars={},
                execution_path=[]
            )
            
            # Check for error files
            error_files = [
                ktest_file.with_suffix('.read_only.err'),
                ktest_file.with_suffix('.out_of_bound.err'),
                ktest_file.with_suffix('.external.err'),
                ktest_file.with_suffix('.abort.err'),
                ktest_file.with_suffix('.assert.err'),
                # Common KLEE error suffixes used in 4-agent runs
                ktest_file.with_suffix('.ptr.err'),
                ktest_file.with_suffix('.user.err'),
                ktest_file.with_suffix('.div.err'),
                ktest_file.with_suffix('.overflow.err')
            ]
            
            for error_file in error_files:
                if error_file.exists():
                    test_case.status = 'error'
                    # Keep raw suffix (e.g. ".ptr.err") as a simple error tag
                    test_case.error_type = error_file.suffix.replace('.', '')
                    test_case.stack_trace = self._parse_stack_trace(error_file)
                    break
            
            # Parse symbolic variables from .kquery files
            kquery_file = ktest_file.with_suffix('.kquery')
            if kquery_file.exists():
                test_case.symbolic_vars = self._parse_symbolic_variables(kquery_file)
            
            test_cases.append(test_case)
        
        return test_cases
    
    def _parse_stack_trace(self, error_file: Path) -> List[str]:
        """Parse stack trace from error file"""
        stack_trace = []
        with open(error_file, 'r') as f:
            in_stack = False
            for line in f:
                line = line.strip()
                if line.startswith('Stack:'):
                    in_stack = True
                    continue
                elif in_stack and line.startswith('#'):
                    stack_trace.append(line)
                elif in_stack and not line:
                    break
        
        return stack_trace
    
    def _parse_symbolic_variables(self, kquery_file: Path) -> Dict[str, Any]:
        """Parse symbolic variables from KLEE query file"""
        symbolic_vars = {}
        
        with open(kquery_file, 'r') as f:
            content = f.read()
            
            # Extract array declarations
            array_pattern = r'array\s+(\w+)\[(\d+)\]\s*:\s*w32\s*->\s*w8\s*=\s*symbolic'
            arrays = re.findall(array_pattern, content)
            
            for var_name, size in arrays:
                symbolic_vars[var_name] = {
                    'type': 'array',
                    'size': int(size),
                    'symbolic': True
                }
        
        return symbolic_vars
    
    def _parse_error_files(self, klee_path: Path) -> List[MemoryError]:
        """Parse memory error files"""
        memory_errors = []
        
        # Find all error files
        error_files = list(klee_path.glob("test*.err"))
        
        for error_file in error_files:
            # Derive test id from error filename by stripping known suffixes
            # Examples:
            #   test000006.ptr.err       -> test000006
            #   test000008.external.err  -> test000008
            #   test000005.user.err      -> test000005
            test_id = error_file.stem
            for suffix in (
                '.read_only',
                '.out_of_bound',
                '.external',
                '.abort',
                '.assert',
                '.ptr',
                '.user',
                '.div',
                '.overflow',
            ):
                if test_id.endswith(suffix):
                    test_id = test_id[: -len(suffix)]
                    break
            
            with open(error_file, 'r') as f:
                content = f.read()
                
                # Determine error type
                if 'memory error: object read only' in content:
                    error_type = 'memory_error'
                    subtype = 'object_read_only'
                elif 'memory error: out of bound pointer' in content:
                    error_type = 'memory_error'
                    subtype = 'out_of_bound_pointer'
                elif 'divide by zero' in content or 'division by zero' in content:
                    error_type = 'memory_error'
                    subtype = 'divide_by_zero'
                elif 'overflow' in content.lower():
                    error_type = 'memory_error'
                    subtype = 'overflow'
                elif 'external call' in content:
                    error_type = 'external_call'
                    subtype = 'external_function'
                elif 'user error' in content:
                    error_type = 'user_error'
                    subtype = 'user'
                elif 'abort' in content:
                    error_type = 'abort'
                    subtype = 'program_abort'
                elif 'assert' in content:
                    error_type = 'assertion'
                    subtype = 'assertion_failure'
                else:
                    error_type = 'unknown'
                    subtype = 'unknown'
                
                # Parse stack trace
                stack_trace = self._parse_stack_trace(error_file)
                
                memory_error = MemoryError(
                    error_type=error_type,
                    subtype=subtype,
                    location=error_file.name,
                    stack_trace=stack_trace,
                    test_case_id=test_id
                )
                
                memory_errors.append(memory_error)
        
        return memory_errors
    
    def _parse_execution_paths(self, klee_path: Path) -> List[Dict[str, Any]]:
        """Parse execution paths from KLEE output"""
        execution_paths = []
        
        # This is a simplified version - in practice, you'd parse more complex path information
        # from KLEE's internal data structures
        
        return execution_paths
    
    def build_graph_database(self, parsed_data: Dict[str, Any]) -> bool:
        """Build graph database from parsed KLEE data (Neo4j or memory)"""
        if self.driver:
            return self._build_neo4j_database(parsed_data)
        else:
            return self._build_memory_database(parsed_data)
    
    def _build_neo4j_database(self, parsed_data: Dict[str, Any]) -> bool:
        """Build Neo4j graph database"""
        try:
            with self.driver.session(database=self.neo4j_database) as session:
                # Clear existing data
                session.run("MATCH (n) DETACH DELETE n")
                
                # Create constraints and indexes
                self._create_schema(session)
                
                # Insert test cases
                self._insert_test_cases(session, parsed_data['test_cases'])
                
                # Insert memory errors
                self._insert_memory_errors(session, parsed_data['memory_errors'])
                
                # Insert functions from stack traces
                self._insert_functions(session, parsed_data['memory_errors'])
                
                # Create relationships
                self._create_relationships(session, parsed_data)
                
                logger.info("Neo4j graph database built successfully")
                return True
                
        except Exception as e:
            logger.error(f"Failed to build Neo4j database: {e}")
            return False
    
    def _build_memory_database(self, parsed_data: Dict[str, Any]) -> bool:
        """Build in-memory graph database"""
        try:
            # Store parsed data as graph structure
            self.graph_data = {
                'nodes': {
                    'test_cases': parsed_data['test_cases'],
                    'memory_errors': parsed_data['memory_errors'],
                    'functions': self._extract_functions(parsed_data['memory_errors'])
                },
                'relationships': self._build_relationships(parsed_data),
                'metadata': {
                    'total_tests': parsed_data['total_tests'],
                    'total_errors': parsed_data['total_errors'],
                    'parsed_at': datetime.now().isoformat()
                }
            }
            
            logger.info("Memory graph database built successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to build memory database: {e}")
            return False
    
    def _create_schema(self, session):
        """Create Neo4j schema constraints and indexes"""
        constraints = [
            "CREATE CONSTRAINT test_case_id FOR (t:TestCase) REQUIRE t.id IS UNIQUE",
            "CREATE CONSTRAINT function_name FOR (f:Function) REQUIRE f.name IS UNIQUE"
        ]
        
        indexes = [
            "CREATE INDEX test_case_status FOR (t:TestCase) ON (t.status)",
            "CREATE INDEX error_subtype FOR (e:Error) ON (e.subtype)",
            "CREATE INDEX function_type FOR (f:Function) ON (f.type)"
        ]
        
        for constraint in constraints:
            try:
                session.run(constraint)
            except Exception:
                pass  # Constraint might already exist
        
        for index in indexes:
            try:
                session.run(index)
            except Exception:
                pass  # Index might already exist
    
    def _insert_test_cases(self, session, test_cases: List[TestCase]):
        """Insert test cases into graph database"""
        for test_case in test_cases:
            # Convert complex objects to strings for Neo4j
            stack_trace_str = json.dumps(test_case.stack_trace) if test_case.stack_trace else None
            symbolic_vars_str = json.dumps(test_case.symbolic_vars) if test_case.symbolic_vars else None
            
            session.run("""
                CREATE (t:TestCase {
                    id: $id,
                    status: $status,
                    error_type: $error_type,
                    error_subtype: $error_subtype,
                    stack_trace: $stack_trace,
                    symbolic_vars: $symbolic_vars
                })
            """, 
            id=test_case.id,
            status=test_case.status,
            error_type=test_case.error_type,
            error_subtype=test_case.error_subtype,
            stack_trace=stack_trace_str,
            symbolic_vars=symbolic_vars_str
            )
    
    def _insert_memory_errors(self, session, memory_errors: List[MemoryError]):
        """Insert memory errors into graph database"""
        for error in memory_errors:
            # Convert stack trace to string for Neo4j
            stack_trace_str = json.dumps(error.stack_trace) if error.stack_trace else None
            
            session.run("""
                CREATE (e:Error {
                    type: $type,
                    subtype: $subtype,
                    location: $location,
                    stack_trace: $stack_trace,
                    test_case_id: $test_case_id
                })
            """,
            type=error.error_type,
            subtype=error.subtype,
            location=error.location,
            stack_trace=stack_trace_str,
            test_case_id=error.test_case_id
            )
    
    def _insert_functions(self, session, memory_errors: List[MemoryError]):
        """Insert functions from stack traces"""
        functions = set()
        
        for error in memory_errors:
            for stack_frame in error.stack_trace:
                # Extract function name from stack frame
                # Format: #000000167 in vulnerable_set(data=1636382539776, ...)
                if ' in ' in stack_frame:
                    func_name = stack_frame.split(' in ')[1].split('(')[0]
                    functions.add(func_name)
        
        for func_name in functions:
            # Determine function type
            if 'vulnerable' in func_name.lower():
                func_type = 'vulnerable'
            elif func_name == 'main':
                func_type = 'entry'
            else:
                func_type = 'helper'
            
            session.run("""
                CREATE (f:Function {
                    name: $name,
                    type: $type
                })
            """,
            name=func_name,
            type=func_type
            )
    
    def _create_relationships(self, session, parsed_data: Dict[str, Any]):
        """Create relationships between nodes"""
        # Link test cases to errors
        session.run("""
            MATCH (t:TestCase), (e:Error)
            WHERE t.id = e.test_case_id
            CREATE (t)-[:FINDS]->(e)
        """)
        
        # Create relationships manually for each error
        for error in parsed_data['memory_errors']:
            if error.stack_trace:
                for stack_frame in error.stack_trace:
                    if ' in ' in stack_frame:
                        func_name = stack_frame.split(' in ')[1].split('(')[0]
                        # Link function to error
                        session.run("""
                            MATCH (f:Function {name: $func_name}), (e:Error {test_case_id: $test_case_id})
                            CREATE (f)-[:TRIGGERS]->(e)
                        """, func_name=func_name, test_case_id=error.test_case_id)
                        
                        # Link test case to function
                        session.run("""
                            MATCH (t:TestCase {id: $test_case_id}), (f:Function {name: $func_name})
                            CREATE (t)-[:EXECUTES]->(f)
                        """, test_case_id=error.test_case_id, func_name=func_name)
    
    def _extract_functions(self, memory_errors: List[MemoryError]) -> List[Function]:
        """Extract functions from memory errors"""
        functions = {}
        
        for error in memory_errors:
            for stack_frame in error.stack_trace:
                if ' in ' in stack_frame:
                    func_name = stack_frame.split(' in ')[1].split('(')[0]
                    if func_name not in functions:
                        # Determine function type
                        if 'vulnerable' in func_name.lower():
                            func_type = 'vulnerable'
                        elif func_name == 'main':
                            func_type = 'entry'
                        else:
                            func_type = 'helper'
                        
                        functions[func_name] = Function(
                            name=func_name,
                            function_type=func_type,
                            parameters={}
                        )
        
        return list(functions.values())
    
    def _build_relationships(self, parsed_data: Dict[str, Any]) -> Dict[str, List[Dict]]:
        """Build relationships between nodes"""
        relationships = {
            'test_case_to_error': [],
            'function_to_error': [],
            'test_case_to_function': []
        }
        
        # Build test case to error relationships
        for error in parsed_data['memory_errors']:
            relationships['test_case_to_error'].append({
                'test_case_id': error.test_case_id,
                'error_type': error.error_type,
                'error_subtype': error.subtype
            })
        
        # Build function to error relationships
        functions = self._extract_functions(parsed_data['memory_errors'])
        for error in parsed_data['memory_errors']:
            for stack_frame in error.stack_trace:
                if ' in ' in stack_frame:
                    func_name = stack_frame.split(' in ')[1].split('(')[0]
                    relationships['function_to_error'].append({
                        'function_name': func_name,
                        'error_type': error.error_type,
                        'error_subtype': error.subtype
                    })
        
        # Build test case to function relationships
        for test_case in parsed_data['test_cases']:
            if test_case.status == 'error':
                for error in parsed_data['memory_errors']:
                    if error.test_case_id == test_case.id:
                        for stack_frame in error.stack_trace:
                            if ' in ' in stack_frame:
                                func_name = stack_frame.split(' in ')[1].split('(')[0]
                                relationships['test_case_to_function'].append({
                                    'test_case_id': test_case.id,
                                    'function_name': func_name
                                })
        
        return relationships
    
    def analyze_vulnerabilities(self) -> Dict[str, Any]:
        """Analyze vulnerabilities using graph queries"""
        if self.driver:
            return self._analyze_neo4j_vulnerabilities()
        else:
            return self._analyze_memory_vulnerabilities()
    
    def _analyze_neo4j_vulnerabilities(self) -> Dict[str, Any]:
        """Analyze vulnerabilities using Neo4j queries"""
        try:
            with self.driver.session(database=self.neo4j_database) as session:
                analysis = {}
                
                # 1. Count vulnerability types
                result = session.run("""
                    MATCH (e:Error)
                    RETURN e.subtype as error_type, COUNT(*) as count
                    ORDER BY count DESC
                """)
                analysis['error_types'] = [dict(record) for record in result]
                
                # 2. Find most vulnerable functions
                result = session.run("""
                    MATCH (f:Function)-[:TRIGGERS]->(e:Error)
                    RETURN f.name as function, f.type as type, COUNT(e) as error_count
                    ORDER BY error_count DESC
                """)
                analysis['vulnerable_functions'] = [dict(record) for record in result]
                
                # 3. Find test cases with most errors
                result = session.run("""
                    MATCH (t:TestCase)-[:FINDS]->(e:Error)
                    RETURN t.id as test_case, t.status as status, COUNT(e) as error_count
                    ORDER BY error_count DESC
                """)
                analysis['problematic_tests'] = [dict(record) for record in result]
                
                # 4. Find memory error patterns
                result = session.run("""
                    MATCH (f:Function)-[:TRIGGERS]->(e:Error {type: 'memory_error'})
                    RETURN f.name as function, e.subtype as error_subtype, COUNT(*) as count
                    ORDER BY count DESC
                """)
                analysis['memory_error_patterns'] = [dict(record) for record in result]
                
                # 5. Find execution paths leading to errors
                result = session.run("""
                    MATCH path = (t:TestCase)-[:EXECUTES]->(f:Function)-[:TRIGGERS]->(e:Error)
                    WHERE e.type = 'memory_error'
                    RETURN t.id as test_case, f.name as function, e.subtype as error_type
                    ORDER BY t.id
                """)
                analysis['error_paths'] = [dict(record) for record in result]
                
                return analysis
                
        except Exception as e:
            logger.error(f"Failed to analyze Neo4j vulnerabilities: {e}")
            return {}
    
    def _analyze_memory_vulnerabilities(self) -> Dict[str, Any]:
        """Analyze vulnerabilities using memory graph data"""
        if not self.graph_data:
            logger.error("No graph data available")
            return {}
        
        analysis = {}
        
        # 1. Count error types
        error_counts = {}
        for error in self.graph_data['nodes']['memory_errors']:
            error_type = error.subtype
            error_counts[error_type] = error_counts.get(error_type, 0) + 1
        
        analysis['error_types'] = [
            {'error_type': error_type, 'count': count}
            for error_type, count in sorted(error_counts.items(), key=lambda x: x[1], reverse=True)
        ]
        
        # 2. Find vulnerable functions
        function_error_counts = {}
        for rel in self.graph_data['relationships']['function_to_error']:
            func_name = rel['function_name']
            if func_name not in function_error_counts:
                function_error_counts[func_name] = 0
            function_error_counts[func_name] += 1
        
        analysis['vulnerable_functions'] = [
            {'function': func_name, 'error_count': count}
            for func_name, count in sorted(function_error_counts.items(), key=lambda x: x[1], reverse=True)
        ]
        
        # 3. Find problematic test cases
        test_error_counts = {}
        for rel in self.graph_data['relationships']['test_case_to_error']:
            test_id = rel['test_case_id']
            if test_id not in test_error_counts:
                test_error_counts[test_id] = 0
            test_error_counts[test_id] += 1
        
        analysis['problematic_tests'] = [
            {'test_case': test_id, 'error_count': count}
            for test_id, count in sorted(test_error_counts.items(), key=lambda x: x[1], reverse=True)
        ]
        
        # 4. Find memory error patterns
        memory_patterns = {}
        for rel in self.graph_data['relationships']['function_to_error']:
            if rel['error_type'] == 'memory_error':
                key = f"{rel['function_name']} -> {rel['error_subtype']}"
                memory_patterns[key] = memory_patterns.get(key, 0) + 1
        
        analysis['memory_error_patterns'] = [
            {'pattern': pattern, 'count': count}
            for pattern, count in sorted(memory_patterns.items(), key=lambda x: x[1], reverse=True)
        ]
        
        # 5. Find error paths
        analysis['error_paths'] = []
        for rel in self.graph_data['relationships']['test_case_to_function']:
            test_id = rel['test_case_id']
            func_name = rel['function_name']
            
            # Find associated errors
            for error_rel in self.graph_data['relationships']['function_to_error']:
                if error_rel['function_name'] == func_name:
                    analysis['error_paths'].append({
                        'test_case': test_id,
                        'function': func_name,
                        'error_type': error_rel['error_subtype']
                    })
        
        return analysis
    
    def generate_report(self, analysis: Dict[str, Any], output_file: str = "vulnerability_report.json"):
        """Generate vulnerability analysis report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'analysis': analysis,
            'summary': {
                'total_error_types': len(analysis.get('error_types', [])),
                'total_vulnerable_functions': len(analysis.get('vulnerable_functions', [])),
                'total_problematic_tests': len(analysis.get('problematic_tests', [])),
                'total_memory_error_patterns': len(analysis.get('memory_error_patterns', []))
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Vulnerability report generated: {output_file}")
        return report
    
    def close(self):
        """Close Neo4j driver"""
        if self.driver:
            self.driver.close()

def main():
    """Main function to test the graph analyzer"""
    import sys
    import os
    
    # Check if Neo4j is available
    if not NEO4J_AVAILABLE:
        print("Neo4j package not available. Install with: pip install neo4j")
        print("Running in analysis-only mode...")
    
    # Get KLEE output directory from command line or use default
    if len(sys.argv) > 1:
        klee_output_dir = sys.argv[1]
    else:
        print("Usage: python3 graph_klee.py <klee-output-directory>")
        print("Example: python3 graph_klee.py 4agent_output/positive/klee_output/cwe-131-cve-2020-35904")
        sys.exit(1)
    
    # Check if directory exists
    if not os.path.exists(klee_output_dir):
        print(f"Error: Directory not found: {klee_output_dir}")
        print("Usage: python3 graph_klee.py <klee-output-directory>")
        print("Example: python3 graph_klee.py klee-out-35")
        sys.exit(1)
    
    # Initialize parser with your Neo4j credentials (env-overridable)
    parser = KLEEGraphParser(
        neo4j_uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
        neo4j_user=os.getenv("NEO4J_USER", "neo4j"), 
        neo4j_password=os.getenv("NEO4J_PASSWORD", ""),
        neo4j_database=os.getenv("NEO4J_DATABASE", "neo4j")
    )
    
    try:
        print(f"Parsing KLEE output from: {klee_output_dir}")
        parsed_data = parser.parse_klee_output(klee_output_dir)
        
        print(f"Parsed {parsed_data['total_tests']} test cases")
        print(f"Found {parsed_data['total_errors']} memory errors")
        
        # Build graph database (Neo4j or memory)
        print("Building graph database...")
        success = parser.build_graph_database(parsed_data)
        
        if success:
            print("Analyzing vulnerabilities...")
            analysis = parser.analyze_vulnerabilities()
            
            print("Vulnerability Analysis Results:")
            print("=" * 50)
            
            # Print error types
            if 'error_types' in analysis:
                print("\nError Types:")
                for error in analysis['error_types'][:5]:  # Top 5
                    print(f"  {error['error_type']}: {error['count']} occurrences")
            
            # Print vulnerable functions
            if 'vulnerable_functions' in analysis:
                print("\nMost Vulnerable Functions:")
                for func in analysis['vulnerable_functions'][:5]:  # Top 5
                    print(f"  {func['function']}: {func['error_count']} errors")
            
            # Print memory error patterns
            if 'memory_error_patterns' in analysis:
                print("\nMemory Error Patterns:")
                for pattern in analysis['memory_error_patterns'][:5]:  # Top 5
                    if isinstance(pattern, dict) and 'pattern' in pattern:
                        print(f"  {pattern['pattern']}: {pattern['count']} times")
                    else:
                        print(f"  {pattern}")
            
            # Print problematic test cases
            if 'problematic_tests' in analysis:
                print("\nMost Problematic Test Cases:")
                for test in analysis['problematic_tests'][:5]:  # Top 5
                    print(f"  {test['test_case']}: {test['error_count']} errors")
            
            # Print error paths
            if 'error_paths' in analysis and analysis['error_paths']:
                print("\nError Execution Paths:")
                for path in analysis['error_paths'][:5]:  # Top 5
                    print(f"  {path['test_case']} -> {path['function']} -> {path['error_type']}")
            
            # Generate report
            report = parser.generate_report(analysis)
            print(f"\nDetailed report saved to: vulnerability_report.json")
        else:
            print("Failed to build graph database")
            print("Parsed data available for analysis:")
            print(f"  Test cases: {len(parsed_data['test_cases'])}")
            print(f"  Memory errors: {len(parsed_data['memory_errors'])}")
            print(f"  Messages: {len(parsed_data['messages'])}")
    
    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        print(f"Error: {e}")
    
    finally:
        parser.close()

if __name__ == "__main__":
    main()
