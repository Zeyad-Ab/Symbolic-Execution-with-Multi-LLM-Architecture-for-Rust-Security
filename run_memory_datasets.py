import os
import sys
import json
from pathlib import Path
from datetime import datetime
from contextlib import redirect_stdout
from io import StringIO
from core_analyzer_4agent_multimodel import CoreAnalyzer4AgentMultiModel

def run_memory_datasets():
    f = StringIO()
    with redirect_stdout(f):
        analyzer = CoreAnalyzer4AgentMultiModel()

    results = {
        'positive': [],
        'summary': {}
    }

    positive_files = sorted(Path("Positive").glob("*.rs"))
    print(f"Processing {len(positive_files)} files from Positive/...")

    for i, file_path in enumerate(positive_files, 1):
        print(f"Generating FFI for file {i}/{len(positive_files)}: {file_path.name}")
        try:
            f = StringIO()
            with redirect_stdout(f):
                result = analyzer.analyze_single_file_4agent(str(file_path), "positive")
            result['file_name'] = file_path.name
            results['positive'].append(result)
            print(f"Generating KLEE output for file {i}/{len(positive_files)}: {file_path.name}")
        except Exception as e:
            print(f"Error processing {file_path.name}: {e}")
            results['positive'].append({
                'file_name': file_path.name,
                'error': str(e),
                'vulnerabilities_detected': False
            })

    pos_vulns = sum(r.get('total_vulnerabilities', 0) for r in results['positive'])
    pos_detected = sum(1 for r in results['positive'] if r.get('vulnerabilities_detected', False))

    results['summary'] = {
        'positive': {
            'total_files': len(positive_files),
            'files_processed': len(results['positive']),
            'vulnerabilities_detected': pos_detected,
            'total_vulnerabilities': pos_vulns
        }
    }

    print(json.dumps(results['summary'], indent=2))
    return results

if __name__ == "__main__":
    run_memory_datasets()
