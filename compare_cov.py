import json
import sys
import argparse
from collections import defaultdict
from pygments import highlight
from pygments.lexers import guess_lexer_for_filename
from pygments.formatters import Terminal256Formatter

def load_coverage(filename):
    with open(filename, 'r') as f:
        return json.load(f)

def read_file_content(filename):
    try:
        with open(filename, 'r') as f:
            return f.readlines()
    except FileNotFoundError:
        return None

def extract_line_coverage(file_data):
    line_coverage = {}
    for segment in file_data['segments']:
        line = segment[0]
        count = segment[2]
        line_coverage[line] = count
    return line_coverage

def compare_coverages(coverage1, coverage2):
    diff = defaultdict(lambda: defaultdict(dict))
    
    files1 = {file['filename']: file for file in coverage1['data'][0]['files']}
    files2 = {file['filename']: file for file in coverage2['data'][0]['files']}
    
    for filename, file1 in files1.items():
        if filename not in files2:
            continue
        
        file2 = files2[filename]
        
        lines1 = extract_line_coverage(file1)
        lines2 = extract_line_coverage(file2)
        
        different_lines = [line for line in set(lines1.keys()) | set(lines2.keys())
                           if lines1.get(line, 0) != lines2.get(line, 0)]
        
        if different_lines:
            diff[filename]['lines'] = sorted(different_lines)
            diff[filename]['coverage1'] = lines1
            diff[filename]['coverage2'] = lines2
    
    return diff

def print_summary(diff):
    print("Coverage Difference Summary:")
    print("============================")
    for filename, file_diff in diff.items():
        print(f"\nFile: {filename}")
        print(f"Lines with coverage differences: {', '.join(map(str, file_diff['lines']))}")

def print_code_with_diff(filename, file_diff, context=10):
    content = read_file_content(filename)
    if content is None:
        print(f"Error: Could not read file {filename}")
        return

    lexer = guess_lexer_for_filename(filename, ''.join(content))
    formatter = Terminal256Formatter()
    print(f"\nFile: {filename}")
    print("=" * (len(filename) + 6))

    diff_lines = file_diff['lines']
    
    # Generate ranges of lines to print
    ranges_to_print = []
    current_range = None
    for line in diff_lines:
        if current_range is None or line > current_range[1] + context:
            if current_range:
                ranges_to_print.append(current_range)
            current_range = [max(1, line - context), min(len(content), line + context)]
        else:
            current_range[1] = min(len(content), line + context)
    if current_range:
        ranges_to_print.append(current_range)

    # Print the ranges
    for i, (start, end) in enumerate(ranges_to_print):
        if i > 0:
            print("...")

        for j in range(start, end + 1):
            cov1 = file_diff['coverage1'].get(j, 0)
            cov2 = file_diff['coverage2'].get(j, 0)

            if j in diff_lines:
                prefix = f"\033[91m{j:4d} [{cov1} -> {cov2}]:\033[0m "  # Red
                highlighted_line = highlight(content[j-1].rstrip(), lexer, formatter).rstrip()
                print(f"{prefix}\033[91m{highlighted_line}\033[0m")  # Whole line in red
            else:
                prefix = f"{j:4d}     : "
                highlighted_line = highlight(content[j-1].rstrip(), lexer, formatter).rstrip()
                print(f"{prefix}{highlighted_line}")

def main():
    parser = argparse.ArgumentParser(description="Compare LLVM coverage data")
    parser.add_argument("coverage1", help="First coverage JSON file")
    parser.add_argument("coverage2", help="Second coverage JSON file")
    parser.add_argument("-c", "--context", type=int, default=5, help="Number of context lines (default: 5)")
    args = parser.parse_args()

    coverage1 = load_coverage(args.coverage1)
    coverage2 = load_coverage(args.coverage2)
    
    diff = compare_coverages(coverage1, coverage2)
    print_summary(diff)
    for filename, file_diff in diff.items():
        print_code_with_diff(filename, file_diff, context=args.context)

if __name__ == '__main__':
    main()
