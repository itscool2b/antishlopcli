#!/usr/bin/env python3
import os
import sys
import json
import argparse
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from colorama import init
from agent import Agent

init(autoreset=True)
console = Console()

class SecurityScanner:
    def __init__(self, path):
        self.path = Path(path)
        self.reports = []
        self.code_extensions = ['.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php', '.c', '.cpp', '.cs']
        self.ignore_dirs = ['node_modules', '.git', 'venv', '__pycache__', 'dist', 'build', '.venv', 'env']
        
    def get_files(self):
        files = []
        for root, dirs, filenames in os.walk(self.path):
            dirs[:] = [d for d in dirs if d not in self.ignore_dirs]
            for filename in filenames:
                if any(filename.endswith(ext) for ext in self.code_extensions):
                    files.append(Path(root) / filename)
        return files
    
    def scan(self):
        files = self.get_files()
        total = len(files)
        
        if total == 0:
            console.print("[yellow]No code files found to scan![/yellow]")
            return []
        
        console.print(Panel.fit(
            f"[bold cyan]AntiShlop Security Scanner[/bold cyan]\n"
            f"[dim]Scanning {total} files in {self.path}[/dim]",
            border_style="cyan"
        ))
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            scan_task = progress.add_task("[cyan]Scanning files...", total=total)
            
            for i, file_path in enumerate(files, 1):
                rel_path = file_path.relative_to(self.path)
                progress.update(scan_task, description=f"[cyan]Scanning: {rel_path.name}")
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    report = Agent(content)
                    
                    self.reports.append({
                        'file': str(rel_path),
                        'status': 'scanned',
                        'report': report
                    })
                    
                except Exception as e:
                    self.reports.append({
                        'file': str(rel_path),
                        'status': 'error',
                        'report': str(e)
                    })
                
                progress.update(scan_task, advance=1)
        
        return self.reports
    
    def display_results(self):
        if not self.reports:
            return
        
        console.print("\n[bold green]✓ Scan Complete![/bold green]\n")
        
        table = Table(title="Scan Summary", show_header=True, header_style="bold magenta")
        table.add_column("File", style="cyan", no_wrap=False)
        table.add_column("Status", justify="center")
        table.add_column("Issues", justify="center")
        
        issues_count = 0
        error_count = 0
        
        for report in self.reports:
            status = report['status']
            if status == 'error':
                status_display = "[red]ERROR[/red]"
                error_count += 1
            else:
                status_display = "[green]✓[/green]"
                if report['report'] and "no vulnerabilities" not in report['report'].lower():
                    issues_count += 1
            
            has_issues = "Yes" if report['report'] and "no vulnerabilities" not in report['report'].lower() else "No"
            table.add_row(report['file'], status_display, has_issues)
        
        console.print(table)
        
        console.print(f"\n[bold]Statistics:[/bold]")
        console.print(f"  Total files: {len(self.reports)}")
        console.print(f"  Files with issues: {issues_count}")
        console.print(f"  Scan errors: {error_count}")
        
        # Display detailed findings
        console.print("\n" + "="*60)
        console.print("[bold cyan]DETAILED FINDINGS[/bold cyan]")
        console.print("="*60)
        
        for report in self.reports:
            if report['status'] == 'error':
                console.print(f"\n[red]❌ {report['file']}[/red]")
                console.print(f"[dim]Error: {report['report']}[/dim]")
            elif report['report'] and "no vulnerabilities" not in report['report'].lower():
                console.print(f"\n[yellow]⚠️  {report['file']}[/yellow]")
                console.print(Panel(report['report'], border_style="yellow", padding=(1, 2)))
            else:
                console.print(f"\n[green]✅ {report['file']}[/green]")
                console.print("[dim]No issues found[/dim]")
    
    def save_report(self, output_file=None):
        if not output_file:
            output_file = f"{self.path.name}_security_report.json"
        
        summary = {
            'path': str(self.path),
            'total_files': len(self.reports),
            'detailed_reports': self.reports
        }
        
        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        console.print(f"\n[green]Report saved to:[/green] {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description='AntiShlop - Security vulnerability scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  antishlop .                    # Scan current directory
  antishlop /path/to/project     # Scan specific project
  antishlop . -o report.json     # Save report to specific file
        '''
    )
    
    parser.add_argument('path', help='Path to codebase to scan')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode, minimal output')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        console.print(f"[red]Error: Path '{args.path}' does not exist[/red]")
        sys.exit(1)
    
    if not os.path.isdir(args.path):
        console.print(f"[red]Error: '{args.path}' is not a directory[/red]")
        sys.exit(1)
    
    scanner = SecurityScanner(args.path)
    scanner.scan()
    
    if not args.quiet:
        scanner.display_results()
    
    if args.output:
        scanner.save_report(args.output)

if __name__ == "__main__":
    main()