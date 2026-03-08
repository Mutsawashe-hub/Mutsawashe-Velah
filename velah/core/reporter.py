"""
Report generation for vulnerability scan results
"""
import json
import csv
from datetime import datetime
from typing import List, Dict, Any, Optional
from jinja2 import Template
import logging

logger = logging.getLogger(__name__)

class Report:
    """Generate vulnerability reports in multiple formats"""
    
    def __init__(self, vulnerabilities: List[Dict[str, Any]], config=None):
        self.vulnerabilities = vulnerabilities
        self.config = config
        self.generated_at = datetime.now()
    
    def generate(self, output_format: str = "json", output_file: Optional[str] = None) -> str:
        """
        Generate report in specified format
        
        Args:
            output_format: Format type (json, html, csv)
            output_file: Optional output file path
        
        Returns:
            Report content as string
        """
        if output_format.lower() == "json":
            report = self._generate_json()
        elif output_format.lower() == "html":
            report = self._generate_html()
        elif output_format.lower() == "csv":
            report = self._generate_csv()
        else:
            raise ValueError(f"Unsupported format: {output_format}")
        
        if output_file:
            self._write_to_file(report, output_file)
            logger.info(f"Report written to {output_file}")
        
        return report
    
    def _generate_json(self) -> str:
        """Generate JSON report"""
        data = {
            "generated_at": self.generated_at.isoformat(),
            "total_vulnerabilities": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities
        }
        return json.dumps(data, indent=2)
    
    def _generate_html(self) -> str:
        """Generate HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vulnerability Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1 { color: #333; }
                table { width: 100%; border-collapse: collapse; }
                th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background-color: #4CAF50; color: white; }
                tr:hover { background-color: #f5f5f5; }
                .critical { color: #d32f2f; font-weight: bold; }
                .high { color: #f57c00; font-weight: bold; }
                .medium { color: #fbc02d; }
                .low { color: #388e3c; }
            </style>
        </head>
        <body>
            <h1>Vulnerability Scan Report</h1>
            <p>Generated: {{ generated_at }}</p>
            <p>Total Vulnerabilities: {{ total_vulnerabilities }}</p>
            <table>
                <tr>
                    <th>Target</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Description</th>
                </tr>
                {% for vuln in vulnerabilities %}
                <tr>
                    <td>{{ vuln.target }}</td>
                    <td>{{ vuln.type }}</td>
                    <td class="{{ vuln.severity|lower }}">{{ vuln.severity }}</td>
                    <td>{{ vuln.description }}</td>
                </tr>
                {% endfor %}
            </table>
        </body>
        </html>
        """
        
        template = Template(html_template)
        return template.render(
            generated_at=self.generated_at.isoformat(),
            total_vulnerabilities=len(self.vulnerabilities),
            vulnerabilities=self.vulnerabilities
        )
    
    def _generate_csv(self) -> str:
        """Generate CSV report"""
        output = []
        
        if self.vulnerabilities:
            fieldnames = self.vulnerabilities[0].keys()
            output.append(",".join(fieldnames))
            
            for vuln in self.vulnerabilities:
                row = [str(vuln.get(field, "")) for field in fieldnames]
                output.append(",".join(row))
        
        return "\n".join(output)
    
    def _write_to_file(self, content: str, filepath: str):
        """Write report to file"""
        try:
            with open(filepath, 'w') as f:
                f.write(content)
        except IOError as e:
            logger.error(f"Failed to write report to {filepath}: {str(e)}")