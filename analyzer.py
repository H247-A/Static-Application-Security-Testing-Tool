"""
analyzer.py — AST visitor that applies all rules to a parsed Python file
"""

import ast
from typing import List
from rules import (
    Finding,
    CALL_RULES,
    check_hardcoded_secret,
    check_dangerous_import,
)


class SecurityVisitor(ast.NodeVisitor):
    def __init__(self, filename: str):
        self.filename = filename
        self.findings: List[Finding] = []

    def _add(self, new: List[Finding]):
        self.findings.extend(new)

    def visit_Call(self, node: ast.Call):
        for rule_fn in CALL_RULES:
            self._add(rule_fn(node, self.filename))
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        self._add(check_hardcoded_secret(node, self.filename))
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import):
        self._add(check_dangerous_import(node, self.filename))
        self.generic_visit(node)


def analyze_source(source: str, filename: str) -> List[Finding]:
    """Parse Python source and return all findings."""
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as e:
        print(f"  [!] Syntax error in {filename}: {e}")
        return []
    visitor = SecurityVisitor(filename=filename)
    visitor.visit(tree)
    return visitor.findings
