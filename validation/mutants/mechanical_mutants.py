#!/usr/bin/env python3
"""Mechanical (AST) mutants: comparison flips, constant +/-1, True/False
flips, removed statements and removed raise statements.

enumerate_sites(source) lists every mutation site in a fixed order; mutate(source,
index) returns the source with exactly that one site changed (via ast.unparse).
The same visitor drives both, children are counted before their parent, so the
indices agree between the two modes. Nothing here touches the pinned files.

Sites skipped on purpose: docstrings, imports, the `if __name__` guard and, for
the PSBT modules, the body of `_validate_known_maps` (its path-based loader is
replaced by the harness, so mutating it would only measure the harness).
"""
import ast
import copy

CMP_FLIP = {
    ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.Lt: ast.LtE, ast.LtE: ast.Lt,
    ast.Gt: ast.GtE, ast.GtE: ast.Gt, ast.Is: ast.IsNot, ast.IsNot: ast.Is,
    ast.In: ast.NotIn, ast.NotIn: ast.In,
}
SKIP_FUNCS = {"_validate_known_maps"}


class _Walker(ast.NodeTransformer):
    def __init__(self, target=None):
        self.target = target
        self.n = 0
        self.sites = []
        self.stack = []
        self.applied = False

    def _site(self, kind, node, desc):
        idx = self.n
        self.n += 1
        if self.target is None:
            self.sites.append({"index": idx, "kind": kind, "line": getattr(node, "lineno", 0), "desc": desc})
            return False
        if idx == self.target:
            self.applied = True
            return True
        return False

    def _skipped(self):
        return any(f in SKIP_FUNCS for f in self.stack)

    def visit_FunctionDef(self, node):
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_If(self, node):
        # leave the __main__ guard alone
        if (isinstance(node.test, ast.Compare) and isinstance(node.test.left, ast.Name)
                and node.test.left.id == "__name__"):
            return node
        self.generic_visit(node)
        return node

    def visit_Compare(self, node):
        self.generic_visit(node)
        if self._skipped():
            return node
        for i, op in enumerate(node.ops):
            flip = CMP_FLIP.get(type(op))
            if flip is None:
                continue
            if self._site("compare", node, "%s: %s -> %s" % (ast.unparse(node)[:70], type(op).__name__, flip.__name__)):
                node.ops[i] = flip()
        return node

    def visit_Constant(self, node):
        if self._skipped():
            return node
        v = node.value
        if isinstance(v, bool):
            if self._site("bool", node, "%r -> %r" % (v, not v)):
                return ast.copy_location(ast.Constant(value=not v), node)
        elif isinstance(v, int):
            if self._site("const+1", node, "%d -> %d" % (v, v + 1)):
                return ast.copy_location(ast.Constant(value=v + 1), node)
            if self._site("const-1", node, "%d -> %d" % (v, v - 1)):
                return ast.copy_location(ast.Constant(value=v - 1), node)
        return node

    def _stmt(self, node, kind):
        self.generic_visit(node)
        if self._skipped():
            return node
        if self._site(kind, node, "removed: %s" % ast.unparse(node).split("\n")[0][:80]):
            return ast.copy_location(ast.Pass(), node)
        return node

    def visit_Raise(self, node):
        return self._stmt(node, "remove_raise")

    def visit_Assign(self, node):
        return self._stmt(node, "remove_stmt")

    def visit_AugAssign(self, node):
        return self._stmt(node, "remove_stmt")

    def visit_Delete(self, node):
        return self._stmt(node, "remove_stmt")

    def visit_Return(self, node):
        if node.value is None:
            return node
        return self._stmt(node, "remove_stmt")

    def visit_Expr(self, node):
        if isinstance(node.value, ast.Constant):  # docstring
            return node
        return self._stmt(node, "remove_stmt")


def _tree(source):
    return ast.parse(source)


def enumerate_sites(source):
    w = _Walker(None)
    w.visit(_tree(source))
    return w.sites


def mutate(source, index):
    w = _Walker(index)
    tree = w.visit(_tree(source))
    if not w.applied:
        raise ValueError("no such mutation site: %d" % index)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree) + "\n"


def roundtrip(source):
    """Control: the unmutated tree through ast.unparse."""
    return ast.unparse(_tree(source)) + "\n"


if __name__ == "__main__":
    import collections
    import pathlib
    import sys
    for p in sys.argv[1:]:
        sites = enumerate_sites(pathlib.Path(p).read_text())
        print(p, len(sites), dict(collections.Counter(s["kind"] for s in sites)))
