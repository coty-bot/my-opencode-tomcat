#!/usr/bin/env python3
"""astnav — tree-sitter-based Java code navigation.

Follows code paths with syntax-aware precision (unlike grep): it ignores comments and
string literals, distinguishes declarations from invocations from references, and can
match specific AST node types. It is SYNTACTIC, not semantic: matching is by name/shape,
so it does not resolve overloads or prove type identity. For true call-hierarchy /
type-based resolution you would need a Java LSP (e.g. jdtls).

Requires:  pip install tree-sitter tree-sitter-java
"""
import argparse
import os
import sys

SKIP_DIRS = {".git", "output", "build", "target", "node_modules", "bin", ".idea"}


def die(msg):
    sys.stderr.write("astnav: %s\n" % msg)
    sys.exit(2)


def get_parser():
    try:
        import tree_sitter_java as tsj
        import tree_sitter as ts
    except ImportError as e:
        die("missing dependency (%s). Run: pip install tree-sitter tree-sitter-java" % e)
    return ts.Parser(ts.Language(tsj.language()))


def java_files(root):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in sorted(filenames):
            if fn.endswith(".java"):
                yield os.path.join(dirpath, fn)


def ntext(node):
    return node.text.decode("utf-8", "replace") if node is not None else ""


def clip(s, n=140):
    s = " ".join(s.split())  # collapse whitespace/newlines
    return s if len(s) <= n else s[: n - 3] + "..."


def same_node(a, b):
    """tree-sitter >=0.23 does not intern Node objects, so compare by position+type."""
    if a is None or b is None:
        return False
    return a.type == b.type and a.start_point == b.start_point and a.end_point == b.end_point


def rel(path, root):
    try:
        r = os.path.relpath(path, root)
    except ValueError:
        return path
    return os.path.basename(path) if r == "." else r


# --------------------------------------------------------------------------- symbols

DECL_KIND = {
    "class_declaration": "class",
    "interface_declaration": "interface",
    "enum_declaration": "enum",
    "record_declaration": "record",
}


def cmd_symbols(args):
    parser = get_parser()
    for path in java_files(args.file):
        tree, _ = parse(parser, path)
        out = []

        def walk(node, depth):
            ind = "  " * depth
            t = node.type
            if t in DECL_KIND:
                nm = ntext(node.child_by_field_name("name"))
                out.append("%s%s %s  (L%d)" % (ind, DECL_KIND[t], nm, node.start_point[0] + 1))
            elif t == "method_declaration":
                nm = ntext(node.child_by_field_name("name"))
                params = ntext(node.child_by_field_name("parameters"))
                out.append("%sL%d method %s%s" % (ind, node.start_point[0] + 1, nm, clip(params, 90)))
            elif t == "field_declaration":
                # one line per declarator name
                for c in node.children:
                    if c.type == "variable_declarator":
                        nm = ntext(c.child_by_field_name("name"))
                        out.append("%sL%d field %s" % (ind, c.start_point[0] + 1, nm))
            for c in node.children:
                walk(c, depth + (1 if t in DECL_KIND else 0))

        walk(tree.root_node, 0)
        print("== %s ==" % rel(path, args.file))
        print("\n".join(out))


def parse(parser, path):
    with open(path, "rb") as f:
        src = f.read()
    return parser.parse(src), src


# --------------------------------------------------------------------------- generic walk

def iter_nodes(root, types):
    stack = [root]
    while stack:
        n = stack.pop()
        if n.type in types:
            yield n
        for c in reversed(n.children):
            stack.append(c)


def last_name(expr):
    """Return the trailing identifier of an expression (identifier or field_access)."""
    if expr is None:
        return ""
    if expr.type == "identifier":
        return ntext(expr)
    if expr.type == "field_access":
        nm = expr.child_by_field_name("name")
        return ntext(nm)
    return ""


def cmd_defs(args):
    parser = get_parser()
    hits = 0
    for path in java_files(args.root):
        tree, _ = parse(parser, path)
        r = rel(path, args.root)
        for node in iter_nodes(tree.root_node, {
                "method_declaration", "field_declaration", "class_declaration",
                "interface_declaration", "enum_declaration", "local_variable_declaration"}):
            if node.type in ("local_variable_declaration", "field_declaration"):
                names = [ntext(c.child_by_field_name("name")) for c in node.children
                         if c.type == "variable_declarator"]
            else:
                nm = ntext(node.child_by_field_name("name"))
                names = [nm] if nm else []
            for name in names:
                if name == args.name:
                    kind = {"method_declaration": "method", "field_declaration": "field",
                            "local_variable_declaration": "local"}.get(DECL_KIND.get(node.type, ""), node.type)
                    print("%s:%d %s %s" % (r, node.start_point[0] + 1, kind, clip(ntext(node), 120)))
                    hits += 1
    sys.stderr.write("astnav: %d definition(s) of '%s'\n" % (hits, args.name))


def cmd_calls(args):
    parser = get_parser()
    hits = 0
    for path in java_files(args.root):
        tree, _ = parse(parser, path)
        r = rel(path, args.root)
        for inv in iter_nodes(tree.root_node, {"method_invocation"}):
            nm = ntext(inv.child_by_field_name("name"))
            if nm != args.name:
                continue
            recv = ntext(inv.child_by_field_name("object"))
            prefix = (recv + ".") if recv else ""
            print("%s:%d %s%s(%s)" % (r, inv.start_point[0] + 1, prefix, nm, clip(ntext(inv), 120)))
            hits += 1
    sys.stderr.write("astnav: %d call site(s) of '%s'\n" % (hits, args.name))


def cmd_writes(args):
    parser = get_parser()
    hits = 0
    for path in java_files(args.root):
        tree, _ = parse(parser, path)
        r = rel(path, args.root)
        for node in iter_nodes(tree.root_node, {"assignment_expression", "augmented_assignment_expression"}):
            lhs = node.child_by_field_name("left")
            if last_name(lhs) == args.field:
                print("%s:%d %s" % (r, node.start_point[0] + 1, clip(ntext(node), 140)))
                hits += 1
    sys.stderr.write("astnav: %d write(s) to '%s'\n" % (hits, args.field))


def cmd_refs(args):
    parser = get_parser()
    hits = 0
    for path in java_files(args.root):
        tree, _ = parse(parser, path)
        r = rel(path, args.root)
        for node in iter_nodes(tree.root_node, {"identifier"}):
            if ntext(node) != args.name:
                continue
            parent = node.parent
            # skip identifiers that ARE a declaration's own name (definitions, not references)
            if parent is not None:
                if parent.type.endswith("_declaration") and same_node(parent.child_by_field_name("name"), node):
                    continue
                if parent.type == "variable_declarator" and same_node(parent.child_by_field_name("name"), node):
                    continue
            ctx = node
            for _ in range(3):
                if ctx.parent is None:
                    break
                ctx = ctx.parent
                if ctx.type in ("expression_statement", "return_statement", "method_invocation",
                                "assignment_expression", "if_statement", "for_statement"):
                    break
            print("%s:%d %s" % (r, node.start_point[0] + 1, clip(ntext(ctx), 140)))
            hits += 1
    sys.stderr.write("astnav: %d reference(s) to '%s'\n" % (hits, args.name))


def cmd_query(args):
    parser = get_parser()
    import tree_sitter_java as tsj
    import tree_sitter as ts
    lang = ts.Language(tsj.language())
    try:
        query = ts.Query(lang, args.query)
    except Exception as e:
        die("bad query: %s" % e)
    cursor = ts.QueryCursor(query)
    hits = 0
    for path in java_files(args.root):
        tree, _ = parse(parser, path)
        r = rel(path, args.root)
        # tree-sitter >=0.23: captures() -> {capture_name_str: [Node, ...]}
        captures = cursor.captures(tree.root_node)
        for capname, nodes in captures.items():
            for node in nodes:
                print("%s:%d %s %s" % (r, node.start_point[0] + 1, capname, clip(ntext(node), 120)))
                hits += 1
    sys.stderr.write("astnav: %d capture(s)\n" % hits)


def main():
    ap = argparse.ArgumentParser(description="tree-sitter Java code navigation")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("symbols", help="outline classes/methods/fields of a file")
    p.add_argument("file")
    p.set_defaults(fn=cmd_symbols)

    for name, fn, helptxt, dest in [
        ("defs", cmd_defs, "find declarations named NAME", "name"),
        ("calls", cmd_calls, "find call sites invoking NAME", "name"),
        ("writes", cmd_writes, "find assignments to field FIELD", "field"),
        ("refs", cmd_refs, "find references to identifier NAME", "name"),
    ]:
        p = sub.add_parser(name, help=helptxt)
        p.add_argument(dest, help="symbol name" if dest == "name" else "field name")
        p.add_argument("--root", default=".", help="file or directory to search (default .)")
        p.set_defaults(fn=fn)

    p = sub.add_parser("query", help="run a raw tree-sitter query string")
    p.add_argument("query")
    p.add_argument("--root", default=".")
    p.set_defaults(fn=cmd_query)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
