import com.sun.source.tree.*;
import com.sun.source.util.JavacTask;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.TreePath;
import com.sun.source.util.TreePathScanner;
import com.sun.source.util.Trees;
import javax.lang.model.element.Element;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.VariableElement;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.TypeMirror;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.StandardLocation;
import javax.tools.ToolProvider;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * SemIndex — build a semantic (type-resolved) call/field-write index of a Java source tree.
 *
 * Compiles the whole source set with full attribution via javac's compiler API, then walks the
 * attributed AST to emit resolved edges: which method each invocation actually resolves to
 * (declaring class FQN + parameter signature), and which field each assignment writes to
 * (declaring class FQN). This disambiguates overloads and same-named symbols that a purely
 * syntactic tool cannot.
 *
 * Usage: java -Xmx4g SemIndex <srcRoot> <classpath-or-empty> <outTsvPath>
 * Output TSV columns: kind \t file \t line \t name \t decl_fqn \t signature \t receiver_type \t enclosing_method
 */
public class SemIndex {

    public static void main(String[] args) throws Exception {
        String srcRoot = args[0];
        String cpArg   = (args.length > 1 && !args[1].isEmpty()) ? args[1] : null;
        String outPath = args[2];

        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) { System.err.println("SemIndex: no system JavaCompiler"); return; }
        DiagnosticCollector<JavaFileObject> diags = new DiagnosticCollector<>();
        StandardJavaFileManager fm =
                compiler.getStandardFileManager(diags, null, StandardCharsets.UTF_8);

        if (cpArg != null) {
            List<File> cpFiles = new ArrayList<>();
            for (String p : cpArg.split(":")) if (!p.isEmpty()) cpFiles.add(new File(p));
            fm.setLocation(StandardLocation.CLASS_PATH, cpFiles);
        }

        List<File> sources = new ArrayList<>();
        collectJava(srcRoot, sources);
        Iterable<? extends JavaFileObject> units = fm.getJavaFileObjectsFromFiles(sources);

        List<String> options = Arrays.asList("-proc:none", "-nowarn");
        JavacTask task = (JavacTask) compiler.getTask(null, fm, diags, options, null, units);
        long t0 = System.currentTimeMillis();
        List<CompilationUnitTree> roots = new ArrayList<>();
        for (CompilationUnitTree cu : task.parse()) roots.add(cu); // parse all units
        task.analyze();                                            // enter + attribute (best effort)
        Trees trees = Trees.instance(task);

        try (PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(outPath)))) {
            for (CompilationUnitTree cu : roots) {
                String file = cu.getSourceFile().toUri().getPath();
                EdgeScanner sc = new EdgeScanner(trees, file, cu.getLineMap(), out);
                sc.scan(cu, null);
            }
        }

        long ms = System.currentTimeMillis() - t0;
        System.err.println("SemIndex: units=" + roots.size()
                + " diags=" + diags.getDiagnostics().size()
                + " calls=" + EdgeScanner.CALLS
                + " field_writes=" + EdgeScanner.WRITES
                + " ms=" + ms);
    }

    static void collectJava(String root, List<File> out) throws Exception {
        Path p = Paths.get(root);
        Files.walk(p).filter(Files::isRegularFile)
              .filter(x -> x.toString().endsWith(".java"))
              .forEach(x -> out.add(x.toFile()));
    }

    static class EdgeScanner extends TreePathScanner<Void, Void> {
        static int CALLS = 0, WRITES = 0;
        final Trees trees; final CompilationUnitTree cu; final String file;
        final SourcePositions sp; final PrintWriter out;
        String cur = ""; // enclosing method "FQN.name"

        EdgeScanner(Trees t, CompilationUnitTree c, String f, PrintWriter o) {
            trees = t; cu = c; file = f; sp = t.getSourcePositions(); out = o;
        }

        int line(Tree n) { return (int) sp.getLineNumber(cu, sp.getStartPosition(cu, n)); }

        // Trees API resolves via a TreePath rooted at the compilation unit, not a bare Tree.
        Element el(Tree n) { TreePath p = trees.getPath(cu, n); return p == null ? null : trees.getElement(p); }
        TypeMirror tm(Tree n) { TreePath p = trees.getPath(cu, n); return p == null ? null : trees.getTypeMirror(p); }

        @Override public Void visitMethod(MethodTree node, Void d) {
            String prev = cur;
            Element el = el(node);
            if (el instanceof ExecutableElement ee && ee.getEnclosingElement() instanceof TypeElement te)
                cur = te.getQualifiedName() + "." + ee.getSimpleName();
            else cur = "?";
            Void r = super.visitMethod(node, d);
            cur = prev;
            return r;
        }

        @Override public Void visitMethodInvocation(MethodInvocationTree node, Void d) {
            Element el = el(node);
            if (el instanceof ExecutableElement ee && ee.getEnclosingElement() instanceof TypeElement te) {
                String recv = "";
                ExpressionTree r = node.getMethodSelect().getExpression();
                if (r != null) recv = shortName(tm(r));
                out.println("call\t" + file + "\t" + line(node) + "\t" + ee.getSimpleName()
                        + "\t" + te.getQualifiedName() + "\t" + sig(ee) + "\t" + recv + "\t" + cur);
                CALLS++;
            }
            return super.visitMethodInvocation(node, d);
        }

        @Override public Void visitAssignment(AssignmentTree node, Void d) {
            recordWrite(node.getVariable());
            return super.visitAssignment(node, d);
        }

        @Override public Void visitCompoundAssignment(CompoundAssignmentTree node, Void d) {
            recordWrite(node.getVariable());
            return super.visitCompoundAssignment(node, d);
        }

        void recordWrite(ExpressionTree lhs) {
            Element el = el(lhs);
            if (el instanceof VariableElement ve && ve.getEnclosingElement() instanceof TypeElement te) {
                String recv = "";
                if (lhs instanceof MemberSelectTree mst && mst.getExpression() != null)
                    recv = shortName(tm(mst.getExpression()));
                out.println("field_write\t" + file + "\t" + line(lhs) + "\t" + ve.getSimpleName()
                        + "\t" + te.getQualifiedName() + "\t\t" + recv + "\t" + cur);
                WRITES++;
            }
        }

        String sig(ExecutableElement ee) {
            StringBuilder sb = new StringBuilder("(");
            boolean first = true;
            for (VariableElement p : ee.getParameters()) {
                if (!first) sb.append(",");
                sb.append(shortName(p.asType()));
                first = false;
            }
            return sb.append(")").toString();
        }

        String shortName(TypeMirror tm) {
            if (tm == null) return "";
            String s = tm.toString();
            int b = s.indexOf('<'); if (b >= 0) s = s.substring(0, b); // drop generics
            int d = s.lastIndexOf('.');
            return d >= 0 ? s.substring(d + 1) : s;
        }
    }
}
