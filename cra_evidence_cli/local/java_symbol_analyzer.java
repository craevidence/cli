import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.TreePath;
import com.sun.source.util.TreePathScanner;
import com.sun.source.util.Trees;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import javax.lang.model.element.Element;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.ModuleElement;
import javax.lang.model.element.TypeElement;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.StandardLocation;
import javax.tools.ToolProvider;

final class CraJavaSymbolAnalyzer {
    private static final Set<String> IGNORED_DIRECTORIES = Set.of(
            ".git", ".gradle", ".hg", ".svn", "bin", "build", "node_modules", "obj", "out", "target");

    private static boolean isSelectedSource(Path root, Path path) {
        Path relative = root.relativize(path);
        for (Path part : relative) {
            if (IGNORED_DIRECTORIES.contains(part.toString())) {
                return false;
            }
        }
        return path.getFileName().toString().endsWith(".java");
    }

    private static String json(String value) {
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '\\' -> out.append("\\\\");
                case '"' -> out.append("\\\"");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (ch < 0x20) {
                        out.append(String.format("\\u%04x", (int) ch));
                    } else {
                        out.append(ch);
                    }
                }
            }
        }
        return out.append('"').toString();
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("one source root is required");
            System.exit(2);
        }
        Path root = Path.of(args[0]).toRealPath();
        if (!Files.isDirectory(root)) {
            System.err.println("the source root must be a directory");
            System.exit(2);
        }
        List<Path> paths;
        try (var stream = Files.walk(root)) {
            paths = stream.filter(Files::isRegularFile)
                    .filter(path -> isSelectedSource(root, path))
                    .sorted(Comparator.comparing(Path::toString))
                    .toList();
        }
        if (paths.isEmpty()) {
            System.err.println("no Java source files were found");
            System.exit(2);
        }
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            System.err.println("the JDK compiler module is unavailable");
            System.exit(2);
        }
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        try (StandardJavaFileManager files = compiler.getStandardFileManager(diagnostics, null, null)) {
            files.setLocationFromPaths(StandardLocation.CLASS_PATH, List.of());
            files.setLocationFromPaths(StandardLocation.SOURCE_PATH, List.of());
            Path output = Files.createTempDirectory("cra-java-symbols-");
            files.setLocationFromPaths(StandardLocation.CLASS_OUTPUT, List.of(output));
            Iterable<? extends JavaFileObject> sources = files.getJavaFileObjectsFromPaths(paths);
            String sourceVersion = Integer.toString(Runtime.version().feature());
            JavacTask task = (JavacTask) compiler.getTask(
                    null,
                    files,
                    diagnostics,
                    List.of("-source", sourceVersion, "-proc:none", "-implicit:none", "-Xlint:none"),
                    null,
                    sources);
            Iterable<? extends CompilationUnitTree> units = task.parse();
            task.analyze();
            boolean failed = diagnostics.getDiagnostics().stream()
                    .anyMatch(item -> item.getKind() == Diagnostic.Kind.ERROR);
            if (failed) {
                for (Diagnostic<? extends JavaFileObject> item : diagnostics.getDiagnostics()) {
                    if (item.getKind() == Diagnostic.Kind.ERROR) {
                        String source = item.getSource() == null ? "<compiler>" : item.getSource().getName();
                        System.err.printf("%s:%d:%d: %s%n", source, item.getLineNumber(),
                                item.getColumnNumber(), item.getMessage(null));
                    }
                }
                System.exit(3);
            }
            System.out.printf("{\"schema\":\"craevidence.java_symbols.v1\",\"java_version\":%s}%n",
                    json(Runtime.version().toString()));
            Trees trees = Trees.instance(task);
            SourcePositions positions = trees.getSourcePositions();
            for (CompilationUnitTree unit : units) {
                new TreePathScanner<Void, Void>() {
                    @Override
                    public Void visitMethodInvocation(MethodInvocationTree invocation, Void unused) {
                        TreePath selectPath = new TreePath(getCurrentPath(), invocation.getMethodSelect());
                        Element element = trees.getElement(selectPath);
                        if (!(element instanceof ExecutableElement method)
                                || !(method.getEnclosingElement() instanceof TypeElement owner)
                                || !method.getSimpleName().contentEquals("getInstance")) {
                            return super.visitMethodInvocation(invocation, unused);
                        }
                        long start = positions.getStartPosition(unit, invocation.getMethodSelect());
                        long end = positions.getEndPosition(unit, invocation.getMethodSelect());
                        if (start < 0 || end < start) {
                            return super.visitMethodInvocation(invocation, unused);
                        }
                        ModuleElement module = task.getElements().getModuleOf(owner);
                        String parameter = method.getParameters().isEmpty()
                                ? ""
                                : task.getTypes().erasure(method.getParameters().get(0).asType()).toString();
                        Path path = Path.of(unit.getSourceFile().toUri()).toAbsolutePath().normalize();
                        Path relative = root.relativize(path);
                        long startLine = unit.getLineMap().getLineNumber(start);
                        long startColumn = unit.getLineMap().getColumnNumber(start);
                        long endLine = unit.getLineMap().getLineNumber(end);
                        long endColumn = unit.getLineMap().getColumnNumber(end);
                        System.out.printf(
                                "{\"path\":%s,\"start_line\":%d,\"start_column\":%d,"
                                        + "\"end_line\":%d,\"end_column\":%d,\"module\":%s,"
                                        + "\"package\":%s,\"qualified_name\":%s,\"binary_name\":%s,"
                                        + "\"nesting\":%s,\"method\":%s,\"first_parameter\":%s}%n",
                                json(relative.toString().replace('\\', '/')),
                                startLine,
                                startColumn,
                                endLine,
                                endColumn,
                                json(module == null ? "" : module.getQualifiedName().toString()),
                                json(task.getElements().getPackageOf(owner).getQualifiedName().toString()),
                                json(owner.getQualifiedName().toString()),
                                json(task.getElements().getBinaryName(owner).toString()),
                                json(owner.getNestingKind().toString()),
                                json(method.getSimpleName().toString()),
                                json(parameter));
                        return super.visitMethodInvocation(invocation, unused);
                    }
                }.scan(unit, null);
            }
        }
    }
}
