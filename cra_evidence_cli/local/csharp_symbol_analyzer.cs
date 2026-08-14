using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

internal static class CraCSharpSymbolAnalyzer
{
    private static readonly HashSet<string> IgnoredDirectories = new(StringComparer.Ordinal)
    {
        ".git", ".gradle", ".hg", ".svn", "bin", "build", "node_modules", "obj", "out", "target",
    };

    private static string Json(string value)
    {
        using var writer = new StringWriter();
        writer.Write('"');
        foreach (var ch in value)
        {
            switch (ch)
            {
                case '\\': writer.Write("\\\\"); break;
                case '"': writer.Write("\\\""); break;
                case '\b': writer.Write("\\b"); break;
                case '\f': writer.Write("\\f"); break;
                case '\n': writer.Write("\\n"); break;
                case '\r': writer.Write("\\r"); break;
                case '\t': writer.Write("\\t"); break;
                default:
                    if (ch < 0x20) writer.Write($"\\u{(int)ch:x4}");
                    else writer.Write(ch);
                    break;
            }
        }
        writer.Write('"');
        return writer.ToString();
    }

    private static string Token(IAssemblySymbol assembly) => string.Concat(
        assembly.Identity.PublicKeyToken.Select(value => value.ToString("x2")));

    private static IEnumerable<string> SourcePaths(string root) => Directory
        .EnumerateFiles(root, "*.cs", SearchOption.AllDirectories)
        .Where(path => !Path.GetRelativePath(root, path).Split(Path.DirectorySeparatorChar)
            .SkipLast(1).Any(IgnoredDirectories.Contains))
        .OrderBy(path => path, StringComparer.Ordinal);

    public static int Main(string[] args)
    {
        if (args.Length != 2)
        {
            Console.Error.WriteLine("a framework reference directory and source root are required");
            return 2;
        }
        var referenceRoot = Path.GetFullPath(args[0]);
        var sourceRoot = Path.GetFullPath(args[1]);
        if (!Directory.Exists(referenceRoot) || !Directory.Exists(sourceRoot))
        {
            Console.Error.WriteLine("the framework reference directory and source root must exist");
            return 2;
        }
        var paths = SourcePaths(sourceRoot).ToArray();
        if (paths.Length == 0)
        {
            Console.Error.WriteLine("no C# source files were found");
            return 2;
        }
        var parseOptions = new CSharpParseOptions(LanguageVersion.CSharp12);
        var trees = paths.Select(path => CSharpSyntaxTree.ParseText(
            File.ReadAllText(path), parseOptions, path)).ToArray();
        var references = Directory.EnumerateFiles(referenceRoot, "*.dll")
            .OrderBy(path => path, StringComparer.Ordinal)
            .Select(path => MetadataReference.CreateFromFile(path));
        var compilation = CSharpCompilation.Create(
            "CraEvidenceAnalysis", trees, references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        var errors = compilation.GetDiagnostics()
            .Where(item => item.Severity == DiagnosticSeverity.Error).ToArray();
        if (errors.Length != 0)
        {
            foreach (var error in errors) Console.Error.WriteLine(error);
            return 3;
        }
        var roslyn = typeof(CSharpCompilation).Assembly.GetName().Version?.ToString() ?? "unknown";
        Console.WriteLine($"{{\"schema\":\"craevidence.csharp_symbols.v1\","
            + $"\"runtime_version\":{Json(Environment.Version.ToString())},"
            + $"\"roslyn_version\":{Json(roslyn)}}}");
        foreach (var tree in trees)
        {
            var model = compilation.GetSemanticModel(tree, ignoreAccessibility: false);
            foreach (var assignment in tree.GetRoot().DescendantNodes().OfType<AssignmentExpressionSyntax>())
            {
                var left = model.GetSymbolInfo(assignment.Left).Symbol as IPropertySymbol;
                var right = model.GetSymbolInfo(assignment.Right).Symbol as IPropertySymbol;
                if (left is null || right is null
                    || left.Name != "ServerCertificateCustomValidationCallback"
                    || right.Name != "DangerousAcceptAnyServerCertificateValidator")
                {
                    continue;
                }
                var span = tree.GetLineSpan(assignment.Span);
                var relative = Path.GetRelativePath(sourceRoot, tree.FilePath).Replace('\\', '/');
                Console.WriteLine("{"
                    + $"\"path\":{Json(relative)},"
                    + $"\"start_line\":{span.StartLinePosition.Line + 1},"
                    + $"\"start_column\":{span.StartLinePosition.Character + 1},"
                    + $"\"end_line\":{span.EndLinePosition.Line + 1},"
                    + $"\"end_column\":{span.EndLinePosition.Character + 1},"
                    + $"\"left_property\":{Json(left.Name)},"
                    + $"\"left_type\":{Json(left.ContainingType.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat))},"
                    + $"\"left_assembly\":{Json(left.ContainingAssembly.Identity.Name)},"
                    + $"\"left_assembly_version\":{Json(left.ContainingAssembly.Identity.Version.ToString())},"
                    + $"\"left_public_key_token\":{Json(Token(left.ContainingAssembly))},"
                    + $"\"right_property\":{Json(right.Name)},"
                    + $"\"right_type\":{Json(right.ContainingType.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat))},"
                    + $"\"right_assembly\":{Json(right.ContainingAssembly.Identity.Name)},"
                    + $"\"right_assembly_version\":{Json(right.ContainingAssembly.Identity.Version.ToString())},"
                    + $"\"right_public_key_token\":{Json(Token(right.ContainingAssembly))}"
                    + "}");
            }
        }
        return 0;
    }
}
