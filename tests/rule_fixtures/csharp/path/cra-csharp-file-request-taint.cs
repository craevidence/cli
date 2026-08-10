using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.IO;

class FileHandler {
    string RequestedPath(HttpRequest request) {
        return request.Query["path"];
    }

    string BadAcrossHelper(HttpRequest request) {
        string path = RequestedPath(request);
        // ruleid: cra-csharp-file-request-taint
        return File.ReadAllText(path);
    }

    byte[] Bad(HttpRequest request) {
        string path = request.Form["path"];
        // ruleid: cra-csharp-file-request-taint
        return File.ReadAllBytes(path);
    }

    string BadFromBody([FromBody] string path) {
        // ruleid: cra-csharp-file-request-taint
        return File.ReadAllText(path);
    }

    void BadWrite(HttpRequest request) {
        string path = request.Query["path"];
        // ruleid: cra-csharp-file-request-taint
        File.WriteAllText(path, "content");
    }

    string Good() {
        // ok: cra-csharp-file-request-taint
        return File.ReadAllText("/srv/app/config.json");
    }

    string GoodCanonicalContainment(HttpRequest request) {
        string basePath = Path.GetFullPath("/srv/app/documents");
        string path = Path.GetFullPath(
            Path.Combine(basePath, request.Query["path"])
        );
        if (!path.StartsWith(basePath + Path.DirectorySeparatorChar)) {
            return "invalid path";
        }
        // ok: cra-csharp-file-request-taint
        return File.ReadAllText(path);
    }

    string BadLateContainment(HttpRequest request) {
        string basePath = Path.GetFullPath("/srv/app/documents");
        string path = Path.GetFullPath(
            Path.Combine(basePath, request.Query["path"])
        );
        // ruleid: cra-csharp-file-request-taint
        string content = File.ReadAllText(path);
        if (!path.StartsWith(basePath + Path.DirectorySeparatorChar)) {
            return "invalid path";
        }
        return content;
    }
}
