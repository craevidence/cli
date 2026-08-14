using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.IO;
using System.Web;

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

    string ReportedCanonicalContainment(HttpRequest request) {
        string basePath = Path.GetFullPath("/srv/app/documents");
        string path = Path.GetFullPath(
            Path.Combine(basePath, request.Query["path"])
        );
        if (!path.StartsWith(basePath + Path.DirectorySeparatorChar)) {
            return "invalid path";
        }
        // ruleid: cra-csharp-file-request-taint
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

    string BadStreamReaderFromParamsGet(HttpRequest req) {
        string name = req.Params.Get("doc");
        // ruleid: cra-csharp-file-request-taint
        using (var reader = new StreamReader("/srv/app/documents/" + name)) {
            return reader.ReadToEnd();
        }
    }

    void BadStreamWriterFromQueryString(HttpRequest req, string body) {
        string name = req.QueryString["doc"];
        // ruleid: cra-csharp-file-request-taint
        using (var writer = new StreamWriter("/srv/app/documents/" + name)) {
            writer.Write(body);
        }
    }

    void BadFileStreamFromCookieCollection(HttpRequest req) {
        HttpCookieCollection cookies = req.Cookies;
        // ruleid: cra-csharp-file-request-taint
        var stream = new FileStream("/srv/app/documents/" + cookies[0].Value, FileMode.Open);
        stream.Dispose();
    }

    string GoodAllowlistedName(HttpRequest req) {
        string requested = req.Params.Get("doc");
        string chosen = requested == "terms" ? "terms.txt" : "privacy.txt";
        // ok: cra-csharp-file-request-taint
        using (var reader = new StreamReader(Path.Combine("/srv/app/documents", chosen))) {
            return reader.ReadToEnd();
        }
    }
}
