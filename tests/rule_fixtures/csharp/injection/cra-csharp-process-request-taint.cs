using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

class ProcessHandler {
    string RequestedCommand(HttpRequest request) {
        return request.Query["command"];
    }

    void BadAcrossHelper(HttpRequest request) {
        string command = RequestedCommand(request);
        // ruleid: cra-csharp-process-request-taint
        Process.Start("cmd.exe", "/c " + command);
    }

    void Bad(HttpRequest request) {
        string command = request.Form["command"];
        // ruleid: cra-csharp-process-request-taint
        var start = new ProcessStartInfo("/bin/sh", "-c " + command);
    }

    void BadFromQuery([FromQuery] string command) {
        // ruleid: cra-csharp-process-request-taint
        Process.Start("cmd.exe", "/c " + command);
    }

    void BadSingleArgument(HttpRequest request) {
        string command = request.Query["command"];
        // ruleid: cra-csharp-process-request-taint
        Process.Start(command);
    }

    void BadInitializer(HttpRequest request) {
        string arguments = request.Form["arguments"];
        // ruleid: cra-csharp-process-request-taint
        var start = new ProcessStartInfo { FileName = "cmd.exe", Arguments = arguments };
    }

    void Good(HttpRequest request) {
        string value = request.Query["value"];
        var start = new ProcessStartInfo("/usr/bin/lookup");
        start.ArgumentList.Add(value);
        // ok: cra-csharp-process-request-taint
        Process.Start(start);
    }

    void GoodArgumentListInitializer(HttpRequest request) {
        string value = request.Query["value"];
        var start = new ProcessStartInfo {
            FileName = "/usr/bin/lookup",
            ArgumentList = { value }
        };
        // ok: cra-csharp-process-request-taint
        Process.Start(start);
    }

    void BadShellArgumentListInitializer(HttpRequest request) {
        string value = request.Query["value"];
        var start = new ProcessStartInfo {
            FileName = "/bin/sh",
            ArgumentList = { "-c", value }
        };
        // ruleid: cra-csharp-process-request-taint
        Process.Start(start);
    }
}
