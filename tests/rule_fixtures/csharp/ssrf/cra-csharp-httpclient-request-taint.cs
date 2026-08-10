using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

class FetchHandler {
    string RequestedUrl(HttpRequest request) {
        return request.Query["url"];
    }

    async Task<string> BadAcrossHelper(HttpRequest request, HttpClient client) {
        string target = RequestedUrl(request);
        // ruleid: cra-csharp-httpclient-request-taint
        return await client.GetStringAsync(target);
    }

    async Task<HttpResponseMessage> Bad(HttpRequest request, HttpClient client) {
        string target = request.Form["target"];
        // ruleid: cra-csharp-httpclient-request-taint
        return await client.GetAsync(target);
    }

    WebRequest BadFromQuery([FromQuery] string target) {
        // ruleid: cra-csharp-httpclient-request-taint
        return WebRequest.Create(target);
    }

    async Task<HttpResponseMessage> Good(HttpClient client) {
        // ok: cra-csharp-httpclient-request-taint
        return await client.GetAsync("https://updates.example.com/manifest.json");
    }
}
