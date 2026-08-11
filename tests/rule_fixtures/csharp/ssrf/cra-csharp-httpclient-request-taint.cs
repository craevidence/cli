using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;

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

    async Task<string> BadParamsGet(HttpRequest req, HttpClient client) {
        string target = req.Params.Get("target");
        // ruleid: cra-csharp-httpclient-request-taint
        return await client.GetStringAsync(target);
    }

    async Task<HttpResponseMessage> GoodConstantDestination(HttpRequest req, HttpClient client) {
        string correlationId = req.Headers.Get("X-Correlation-Id");
        var message = new HttpRequestMessage(HttpMethod.Get, "https://updates.example.com/manifest.json");
        message.Headers.Add("X-Correlation-Id", correlationId);
        // ok: cra-csharp-httpclient-request-taint
        return await client.SendAsync(message);
    }
}
