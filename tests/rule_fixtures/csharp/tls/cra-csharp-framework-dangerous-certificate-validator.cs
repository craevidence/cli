using System.Net.Http;

class FrameworkCases
{
    HttpClientHandler Direct()
    {
        var handler = new HttpClientHandler();
        // ruleid: cra-csharp-framework-dangerous-certificate-validator
        handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        return handler;
    }

    HttpClientHandler Qualified()
    {
        var handler = new HttpClientHandler();
        // ruleid: cra-csharp-framework-dangerous-certificate-validator
        handler.ServerCertificateCustomValidationCallback = System.Net.Http.HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        return handler;
    }

    HttpClientHandler GlobalQualified()
    {
        var handler = new HttpClientHandler();
        // ruleid: cra-csharp-framework-dangerous-certificate-validator
        handler.ServerCertificateCustomValidationCallback = global::System.Net.Http.HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        return handler;
    }

    HttpClientHandler Initializer()
    {
        return new HttpClientHandler {
            // ruleid: cra-csharp-framework-dangerous-certificate-validator
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };
    }

    HttpClientHandler SafeDefault()
    {
        // ok: cra-csharp-framework-dangerous-certificate-validator
        return new HttpClientHandler();
    }

    HttpClientHandler SafePolicyCheck()
    {
        var handler = new HttpClientHandler();
        // ok: cra-csharp-framework-dangerous-certificate-validator
        handler.ServerCertificateCustomValidationCallback =
            (message, certificate, chain, errors) => errors == System.Net.Security.SslPolicyErrors.None;
        return handler;
    }
}

namespace Application
{
    class HttpClientHandler
    {
        public object ServerCertificateCustomValidationCallback { get; set; } = new object();
        public static object DangerousAcceptAnyServerCertificateValidator { get; } = new object();
    }

    class ApplicationCase
    {
        HttpClientHandler CorrectApplicationCode()
        {
            var handler = new HttpClientHandler();
            // ruleid: cra-csharp-framework-dangerous-certificate-validator
            handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
            return handler;
        }
    }
}
