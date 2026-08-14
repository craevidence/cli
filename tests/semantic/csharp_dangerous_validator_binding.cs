using System.Net.Http;

class FrameworkCase
{
    void Configure(HttpClientHandler handler)
    {
        handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
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
        void Configure(HttpClientHandler handler)
        {
            handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        }
    }
}
