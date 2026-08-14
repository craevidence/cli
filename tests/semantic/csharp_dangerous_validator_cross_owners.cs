using System;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace CrossOwners
{
    class HttpClientHandler
    {
        public object ServerCertificateCustomValidationCallback { get; set; } = new object();
        public static Func<HttpRequestMessage, X509Certificate2, X509Chain, SslPolicyErrors, bool>
            DangerousAcceptAnyServerCertificateValidator { get; } = (_, _, _, _) => true;
    }

    class Cases
    {
        void ApplicationLeft(HttpClientHandler handler)
        {
            handler.ServerCertificateCustomValidationCallback = System.Net.Http.HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        }

        void ApplicationRight(System.Net.Http.HttpClientHandler handler)
        {
            handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        }
    }
}
