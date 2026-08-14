#if DEBUG
using System.Net.Http;

class ConditionalCase
{
    void Configure(HttpClientHandler handler)
    {
        handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
    }
}
#endif

class DefaultProfileCase
{
}
