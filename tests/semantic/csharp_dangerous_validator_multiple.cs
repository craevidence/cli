using System.Net.Http;

class MultipleCase
{
    void Configure(HttpClientHandler first, HttpClientHandler second)
    {
        first.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator; second.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
    }
}
