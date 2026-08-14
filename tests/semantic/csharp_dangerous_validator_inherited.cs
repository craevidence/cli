class HttpClientHandler : System.Net.Http.HttpClientHandler
{
}

class InheritedCase
{
    void Configure(HttpClientHandler handler)
    {
        handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
    }
}
