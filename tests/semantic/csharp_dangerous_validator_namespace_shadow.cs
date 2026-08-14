namespace System.Net.Http
{
    class HttpClientHandler
    {
        public object ServerCertificateCustomValidationCallback { get; set; } = new object();
        public static object DangerousAcceptAnyServerCertificateValidator { get; } = new object();
    }
}

namespace NamespaceShadow
{
    class Case
    {
        void Configure(System.Net.Http.HttpClientHandler handler)
        {
            handler.ServerCertificateCustomValidationCallback = System.Net.Http.HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        }
    }
}
