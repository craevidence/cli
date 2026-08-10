using System.Net;
using System.Net.Http;
using System.Net.Security;

class ClientFactory {
    HttpClientHandler Bad() {
        var handler = new HttpClientHandler();
        // ruleid: cra-csharp-certificate-callback-accept-all
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
        return handler;
    }

    HttpClientHandler BadBuiltIn() {
        var handler = new HttpClientHandler();
        // ruleid: cra-csharp-certificate-callback-accept-all
        handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        return handler;
    }

    HttpClientHandler BadBlockLambda() {
        var handler = new HttpClientHandler();
        // ruleid: cra-csharp-certificate-callback-accept-all
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => { return true; };
        return handler;
    }

    HttpClientHandler BadObjectInitializer() {
        // ruleid: cra-csharp-certificate-callback-accept-all
        return new HttpClientHandler { ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true };
    }

    HttpClientHandler BadObjectInitializerBuiltIn() {
        // ruleid: cra-csharp-certificate-callback-accept-all
        return new HttpClientHandler { ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };
    }

    void BadAnonymousDelegate() {
        // ruleid: cra-csharp-certificate-callback-accept-all
        ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
    }

    void BadEventStyleAttach() {
        // ruleid: cra-csharp-certificate-callback-accept-all
        ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, errors) => true;
    }

    SocketsHttpHandler BadSslOptions() {
        var handler = new SocketsHttpHandler();
        // ruleid: cra-csharp-certificate-callback-accept-all
        handler.SslOptions.RemoteCertificateValidationCallback = (sender, cert, chain, errors) => true;
        return handler;
    }

    HttpClientHandler Good() {
        // ok: cra-csharp-certificate-callback-accept-all
        return new HttpClientHandler();
    }

    HttpClientHandler GoodRejects() {
        var handler = new HttpClientHandler();
        // ok: cra-csharp-certificate-callback-accept-all
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => false;
        return handler;
    }

    HttpClientHandler GoodChecksPolicyErrors() {
        var handler = new HttpClientHandler();
        // ok: cra-csharp-certificate-callback-accept-all
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => errors == SslPolicyErrors.None;
        return handler;
    }

    void GoodClearsCallback() {
        // ok: cra-csharp-certificate-callback-accept-all
        ServicePointManager.ServerCertificateValidationCallback = null;
    }
}
