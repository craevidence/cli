using System.Net.Http;

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

    HttpClientHandler Good() {
        // ok: cra-csharp-certificate-callback-accept-all
        return new HttpClientHandler();
    }
}
