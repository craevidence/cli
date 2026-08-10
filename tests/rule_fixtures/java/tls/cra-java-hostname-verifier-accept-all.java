import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

class AcceptAllHostnames implements HostnameVerifier {
    public boolean verify(String hostname, SSLSession session) {
        // ruleid: cra-java-hostname-verifier-accept-all
        return true;
    }
}

class TlsClient {
    void bad(HttpsURLConnection connection) {
        // ruleid: cra-java-hostname-verifier-accept-all
        connection.setHostnameVerifier((host, session) -> true);
    }

    void good(HttpsURLConnection connection) {
        // ok: cra-java-hostname-verifier-accept-all
        connection.setHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());
    }
}
