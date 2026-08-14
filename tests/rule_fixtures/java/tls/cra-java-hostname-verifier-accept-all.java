import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

class AcceptAllHostnames implements HostnameVerifier {
    // ruleid: cra-java-hostname-verifier-accept-all
    public boolean verify(String hostname, SSLSession session) {
        return true;
    }
}

class AcceptAllAfterLogging implements HostnameVerifier {
    // ruleid: cra-java-hostname-verifier-accept-all
    public boolean verify(String hostname, SSLSession session) {
        System.out.println("skipping hostname check for " + hostname);
        return true;
    }
}

class AcceptAllAfterConditionalLogging implements HostnameVerifier {
    private final boolean debug = true;

    // ruleid: cra-java-hostname-verifier-accept-all
    public boolean verify(String hostname, SSLSession session) {
        if (debug) {
            System.out.println(hostname);
        }
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

class DefaultVerifierSetter {
    void badStaticDefault() {
        // ruleid: cra-java-hostname-verifier-accept-all
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
    }

    void badAnonymousInnerClass(HttpsURLConnection connection) {
        connection.setHostnameVerifier(new HostnameVerifier() {
            // ruleid: cra-java-hostname-verifier-accept-all
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        });
    }

    void okAnonymousInnerClassChecksHost(HttpsURLConnection connection) {
        connection.setHostnameVerifier(new HostnameVerifier() {
            // ok: cra-java-hostname-verifier-accept-all
            public boolean verify(String hostname, SSLSession session) {
                return hostname.equals("known.example");
            }
        });
    }

    void okAnonymousInnerClassWithHelper(HttpsURLConnection connection) {
        connection.setHostnameVerifier(new HostnameVerifier() {

            private boolean auditingEnabled() {
                // ok: cra-java-hostname-verifier-accept-all
                return true;
            }

            public boolean verify(String hostname, SSLSession session) {
                if (auditingEnabled()) {
                    System.out.println(hostname);
                }
                return hostname.endsWith(".known.example");
            }
        });
    }
}

// A branch that accepts one host is a real check, not an accept-all verifier.
class BranchingVerifier implements HostnameVerifier {
    // ok: cra-java-hostname-verifier-accept-all
    public boolean verify(String hostname, SSLSession session) {
        if (hostname.equals("known.example")) {
            return true;
        }
        return false;
    }
}

// An unrelated boolean method next to a correct verify method.
class VerifierWithFlag implements HostnameVerifier {
    // ok: cra-java-hostname-verifier-accept-all
    public boolean isEnabled() {
        return true;
    }

    public boolean verify(String hostname, SSLSession session) {
        return hostname.equals("known.example");
    }
}

// Same method signature on a type that is not a HostnameVerifier.
class FeatureFlag {
    // ok: cra-java-hostname-verifier-accept-all
    public boolean verify(String hostname, SSLSession session) {
        return true;
    }
}
