import java.security.MessageDigest;
import static java.security.MessageDigest.getInstance;

class JdkDigests {
    Object direct() throws Exception {
        // ruleid: cra-java-jdk-weak-message-digest-literal
        return MessageDigest.getInstance("MD5");
    }

    Object qualified() throws Exception {
        // ruleid: cra-java-jdk-weak-message-digest-literal
        return java.security.MessageDigest.getInstance("SHA-1");
    }

    Object imported() throws Exception {
        // ruleid: cra-java-jdk-weak-message-digest-literal
        return getInstance("SHA1");
    }

    Object strong() throws Exception {
        // ok: cra-java-jdk-weak-message-digest-literal
        return MessageDigest.getInstance("SHA-256");
    }
}
