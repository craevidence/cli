import java.security.*;

class MessageDigest {
    static Object getInstance(String algorithm) {
        return algorithm;
    }
}

class ApplicationDigest {
    Object shadow() {
        // ruleid: cra-java-jdk-weak-message-digest-literal
        return MessageDigest.getInstance("MD5");
    }
}
