import java.security.MessageDigest;
import static java.security.MessageDigest.getInstance;

class Digests {
    static final String LEGACY_DIGEST = "MD5";
    static final String ALIAS_DIGEST = "SHA";
    static final String OID_DIGEST = "1.2.840.113549.2.5";
    static final String STRONG_DIGEST = "SHA-256";
    static final String md5 = "SHA-256";
    static final String BLANK_FINAL;

    static {
        BLANK_FINAL = "MD2";
    }

    MessageDigest badNamedConstant() throws Exception {
        // ruleid: cra-java-weak-message-digest
        return MessageDigest.getInstance(LEGACY_DIGEST);
    }

    MessageDigest badShaAliasConstant() throws Exception {
        // ruleid: cra-java-weak-message-digest
        return MessageDigest.getInstance(ALIAS_DIGEST);
    }

    MessageDigest badOidConstant() throws Exception {
        // ruleid: cra-java-weak-message-digest
        return MessageDigest.getInstance(OID_DIGEST);
    }

    MessageDigest badStaticBlockConstant() throws Exception {
        // ruleid: cra-java-weak-message-digest
        return MessageDigest.getInstance(BLANK_FINAL);
    }

    MessageDigest good() throws Exception {
        // ok: cra-java-weak-message-digest
        return MessageDigest.getInstance("SHA-256");
    }

    java.security.MessageDigest goodFullyQualified() throws Exception {
        // ok: cra-java-weak-message-digest
        return java.security.MessageDigest.getInstance("SHA-256");
    }

    java.security.MessageDigest goodProviderOverload() throws Exception {
        // ok: cra-java-weak-message-digest
        return java.security.MessageDigest.getInstance("SHA-256", "SUN");
    }

    MessageDigest goodSha3() throws Exception {
        // ok: cra-java-weak-message-digest
        return MessageDigest.getInstance("SHA3-256");
    }

    MessageDigest goodTruncatedSha512() throws Exception {
        // ok: cra-java-weak-message-digest
        return MessageDigest.getInstance("SHA-512/256");
    }

    MessageDigest goodSha224() throws Exception {
        // ok: cra-java-weak-message-digest
        return MessageDigest.getInstance("SHA-224");
    }

    MessageDigest goodMixedCase() throws Exception {
        // ok: cra-java-weak-message-digest
        return MessageDigest.getInstance("sha-256");
    }

    // 2.16.840.1.101.3.4.2.1 is the SHA-256 object identifier.
    MessageDigest goodSha256Oid() throws Exception {
        // ok: cra-java-weak-message-digest
        return MessageDigest.getInstance("2.16.840.1.101.3.4.2.1");
    }

    MessageDigest goodStrongConstant() throws Exception {
        // ok: cra-java-weak-message-digest
        return MessageDigest.getInstance(STRONG_DIGEST);
    }

    // The constant is named md5 but holds a strong algorithm.
    MessageDigest goodMisleadingConstantName() throws Exception {
        // ok: cra-java-weak-message-digest
        return MessageDigest.getInstance(md5);
    }

    // The JDK rejects every spelling below, so none of them selects a digest.
    MessageDigest goodUnknownNames() throws Exception {
        // ok: cra-java-weak-message-digest
        MessageDigest.getInstance("MD-5");
        // ok: cra-java-weak-message-digest
        MessageDigest.getInstance("SHA-128");
        // ok: cra-java-weak-message-digest
        MessageDigest.getInstance("MD5X");
        // ok: cra-java-weak-message-digest
        MessageDigest.getInstance("MD4");
        // ok: cra-java-weak-message-digest
        MessageDigest.getInstance("SHA-0");
        // ok: cra-java-weak-message-digest
        MessageDigest.getInstance(" MD5");
        // ok: cra-java-weak-message-digest
        MessageDigest.getInstance("MD5 ");
        // ok: cra-java-weak-message-digest
        MessageDigest.getInstance("1.2.840.113549.2.4");
        // ok: cra-java-weak-message-digest
        return MessageDigest.getInstance("1.3.14.3.2.26.1");
    }

    // Other factories keyed on an algorithm name are out of scope.
    void goodOtherFactories() throws Exception {
        // ok: cra-java-weak-message-digest
        javax.crypto.Mac.getInstance("HmacMD5");
        // ok: cra-java-weak-message-digest
        java.security.Signature.getInstance("SHA1withRSA");
        // ok: cra-java-weak-message-digest
        java.security.KeyFactory.getInstance("MD5");
        // ok: cra-java-weak-message-digest
        javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
    }

    // "MD5" and "SHA-1" as plain data never select a digest.
    void goodPlainStrings() {
        String md5Label = "MD5";
        // ok: cra-java-weak-message-digest
        System.out.println("hashed with MD5 and SHA-1");
        switch (md5Label) {
            // ok: cra-java-weak-message-digest
            case "MD5":
                break;
            default:
                break;
        }
    }
}

record RecordDigests(int size) {
    static final String LEGACY_DIGEST = "MD5";

    static MessageDigest badRecordConstant() throws Exception {
        // ruleid: cra-java-weak-message-digest
        return MessageDigest.getInstance(LEGACY_DIGEST);
    }
}

enum EnumDigests {
    ONLY;

    static final String LEGACY_DIGEST = "SHA-1";

    static MessageDigest badEnumConstant() throws Exception {
        // ruleid: cra-java-weak-message-digest
        return MessageDigest.getInstance(LEGACY_DIGEST);
    }
}

interface InterfaceDigests {
    // Interface fields are implicitly public static final.
    String LEGACY_DIGEST = "MD2";

    static MessageDigest badInterfaceConstant() throws Exception {
        // ruleid: cra-java-weak-message-digest
        return MessageDigest.getInstance(LEGACY_DIGEST);
    }
}

class InstanceFieldDigests {
    // Not static final, so the rule does not treat it as a constant.
    private final String algorithm = "MD5";

    MessageDigest goodInstanceField() throws Exception {
        // ok: cra-java-weak-message-digest
        return MessageDigest.getInstance(algorithm);
    }
}
