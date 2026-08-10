using System.Security.Cryptography;

class Hashes {
    HashAlgorithm BadMd5() {
        // ruleid: cra-csharp-weak-hash
        return MD5.Create();
    }

    HashAlgorithm BadSha1() {
        // ruleid: cra-csharp-weak-hash
        return SHA1.Create();
    }

    HashAlgorithm BadQualifiedMd5() {
        // ruleid: cra-csharp-weak-hash
        return System.Security.Cryptography.MD5.Create();
    }

    HashAlgorithm BadFactoryMd5() {
        // ruleid: cra-csharp-weak-hash
        return HashAlgorithm.Create("MD5");
    }

    HashAlgorithm Good() {
        // ok: cra-csharp-weak-hash
        return SHA256.Create();
    }
}
