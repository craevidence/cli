using System.Security.Cryptography;

class FrameworkDigest {
    HashAlgorithm CreateDigest() {
        // ruleid: cra-csharp-framework-md5-create
        return MD5.Create();
    }

    HashAlgorithm CreateQualifiedDigest() {
        // ruleid: cra-csharp-framework-md5-create
        return System.Security.Cryptography.MD5.Create();
    }

    HashAlgorithm CreateGlobalQualifiedDigest() {
        // ruleid: cra-csharp-framework-md5-create
        return global::System.Security.Cryptography.MD5.Create();
    }

    HashAlgorithm CreateSafeDigest() {
        // ok: cra-csharp-framework-md5-create
        return SHA256.Create();
    }
}

namespace Application.Cryptography {
    class MD5 {
        public static object Create() => new object();
    }

    class ApplicationDigest {
        object CreateDigest() {
            // ruleid: cra-csharp-framework-md5-create
            return MD5.Create();
        }
    }
}
