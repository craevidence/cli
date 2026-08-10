using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

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

    byte[] BadMd5HashData(byte[] input) {
        // ruleid: cra-csharp-weak-hash
        return MD5.HashData(input);
    }

    byte[] BadSha1HashData(byte[] input) {
        // ruleid: cra-csharp-weak-hash
        return SHA1.HashData(input);
    }

    bool BadSha1TryHashData(byte[] input, Span<byte> destination) {
        // ruleid: cra-csharp-weak-hash
        return SHA1.TryHashData(input, destination, out int written);
    }

    async Task<byte[]> BadMd5HashDataAsync(Stream input) {
        // ruleid: cra-csharp-weak-hash
        return await MD5.HashDataAsync(input);
    }

    HashAlgorithm BadSha1ManagedCreate() {
        // ruleid: cra-csharp-weak-hash
        return SHA1Managed.Create();
    }

    HashAlgorithm BadNewSha1Managed() {
        // ruleid: cra-csharp-weak-hash
        return new SHA1Managed();
    }

    HashAlgorithm BadNewMd5CryptoServiceProvider() {
        // ruleid: cra-csharp-weak-hash
        return new MD5CryptoServiceProvider();
    }

    HashAlgorithm Good() {
        // ok: cra-csharp-weak-hash
        return SHA256.Create();
    }

    byte[] GoodHashData(byte[] input) {
        // ok: cra-csharp-weak-hash
        return SHA256.HashData(input);
    }

    HashAlgorithm GoodSha512() {
        // ok: cra-csharp-weak-hash
        return new SHA512CryptoServiceProvider();
    }

    byte[] GoodKeyedMac(byte[] key, byte[] input) {
        using var mac = new HMACSHA256(key);
        // ok: cra-csharp-weak-hash
        return mac.ComputeHash(input);
    }
}

static class MD5Helper {
    public static byte[] HashData(byte[] input) {
        return SHA256.HashData(input);
    }
}

class UsesApplicationHelper {
    byte[] GoodApplicationType(byte[] input) {
        // ok: cra-csharp-weak-hash
        return MD5Helper.HashData(input);
    }
}
