using Microsoft.IdentityModel.Tokens;
using System;
using System.Text;

class JwtKeys {
    SymmetricSecurityKey Bad() {
        // ruleid: cra-csharp-jwt-hardcoded-secret
        return new SymmetricSecurityKey(Encoding.UTF8.GetBytes("development-secret"));
    }

    SymmetricSecurityKey Good() {
        string secret = Environment.GetEnvironmentVariable("JWT_SECRET");
        // ok: cra-csharp-jwt-hardcoded-secret
        return new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
    }
}
