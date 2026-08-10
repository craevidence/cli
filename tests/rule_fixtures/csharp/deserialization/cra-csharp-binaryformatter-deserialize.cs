using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text.Json;

class Decoder {
    object Bad(Stream input) {
        var formatter = new BinaryFormatter();
        // ruleid: cra-csharp-binaryformatter-deserialize
        return formatter.Deserialize(input);
    }

    object BadInline(Stream input) {
        // ruleid: cra-csharp-binaryformatter-deserialize
        return new BinaryFormatter().Deserialize(input);
    }

    object Good(string input) {
        // ok: cra-csharp-binaryformatter-deserialize
        return JsonSerializer.Deserialize<object>(input);
    }
}
