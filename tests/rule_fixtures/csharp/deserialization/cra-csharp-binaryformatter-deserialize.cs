using System.IO;
using System.Runtime.Serialization.Formatters;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text.Json;
using System.Xml.Serialization;

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

    object BadFullyQualified(Stream input) {
        // ruleid: cra-csharp-binaryformatter-deserialize
        return new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter().Deserialize(input);
    }

    object BadTargetTypedNew(Stream input) {
        BinaryFormatter formatter = new();
        // ruleid: cra-csharp-binaryformatter-deserialize
        return formatter.Deserialize(input);
    }

    object BadObjectInitializer(Stream input) {
        // ruleid: cra-csharp-binaryformatter-deserialize
        return new BinaryFormatter { AssemblyFormat = FormatterAssemblyStyle.Simple }.Deserialize(input);
    }

    object BadObjectInitializerLocal(Stream input) {
        var formatter = new BinaryFormatter { AssemblyFormat = FormatterAssemblyStyle.Simple };
        // ruleid: cra-csharp-binaryformatter-deserialize
        return formatter.Deserialize(input);
    }

    object Good(string input) {
        // ok: cra-csharp-binaryformatter-deserialize
        return JsonSerializer.Deserialize<object>(input);
    }

    object GoodXmlSerializer(Stream input) {
        XmlSerializer serializer = new(typeof(object));
        // ok: cra-csharp-binaryformatter-deserialize
        return serializer.Deserialize(input);
    }

    string GoodMentionInString() {
        // ok: cra-csharp-binaryformatter-deserialize
        return "new BinaryFormatter().Deserialize(stream) must not be used";
    }
}
