import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectInputFilter;

class NativeDeserializer {
    Object bad(InputStream input) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(input);
        // ruleid: cra-java-objectinputstream-readobject
        return stream.readObject();
    }

    String good(InputStream input) throws Exception {
        // ok: cra-java-objectinputstream-readobject
        return new String(input.readAllBytes());
    }

    Object goodFiltered(InputStream input) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(input);
        ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
            "java.base/*;!*"
        );
        stream.setObjectInputFilter(filter);
        // ok: cra-java-objectinputstream-readobject
        return stream.readObject();
    }

    Object goodFilteredAssignment(InputStream input) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(input);
        stream.setObjectInputFilter(
            ObjectInputFilter.Config.createFilter("java.base/*;!*")
        );
        // ok: cra-java-objectinputstream-readobject
        Object value = stream.readObject();
        return value;
    }

    Object badFilterOnAnotherStream(InputStream trustedInput, InputStream input)
            throws Exception {
        ObjectInputStream trusted = new ObjectInputStream(trustedInput);
        trusted.setObjectInputFilter(
            ObjectInputFilter.Config.createFilter("java.base/*;!*")
        );
        ObjectInputStream stream = new ObjectInputStream(input);
        // ruleid: cra-java-objectinputstream-readobject
        return stream.readObject();
    }

    Object badLateFilter(InputStream input) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(input);
        // ruleid: cra-java-objectinputstream-readobject
        Object value = stream.readObject();
        ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
            "java.base/*;!*"
        );
        stream.setObjectInputFilter(filter);
        return value;
    }
}
