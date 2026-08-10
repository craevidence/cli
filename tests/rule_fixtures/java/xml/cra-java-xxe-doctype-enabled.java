import javax.xml.parsers.DocumentBuilderFactory;
import java.io.InputStream;

class XmlParserConfig {
    void badDefault(InputStream input) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // ruleid: cra-java-xxe-doctype-enabled
        factory.newDocumentBuilder().parse(input);
    }

    void bad(DocumentBuilderFactory factory) throws Exception {
        // ruleid: cra-java-xxe-doctype-enabled
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        // ruleid: cra-java-xxe-doctype-enabled
        factory.setExpandEntityReferences(true);
    }

    void good(DocumentBuilderFactory factory) throws Exception {
        // ok: cra-java-xxe-doctype-enabled
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        // ok: cra-java-xxe-doctype-enabled
        factory.setExpandEntityReferences(false);
    }

    void goodDefaultHardened(InputStream input) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(
            "http://apache.org/xml/features/disallow-doctype-decl",
            true
        );
        // ok: cra-java-xxe-doctype-enabled
        factory.newDocumentBuilder().parse(input);
    }

    void badLateHardening(InputStream input) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // ruleid: cra-java-xxe-doctype-enabled
        factory.newDocumentBuilder().parse(input);
        factory.setFeature(
            "http://apache.org/xml/features/disallow-doctype-decl",
            true
        );
    }
}
