import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URL;

class FetchHandler {
    String requestedUrl(HttpServletRequest request) {
        return request.getParameter("url");
    }

    URL badAcrossHelper(HttpServletRequest request) throws Exception {
        String target = requestedUrl(request);
        // ruleid: cra-java-url-request-taint
        return new URL(target);
    }

    URI bad(HttpServletRequest request) {
        String target = request.getHeader("X-Target");
        // ruleid: cra-java-url-request-taint
        return URI.create(target);
    }

    URL good() throws Exception {
        // ok: cra-java-url-request-taint
        return new URL("https://updates.example.com/manifest.json");
    }


    // Bad: Spring binds the request value to an annotated parameter
    public void fetchSpringParam(@RequestParam("value") String value) throws Exception {
        // ruleid: cra-java-url-request-taint
        new URL(value).openStream();
    }
}