import jakarta.servlet.http.HttpServletRequest;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

class FileHandler {
    String requestedPath(HttpServletRequest request) {
        return request.getParameter("path");
    }

    File badAcrossHelper(HttpServletRequest request) {
        String path = requestedPath(request);
        // ruleid: cra-java-file-request-taint
        return new File(path);
    }

    Path bad(HttpServletRequest request) {
        String path = request.getHeader("X-File");
        // ruleid: cra-java-file-request-taint
        return Paths.get(path);
    }

    File badFullyQualified(HttpServletRequest request) {
        String path = request.getParameter("path");
        // ruleid: cra-java-file-request-taint
        return new java.io.File(path);
    }

    File badChildPath(HttpServletRequest request) {
        String path = request.getParameter("path");
        // ruleid: cra-java-file-request-taint
        return new java.io.File("/srv/app/uploads", path);
    }

    java.nio.file.Path badFullyQualifiedPath(HttpServletRequest request) {
        String path = request.getParameter("path");
        // ruleid: cra-java-file-request-taint
        return java.nio.file.Paths.get(path);
    }

    Path good() {
        // ok: cra-java-file-request-taint
        return Path.of("/srv/app/config.json");
    }

    java.io.File goodFullyQualified() {
        // ok: cra-java-file-request-taint
        return new java.io.File("/srv/app/config.json");
    }

    java.io.File goodChildPath() {
        // ok: cra-java-file-request-taint
        return new java.io.File("/srv/app", "config.json");
    }
}
