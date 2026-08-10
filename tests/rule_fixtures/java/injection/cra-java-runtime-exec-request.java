import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;

class CommandHandler {
    String requestCommand(HttpServletRequest request) {
        return request.getParameter("command");
    }

    void badAcrossHelper(HttpServletRequest request) throws IOException {
        String command = requestCommand(request);
        // ruleid: cra-java-runtime-exec-request
        Runtime.getRuntime().exec(command);
    }

    void bad(HttpServletRequest request) throws IOException {
        String command = request.getParameter("command");
        // ruleid: cra-java-runtime-exec-request
        Runtime.getRuntime().exec(command);
    }

    void good(HttpServletRequest request) throws IOException {
        String value = request.getParameter("value");
        if (!value.matches("[a-z0-9]+")) {
            return;
        }
        // ok: cra-java-runtime-exec-request
        new ProcessBuilder("/usr/bin/lookup", value).start();
    }
}
