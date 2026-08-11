import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

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


    // Bad: Spring binds the request value to an annotated parameter
    public void execSpringParam(@RequestParam("value") String value) throws Exception {
        // ruleid: cra-java-runtime-exec-request
        Runtime.getRuntime().exec(value);
    }
}

// The first element of a command sequence is the program. When it is a fixed
// literal that is not a shell, the request value is an argument, which is the
// remediation this rule asks for.
class CommandSequences {
    void goodFixedProgramList(HttpServletRequest request) throws IOException {
        // ok: cra-java-runtime-exec-request
        new ProcessBuilder(List.of("/usr/bin/lookup", request.getParameter("value"))).start();
    }

    void goodFixedProgramAsList(HttpServletRequest request) throws IOException {
        // ok: cra-java-runtime-exec-request
        new ProcessBuilder(Arrays.asList("/usr/bin/lookup", request.getParameter("value"))).start();
    }

    void goodFixedProgramArray(HttpServletRequest request) throws IOException {
        // ok: cra-java-runtime-exec-request
        new ProcessBuilder(new String[] {"/usr/bin/lookup", request.getParameter("value")}).start();
    }

    void goodFixedProgramExecArray(HttpServletRequest request) throws IOException {
        // ok: cra-java-runtime-exec-request
        Runtime.getRuntime().exec(new String[] {"/usr/bin/lookup", request.getParameter("value")});
    }

    void badShellProgramList(HttpServletRequest request) throws IOException {
        // ruleid: cra-java-runtime-exec-request
        new ProcessBuilder(List.of("/bin/sh", "-c", request.getParameter("value"))).start();
    }

    void badShellProgramArray(HttpServletRequest request) throws IOException {
        // ruleid: cra-java-runtime-exec-request
        new ProcessBuilder(new String[] {"cmd.exe", "/c", request.getParameter("value")}).start();
    }

    void badShellProgramExecArray(HttpServletRequest request) throws IOException {
        // ruleid: cra-java-runtime-exec-request
        Runtime.getRuntime().exec(new String[] {"bash", "-c", request.getParameter("value")});
    }

    void badProgramFromRequest(HttpServletRequest request) throws IOException {
        // ruleid: cra-java-runtime-exec-request
        new ProcessBuilder(List.of(request.getParameter("value"))).start();
    }

    void badBareShellProgram(HttpServletRequest request) throws IOException {
        // ruleid: cra-java-runtime-exec-request
        new ProcessBuilder(List.of("sh", "-c", request.getParameter("value"))).start();
    }

    void badWindowsShellProgram(HttpServletRequest request) throws IOException {
        // ruleid: cra-java-runtime-exec-request
        new ProcessBuilder(List.of("C:\\Windows\\System32\\cmd.exe", "/c",
                request.getParameter("value"))).start();
    }

    // Program names that merely end in the letters of a shell name.
    void goodProgramEndingInShellLetters(HttpServletRequest request) throws IOException {
        // ok: cra-java-runtime-exec-request
        new ProcessBuilder(List.of("/usr/bin/refresh", request.getParameter("value"))).start();
    }

    void goodProgramEndingInCmd(HttpServletRequest request) throws IOException {
        // ok: cra-java-runtime-exec-request
        new ProcessBuilder(List.of("/opt/tools/mycmd", request.getParameter("value"))).start();
    }
}