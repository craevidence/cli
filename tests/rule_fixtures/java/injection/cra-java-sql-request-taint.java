import jakarta.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.UUID;

class SqlHandler {
    String requestedName(HttpServletRequest request) {
        return request.getParameter("name");
    }

    void badAcrossHelper(HttpServletRequest request, Statement statement) throws Exception {
        String name = requestedName(request);
        String query = "SELECT * FROM users WHERE name = '" + name + "'";
        // ruleid: cra-java-sql-request-taint
        statement.executeQuery(query);
    }

    void bad(HttpServletRequest request, Statement statement) throws Exception {
        String query = "SELECT * FROM users WHERE id = " + request.getParameter("id");
        // ruleid: cra-java-sql-request-taint
        statement.execute(query);
    }

    void badPrepareStatement(HttpServletRequest request, Connection connection) throws Exception {
        String query = "SELECT * FROM users WHERE id = " + request.getParameter("id");
        // ruleid: cra-java-sql-request-taint
        connection.prepareStatement(query);
    }

    void badBatch(HttpServletRequest request, Statement statement) throws Exception {
        String query = "DELETE FROM users WHERE id = " + request.getParameter("id");
        // ruleid: cra-java-sql-request-taint
        statement.addBatch(query);
        statement.executeBatch();
    }

    void good(HttpServletRequest request, Connection connection) throws Exception {
        String name = request.getParameter("name");
        PreparedStatement statement = connection.prepareStatement(
            "SELECT * FROM users WHERE name = ?"
        );
        statement.setString(1, name);
        // ok: cra-java-sql-request-taint
        statement.executeQuery();
    }

    void goodInteger(HttpServletRequest request, Statement statement) throws Exception {
        int id = Integer.parseInt(request.getParameter("id"));
        // ok: cra-java-sql-request-taint
        statement.executeQuery("SELECT * FROM users WHERE id = " + id);
    }

    void goodLong(HttpServletRequest request, Statement statement) throws Exception {
        long id = Long.parseLong(request.getParameter("id"));
        // ok: cra-java-sql-request-taint
        statement.executeQuery("SELECT * FROM users WHERE id = " + id);
    }

    void goodUuid(HttpServletRequest request, Statement statement) throws Exception {
        UUID id = UUID.fromString(request.getParameter("id"));
        // ok: cra-java-sql-request-taint
        statement.executeQuery("SELECT * FROM users WHERE id = '" + id + "'");
    }
}
