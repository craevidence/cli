using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Data.SqlClient;

class SqlHandler {
    string RequestedName(HttpRequest request) {
        return request.Query["name"];
    }

    SqlCommand BadAcrossHelper(HttpRequest request, SqlConnection connection) {
        string name = RequestedName(request);
        string query = "SELECT * FROM users WHERE name = '" + name + "'";
        // ruleid: cra-csharp-sql-request-taint
        return new SqlCommand(query, connection);
    }

    SqlCommand Bad(HttpRequest request, SqlConnection connection) {
        string query = "SELECT * FROM users WHERE id = " + request.Form["id"];
        // ruleid: cra-csharp-sql-request-taint
        return new SqlCommand(query, connection);
    }

    object BadFromRoute([FromRoute] string table, DbContext context) {
        string query = "SELECT * FROM " + table;
        // ruleid: cra-csharp-sql-request-taint
        return context.Database.ExecuteSqlRaw(query);
    }

    SqlCommand Good(HttpRequest request, SqlConnection connection) {
        string name = request.Query["name"];
        var command = new SqlCommand("SELECT * FROM users WHERE name = @name", connection);
        command.Parameters.AddWithValue("@name", name);
        // ok: cra-csharp-sql-request-taint
        return command;
    }

    SqlCommand GoodInt(HttpRequest request, SqlConnection connection) {
        int id = int.Parse(request.Query["id"]);
        // ok: cra-csharp-sql-request-taint
        return new SqlCommand("SELECT * FROM users WHERE id = " + id, connection);
    }

    SqlCommand GoodTryParse(HttpRequest request, SqlConnection connection) {
        int.TryParse(request.Query["id"], out int id);
        // ok: cra-csharp-sql-request-taint
        return new SqlCommand("SELECT * FROM users WHERE id = " + id, connection);
    }

    SqlCommand GoodGuid(HttpRequest request, SqlConnection connection) {
        Guid id = Guid.Parse(request.Query["id"]);
        // ok: cra-csharp-sql-request-taint
        return new SqlCommand("SELECT * FROM users WHERE id = '" + id + "'", connection);
    }
}
