using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Data.SqlClient;
using System.Web;

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

    void BadQueryStringCompoundAssign(HttpRequest req, SqlConnection connection) {
        string name = req.QueryString["name"];
        var command = new SqlCommand(null, connection);
        // ruleid: cra-csharp-sql-request-taint
        command.CommandText += "SELECT * FROM users WHERE name = '" + name + "'";
    }

    void BadParamsGet(HttpRequest req, SqlConnection connection) {
        string name = req.Params.Get("name");
        var command = new SqlCommand(null, connection);
        // ruleid: cra-csharp-sql-request-taint
        command.CommandText = "SELECT * FROM users WHERE name = '" + name + "'";
    }

    void BadCookieCollection(HttpRequest req, SqlConnection connection) {
        HttpCookieCollection cookies = req.Cookies;
        string name = cookies[0].Value;
        var command = new SqlCommand(null, connection);
        // ruleid: cra-csharp-sql-request-taint
        command.CommandText = "SELECT * FROM users WHERE name = '" + name + "'";
    }

    void GoodConstantCompoundAssign(HttpRequest req, SqlConnection connection) {
        string name = req.QueryString["name"];
        var command = new SqlCommand(null, connection);
        command.Parameters.AddWithValue("@name", name);
        // ok: cra-csharp-sql-request-taint
        command.CommandText += "SELECT * FROM users WHERE name = @name";
    }

    void GoodApplicationParamsHomonym(ReportSpec spec, SqlConnection connection) {
        var command = new SqlCommand("SELECT 1", connection);
        // ok: cra-csharp-sql-request-taint
        command.CommandText += " -- " + spec.Params.Get("range");
    }
}

class ReportSpec {
    public ParamBag Params { get; set; }
}

class ParamBag {
    public string Get(string key) => "fixed";
}
