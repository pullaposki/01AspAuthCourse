using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

const string AuthScheme = "cookie";
const string AuthScheme2 = "cookie2";

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(AuthScheme)
    .AddCookie(AuthScheme)
    .AddCookie(AuthScheme2);

builder.Services.AddAuthorization(builder =>
{
    builder.AddPolicy("eu_passport", policyBuilder =>
    {
        policyBuilder.RequireAuthenticatedUser()
            .AddAuthenticationSchemes(AuthScheme)
            .RequireClaim("passport_type", "eur");
    });
});

var app = builder.Build();

app.UseAuthentication();

app.Use((context, next) =>
{
    if(context.Request.Path == "/login")
    {
        return next();
    }

    if (!DoesHaveAuthScheme(context, AuthScheme))
    {
        context.Response.StatusCode = 401;
        return Task.CompletedTask;
    }

    if (!HasEurClaim(context))
    {
        context.Response.StatusCode = 403;
        return Task.CompletedTask;
    }

    return next();
});

app.MapGet("/unsecure", (HttpContext context) =>
{
    // Try to get the user name from the claims
    return context.User.FindFirst("usr")?
        .Value ?? "No user";
});

app.MapGet("/sweden", (HttpContext context) =>
{
    // if (!DoesHaveAuthScheme(context, AuthScheme))
    // {
    //   context.Response.StatusCode = 401;
    //   return "wrong auth scheme";
    // }

    // if (!HasEurClaim(context))
    // {
    //   context.Response.StatusCode = 403;
    //   return "not allowed";
    // }

    return "allowed";
}).RequireAuthorization("eu_passport");

app.MapGet("/norway", (HttpContext context) =>
{
    if (!DoesHaveAuthScheme(context, AuthScheme))
    {
        context.Response.StatusCode = 401;
        return "wrong auth scheme";
    }

    if (!HasNorClaim(context))
    {
        context.Response.StatusCode = 403;
        return "not allowed";
    }

    return "allowed";
});

app.MapGet("/denmark", (HttpContext context) =>
{
    // if (!DoesHaveAuthScheme(context, AuthScheme2))
    // {
    //   context.Response.StatusCode = 401;
    //   return "wrong auth scheme";
    // }

    // if (!HasEurClaim(context))
    // {
    //   context.Response.StatusCode = 403;
    //   return "not allowed";
    // }
    return "allowed";
});

app.MapGet("/login", async (HttpContext context) =>
{
    var claims = new List<Claim>
    {
        new Claim("usr", "Janne"),
         new Claim("passport_type", "eur")
    };

    var identity = new ClaimsIdentity(claims, AuthScheme);

    var user = new ClaimsPrincipal(identity);

    await context.SignInAsync(AuthScheme, user);
    return "logged in";
}).AllowAnonymous();


app.Run();


static bool DoesHaveAuthScheme(HttpContext context, string AuthScheme)
{
    return context.User.Identities.Any(i => i.AuthenticationType == AuthScheme);
}

static bool HasEurClaim(HttpContext context)
{
    return context.User.HasClaim("passport_type", "eur");
}

static bool HasNorClaim(HttpContext context)
{
    return context.User.HasClaim("passport_type", "NOR");
}

public class MyRequirement : IAuthorizationRequirement
{

}

public class MyRequirementHandler : AuthorizationHandler<MyRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, MyRequirement requirement)
    {
        return Task.CompletedTask;
    }
}