using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using FirebaseAdmin.Auth;
using System.Linq;
using System.Security.Claims;
using System; // Required for StringComparison
using Microsoft.Extensions.Logging; // Recommended for logging

namespace CodeFirstAPI.Middleware // Added namespace
{
    public class FirebaseAuthMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<FirebaseAuthMiddleware> _logger; // Recommended for logging

        public FirebaseAuthMiddleware(RequestDelegate next, ILogger<FirebaseAuthMiddleware> logger) // Added logger
        {
            _next = next;
            _logger = logger; // Added logger
        }

        public async Task Invoke(HttpContext context)
        {
            var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
            FirebaseToken decodedToken = null;

            if (authHeader != null && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                var token = authHeader.Substring("Bearer ".Length).Trim();

                if (!string.IsNullOrEmpty(token))
                {
                    try
                    {
                        // If you have a FirebaseInitializer.GetApp(), prefer using that:
                        // decodedToken = await FirebaseInitializer.GetApp().Auth.VerifyIdTokenAsync(token);
                        decodedToken = await FirebaseAuth.DefaultInstance.VerifyIdTokenAsync(token);
                        _logger.LogInformation("Successfully verified Firebase ID token for UID: {UserId}", decodedToken.Uid);
                    }
                    catch (FirebaseAuthException ex)
                    {
                        _logger.LogWarning(ex, "Invalid Firebase ID token. AuthErrorCode: {AuthErrorCode}", ex.AuthErrorCode);
                        context.Response.StatusCode = 401; // Unauthorized
                        await context.Response.WriteAsync($"Invalid Firebase token: {ex.Message}");
                        return;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "An unexpected error occurred while verifying Firebase ID token.");
                        context.Response.StatusCode = 500; // Internal Server Error
                        await context.Response.WriteAsync("An internal error occurred while processing the authentication token.");
                        return;
                    }
                }
                else
                {
                    _logger.LogInformation("Authorization header was present but token was empty.");
                }
            }
            // else: No Authorization header or not a Bearer token. Proceeding anonymously.
            // The [Authorize] attribute will handle if authentication is required.

            if (decodedToken != null)
            {
                var claims = decodedToken.Claims.Select(c => new Claim(c.Key, c.Value.ToString()));
                var identity = new ClaimsIdentity(claims, "Firebase");
                context.User = new ClaimsPrincipal(identity);
                _logger.LogInformation("Set HttpContext.User for UID: {UserId}", decodedToken.Uid);
            }

            await _next(context);
        }
    }
}
