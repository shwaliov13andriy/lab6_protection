using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var secretKey = "MySuperSecretKeyForApplicationSecurityLab6!";
var keyBytes = Encoding.UTF8.GetBytes(secretKey);

app.MapGet("/", () => Results.Content("""
<!DOCTYPE html>
<html lang="uk">
<head>
    <meta charset="UTF-8">
    <title>Лабораторна 6 — JWT Аутентифікація</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 40px auto; line-height: 1.5; }
        .box { border: 1px solid #ccc; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        input { width: 95%; padding: 8px; margin: 6px 0 12px; }
        button { padding: 10px 16px; cursor: pointer; background: #0066cc; color: white; border: none; border-radius: 4px; }
        textarea { width: 95%; height: 80px; margin-top: 10px; font-family: monospace; }
        .status { margin-top: 12px; font-weight: bold; }
    </style>
</head>
<body>
    <h2>Аутентифікація користувача за JWT-токеном</h2>

    <div class="box">
        <h3>1. Вхід (Отримання токена на 2 хв)</h3>
        <label>Логін (тестовий: <b>admin</b>):</label>
        <input type="text" id="username" value="admin">
        <label>Пароль (тестовий: <b>12345</b>):</label>
        <input type="password" id="password" value="12345">
        <button onclick="login()">Увійти та отримати токен</button>
        <div id="loginStatus" class="status"></div>
        <textarea id="tokenBox" placeholder="Тут з'явиться ваш JWT токен..."></textarea>
    </div>

    <div class="box">
        <h3>2. Доступ до захищеного ресурсу по токену</h3>
        <button onclick="getSecretData()">Перевірити токен на сервері</button>
        <div id="authStatus" class="status"></div>
    </div>

    <script>
        async function login() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;

            const response = await fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            const statusEl = document.getElementById('loginStatus');
            if (response.ok) {
                const data = await response.json();
                document.getElementById('tokenBox').value = data.token;
                statusEl.style.color = 'green';
                statusEl.innerText = 'Успішно! Токен видано (дійсний 2 хвилини).';
            } else {
                statusEl.style.color = 'red';
                statusEl.innerText = 'Помилка: Невірний логін або пароль.';
            }
        }

        async function getSecretData() {
            const token = document.getElementById('tokenBox').value.trim();
            const statusEl = document.getElementById('authStatus');

            const response = await fetch('/protected', {
                method: 'GET',
                headers: { 'Authorization': 'Bearer ' + token }
            });

            if (response.ok) {
                const data = await response.json();
                statusEl.style.color = 'green';
                statusEl.innerText = 'Доступ дозволено! Відповідь сервера: ' + data.message;
            } else {
                statusEl.style.color = 'red';
                statusEl.innerText = 'Відмовлено в доступі (401): Токен недійсний або прострочений.';
            }
        }
    </script>
</body>
</html>
""", "text/html; charset=utf-8"));

app.MapPost("/login", (LoginRequest request) =>
{
    if (request.Username == "admin" && request.Password == "12345")
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, request.Username),
                new Claim(ClaimTypes.Role, "User")
            }),
            Expires = DateTime.UtcNow.AddMinutes(2),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(keyBytes),
                SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        var jwtString = tokenHandler.WriteToken(token);

        return Results.Ok(new { token = jwtString });
    }

    return Results.Unauthorized();
});

app.MapGet("/protected", (HttpContext context) =>
{
    var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
    if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
    {
        Console.WriteLine($"[{DateTime.Now}] LOG: Невдала спроба доступу — токен відсутній.");
        return Results.Unauthorized();
    }

    var token = authHeader.Substring("Bearer ".Length).Trim();
    var tokenHandler = new JwtSecurityTokenHandler();

    try
    {
        var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
            ValidateIssuer = false,
            ValidateAudience = false,
            ClockSkew = TimeSpan.Zero
        }, out _);

        var username = principal.Identity?.Name;
        return Results.Ok(new { message = $"Вітаємо, {username}! Ви успішно пройшли аутентифікацію по токену." });
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[{DateTime.Now}] LOG: Невдала спроба використання токена! Причина: {ex.Message}");
        return Results.Unauthorized();
    }
});

app.Run();

record LoginRequest(string Username, string Password);