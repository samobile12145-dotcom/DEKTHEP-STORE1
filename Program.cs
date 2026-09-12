using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Numerics;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Railway injects PORT at runtime. Bind to all interfaces so the service is reachable.
var port = Environment.GetEnvironmentVariable("PORT") ?? "8080";
builder.WebHost.UseUrls($"http://0.0.0.0:{port}");

// For persistent SQLite on Railway, mount a Volume at /data and set DATABASE_PATH=/data/keyauth.db.
var databasePath = Environment.GetEnvironmentVariable("DATABASE_PATH") ?? "keyauth.db";
var databaseDirectory = Path.GetDirectoryName(Path.GetFullPath(databasePath));
if (!string.IsNullOrWhiteSpace(databaseDirectory)) Directory.CreateDirectory(databaseDirectory);
builder.Services.AddDbContext<AppDb>(o => o.UseSqlite($"Data Source={databasePath}"));
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
var secret = Environment.GetEnvironmentVariable("JWT_SECRET")
    ?? builder.Configuration["Jwt:Secret"]
    ?? "change-this-development-secret-32chars-minimum";

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(o =>
{
    o.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = false, ValidateAudience = false, ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret))
    };
});
builder.Services.AddAuthorization();

var app = builder.Build();
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    db.Database.EnsureCreated();
    // Keep profile storage compatible with existing keyauth.db files.
    try
    {
        using var conn = db.Database.GetDbConnection();
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "CREATE TABLE IF NOT EXISTS Profiles (Id INTEGER PRIMARY KEY AUTOINCREMENT, Username TEXT NOT NULL UNIQUE, DisplayName TEXT NOT NULL DEFAULT '', Bio TEXT NOT NULL DEFAULT '', Avatar TEXT NOT NULL DEFAULT 'user', UpdatedAt TEXT NOT NULL)";
        cmd.ExecuteNonQuery();
        try { cmd.CommandText = "ALTER TABLE Profiles ADD COLUMN AvatarData TEXT NOT NULL DEFAULT ''"; cmd.ExecuteNonQuery(); } catch { }
    }
    catch { }
    // Migrate legacy password hashes created by older builds. Those hashes did not persist their salt,
    // so reset the existing admin credential to the current bootstrap password once.
    var existingAdmin = db.Admins.OrderBy(x => x.Id).FirstOrDefault();
    if (existingAdmin is not null && !existingAdmin.PasswordHash.StartsWith("v1$", StringComparison.Ordinal))
    {
        existingAdmin.PasswordHash = Hash("124578");
        if (existingAdmin.Username != "admin") existingAdmin.Username = "admin";
        db.SaveChanges();
    }
    if (!db.Admins.Any())
    {
        db.Admins.Add(new Admin { Username = "admin", PasswordHash = Hash("124578") });
        db.Apps.Add(new AppRecord { Name = "My Application", OwnerId = "OWNER-001", Version = "1.0", Description = "Demo application", Status = "active" });
        db.Subscriptions.Add(new Subscription { Name = "ค่าเริ่มต้น", Level = 1, Users = 0 });
        db.Settings.AddRange(
            new Setting { Key = "brand", Value = "KeyAuth" },
            new Setting { Key = "description", Value = "ระบบจัดการแอปพลิเคชันและ License" },
            new Setting { Key = "backgroundMode", Value = "arctic" },
            new Setting { Key = "backgroundColor", Value = "#061925" },
            new Setting { Key = "backgroundImage", Value = "" },
            new Setting { Key = "backgroundOverlay", Value = "0.18" }
        );
        db.SaveChanges();
    }
    // Upgrade databases created by the earlier starter build.
    try
    {
        using var conn = db.Database.GetDbConnection();
        conn.Open();
        using var check = conn.CreateCommand();
        check.CommandText = "SELECT COUNT(*) FROM pragma_table_info('Apps') WHERE name='Status'";
        var hasStatus = Convert.ToInt32(check.ExecuteScalar()) > 0;
        if (!hasStatus)
        {
            using var alter = conn.CreateCommand();
            alter.CommandText = "ALTER TABLE Apps ADD COLUMN Status TEXT NOT NULL DEFAULT 'active'";
            alter.ExecuteNonQuery();
        }
    }
    catch { /* Fresh databases already have the column. */ }
    if (!db.Licenses.Any() && db.Apps.Any())
    {
        db.Licenses.Add(new License { Key = "DEMO-KEY-1234", AppId = db.Apps.OrderBy(x => x.Id).Select(x => x.Id).First(), ExpiresAt = DateTime.UtcNow.AddDays(30), CreatedAt = DateTime.UtcNow, Status = "active", Note = "Demo key" });
        db.SaveChanges();
    }
}

app.UseDefaultFiles();
app.UseStaticFiles();
app.UseSwagger();
app.UseSwaggerUI();
app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/api/auth/login", (LoginRequest req) =>
{
    var ownerUsername = Environment.GetEnvironmentVariable("OWNER_USERNAME");
    var ownerPassword = Environment.GetEnvironmentVariable("OWNER_PASSWORD");

    if (string.IsNullOrWhiteSpace(ownerUsername) || string.IsNullOrWhiteSpace(ownerPassword))
        return Results.Problem("OWNER_USERNAME / OWNER_PASSWORD are not configured.", statusCode: 503);

    if (!SecureEquals(req.Username, ownerUsername) || !SecureEquals(req.Password, ownerPassword))
        return Results.Unauthorized();

    return Results.Ok(new { token = MakeToken(ownerUsername, "admin", 12, secret), username = ownerUsername, mode = "admin" });
});

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

// A real license-key sign-in flow for the client/dashboard view.
app.MapPost("/api/auth/license-login", async (LicenseLoginRequest req, AppDb db) =>
{
    var l = await db.Licenses.SingleOrDefaultAsync(x => x.Key == req.Key);
    if (l is null) return Results.BadRequest(new { message = "ไม่พบ License Key" });
    if (l.Status != "active" || l.ExpiresAt < DateTime.UtcNow) return Results.BadRequest(new { message = "License หมดอายุหรือถูกระงับ" });
    var appRecord = await db.Apps.FindAsync(l.AppId);
    if (appRecord is null) return Results.BadRequest(new { message = "ไม่พบแอปที่ผูกกับ License" });
    if (appRecord.Status != "active") return Results.BadRequest(new { message = "แอปพลิเคชันถูกหยุดชั่วคราว" });

    var username = string.IsNullOrWhiteSpace(req.HwId) ? $"license-{l.Id}" : req.HwId.Trim();
    var existing = await db.Sessions.FirstOrDefaultAsync(x => x.Username == username && x.Active);
    if (existing is null)
    {
        db.Sessions.Add(new Session { Username = username, Ip = "client", Active = true, LastSeen = DateTime.UtcNow });
        await db.SaveChangesAsync();
    }
    return Results.Ok(new { token = MakeToken(username, "client", 12, secret), username, appId = l.AppId, appName = appRecord.Name, license = l.Key, expiresAt = l.ExpiresAt, mode = "license" });
});

var api = app.MapGroup("/api").RequireAuthorization();
var adminApi = app.MapGroup("/api").RequireAuthorization(new AuthorizeAttribute { Roles = "admin" });
api.MapGet("/dashboard", async (AppDb db) => Results.Ok(new
{
    apps = await db.Apps.CountAsync(),
    licenses = await db.Licenses.CountAsync(),
    activeLicenses = await db.Licenses.CountAsync(x => x.Status == "active" && x.ExpiresAt >= DateTime.UtcNow),
    sessions = await db.Sessions.CountAsync(x => x.Active),
    users = await db.Users.CountAsync(),
    pausedApps = await db.Apps.CountAsync(x => x.Status == "paused")
}));

api.MapGet("/apps", async (AppDb db) => Results.Ok(await db.Apps.OrderByDescending(x => x.Id).ToListAsync()));
adminApi.MapPost("/apps", async (AppRecord item, AppDb db) =>
{
    item.Id = 0;
    item.Name = string.IsNullOrWhiteSpace(item.Name) ? "New Application" : item.Name.Trim();
    if (string.IsNullOrWhiteSpace(item.OwnerId)) item.OwnerId = "OWNER-" + RandomNumberGenerator.GetInt32(100000, 999999);
    if (string.IsNullOrWhiteSpace(item.Version)) item.Version = "1.0";
    item.Status = "active";
    db.Apps.Add(item); await db.SaveChangesAsync(); return Results.Ok(item);
});
adminApi.MapPut("/apps/{id:int}", async (int id, AppRecord input, AppDb db) =>
{
    var x = await db.Apps.FindAsync(id); if (x is null) return Results.NotFound();
    x.Name = input.Name.Trim(); x.Version = input.Version.Trim(); x.Description = input.Description ?? "";
    await db.SaveChangesAsync(); return Results.Ok(x);
});
adminApi.MapPost("/apps/{id:int}/toggle", async (int id, AppDb db) =>
{
    var x = await db.Apps.FindAsync(id); if (x is null) return Results.NotFound();
    x.Status = x.Status == "active" ? "paused" : "active";
    await db.SaveChangesAsync(); return Results.Ok(x);
});
adminApi.MapDelete("/apps/{id:int}", async (int id, AppDb db) =>
{
    var x = await db.Apps.FindAsync(id); if (x is null) return Results.NotFound();
    db.Apps.Remove(x); await db.SaveChangesAsync(); return Results.NoContent();
});

api.MapGet("/licenses", async (AppDb db) => Results.Ok(await db.Licenses.OrderByDescending(x => x.Id).ToListAsync()));
adminApi.MapPost("/licenses", async (LicenseCreate req, AppDb db, CancellationToken ct) =>
{
    if (req.AppId <= 0 || !await db.Apps.AnyAsync(x => x.Id == req.AppId, ct))
        return Results.BadRequest(new { message = "ไม่พบแอปที่เลือก" });

    if (req.Count < 1)
        return Results.BadRequest(new { message = "จำนวนใบอนุญาตต้องมากกว่า 0" });

    var mask = string.IsNullOrWhiteSpace(req.Mask) ? "KEYAUTH******" : req.Mask.Trim();
    var wildcardCount = mask.Count(c => c == '*');
    if (wildcardCount == 0)
        return Results.BadRequest(new { message = "หน้ากากใบอนุญาตต้องมี * อย่างน้อย 1 ตัว" });

    var charset = BuildKeyCharset(req.Lowercase, req.Uppercase);
    var capacity = BigInteger.Pow(charset.Length, wildcardCount);
    if (new BigInteger(req.Count) > capacity)
        return Results.BadRequest(new { message = $"หน้ากากนี้สร้างคีย์ไม่ซ้ำได้สูงสุด {capacity:N0} แบบ กรุณาเพิ่ม *" });

    var unit = (req.Unit ?? "days").Trim().ToLowerInvariant();
    if (unit is not ("minutes" or "hours" or "days"))
        return Results.BadRequest(new { message = "หน่วยหมดอายุไม่ถูกต้อง" });

    var duration = req.Duration > 0 ? req.Duration : 1;
    var expiresAt = unit switch
    {
        "minutes" => DateTime.UtcNow.AddMinutes(duration),
        "hours" => DateTime.UtcNow.AddHours(duration),
        _ => DateTime.UtcNow.AddDays(duration)
    };

    var used = new HashSet<string>(
        await db.Licenses.AsNoTracking().Select(x => x.Key).ToListAsync(ct),
        StringComparer.OrdinalIgnoreCase);

    // No artificial limit such as 1 or 500. Practical limits are the DB,
    // machine resources, and the number of unique combinations in the mask.
    var previewKeys = new List<string>(Math.Min(req.Count, 200));
    var returnKeys = req.Count <= 10000 ? new List<string>(req.Count) : null;
    const int batchSize = 1000;
    var created = 0;

    await using var tx = await db.Database.BeginTransactionAsync(ct);

    while (created < req.Count)
    {
        var take = Math.Min(batchSize, req.Count - created);

        for (var i = 0; i < take; i++)
        {
            string key;
            var attempts = 0;
            do
            {
                key = CreateMaskedKey(mask, req.Lowercase, req.Uppercase);
                if (++attempts > 10000)
                    return Results.BadRequest(new { message = "ไม่สามารถสร้างคีย์ที่ไม่ซ้ำได้จากหน้ากากนี้ กรุณาเพิ่ม *" });
            } while (!used.Add(key));

            if (previewKeys.Count < 200)
                previewKeys.Add(key);
            returnKeys?.Add(key);

            db.Licenses.Add(new License
            {
                Key = key,
                AppId = req.AppId,
                ExpiresAt = expiresAt,
                Status = "active",
                CreatedAt = DateTime.UtcNow,
                Note = req.Note ?? ""
            });
        }

        await db.SaveChangesAsync(ct);
        db.ChangeTracker.Clear();
        created += take;
    }

    await tx.CommitAsync(ct);

    return Results.Ok(new
    {
        success = true,
        count = created,
        previewKeys,
        keys = returnKeys,
        expiresAt,
        message = $"สร้างใบอนุญาตสำเร็จ {created:N0} คีย์"
    });
});
adminApi.MapPost("/licenses/delete-selected", async (int[] ids, AppDb db, CancellationToken ct) =>
{
    var cleanIds = (ids ?? Array.Empty<int>()).Where(x => x > 0).Distinct().ToArray();
    if (cleanIds.Length == 0) return Results.BadRequest(new { message = "กรุณาเลือก License อย่างน้อย 1 รายการ" });
    var deleted = await db.Licenses.Where(x => cleanIds.Contains(x.Id)).ExecuteDeleteAsync(ct);
    return Results.Ok(new { deleted });
});
adminApi.MapDelete("/licenses-all", async (AppDb db, CancellationToken ct) =>
{
    var deleted = await db.Licenses.ExecuteDeleteAsync(ct);
    return Results.Ok(new { deleted });
});

adminApi.MapPut("/licenses/{id:int}", async (int id, LicenseUpdate req, AppDb db) =>
{
    var x = await db.Licenses.FindAsync(id); if (x is null) return Results.NotFound();
    x.Status = req.Status; x.Note = req.Note ?? x.Note; await db.SaveChangesAsync(); return Results.Ok(x);
});
adminApi.MapDelete("/licenses/{id:int}", async (int id, AppDb db) =>
{
    var x = await db.Licenses.FindAsync(id); if (x is null) return Results.NotFound();
    db.Licenses.Remove(x); await db.SaveChangesAsync(); return Results.NoContent();
});

api.MapGet("/users", async (AppDb db) => Results.Ok(await db.Users.OrderByDescending(x => x.Id).ToListAsync()));
adminApi.MapPost("/users", async (User u, AppDb db) => { u.Id = 0; db.Users.Add(u); await db.SaveChangesAsync(); return Results.Ok(u); });
adminApi.MapDelete("/users/{id:int}", async (int id, AppDb db) => { var x = await db.Users.FindAsync(id); if (x is null) return Results.NotFound(); db.Users.Remove(x); await db.SaveChangesAsync(); return Results.NoContent(); });

api.MapGet("/tokens", async (AppDb db) => Results.Ok(await db.Tokens.OrderByDescending(x => x.Id).ToListAsync()));
adminApi.MapPost("/tokens", async (Token t, AppDb db) => { t.Id = 0; if (string.IsNullOrWhiteSpace(t.Value)) t.Value = CreateKey(); db.Tokens.Add(t); await db.SaveChangesAsync(); return Results.Ok(t); });
adminApi.MapDelete("/tokens/{id:int}", async (int id, AppDb db) => { var x = await db.Tokens.FindAsync(id); if (x is null) return Results.NotFound(); db.Tokens.Remove(x); await db.SaveChangesAsync(); return Results.NoContent(); });

api.MapGet("/subscriptions", async (AppDb db) => Results.Ok(await db.Subscriptions.ToListAsync()));
adminApi.MapPost("/subscriptions", async (Subscription s, AppDb db) => { s.Id = 0; db.Subscriptions.Add(s); await db.SaveChangesAsync(); return Results.Ok(s); });
adminApi.MapDelete("/subscriptions/{id:int}", async (int id, AppDb db) => { var x = await db.Subscriptions.FindAsync(id); if (x is null) return Results.NotFound(); db.Subscriptions.Remove(x); await db.SaveChangesAsync(); return Results.NoContent(); });

api.MapGet("/sessions", async (AppDb db) => Results.Ok(await db.Sessions.OrderByDescending(x => x.Id).ToListAsync()));
adminApi.MapPost("/sessions/{id:int}/toggle", async (int id, AppDb db) => { var x = await db.Sessions.FindAsync(id); if (x is null) return Results.NotFound(); x.Active = !x.Active; x.LastSeen = DateTime.UtcNow; await db.SaveChangesAsync(); return Results.Ok(x); });
adminApi.MapDelete("/sessions/{id:int}", async (int id, AppDb db) => { var x = await db.Sessions.FindAsync(id); if (x is null) return Results.NotFound(); db.Sessions.Remove(x); await db.SaveChangesAsync(); return Results.NoContent(); });

api.MapGet("/profile", async (ClaimsPrincipal user, AppDb db) =>
{
    var username = user.Identity?.Name ?? "admin";
    var p = await db.Profiles.SingleOrDefaultAsync(x => x.Username == username);
    if (p is null)
    {
        p = new Profile { Username = username, DisplayName = username, Bio = "", Avatar = "user", UpdatedAt = DateTime.UtcNow };
        db.Profiles.Add(p);
        await db.SaveChangesAsync();
    }
    return Results.Ok(new { username = p.Username, displayName = p.DisplayName, bio = p.Bio, avatar = p.Avatar, avatarData = p.AvatarData, updatedAt = p.UpdatedAt });
});
api.MapPut("/profile", async (ClaimsPrincipal user, ProfileUpdate req, AppDb db) =>
{
    var username = user.Identity?.Name ?? "admin";
    var p = await db.Profiles.SingleOrDefaultAsync(x => x.Username == username);
    if (p is null)
    {
        p = new Profile { Username = username };
        db.Profiles.Add(p);
    }
    p.DisplayName = string.IsNullOrWhiteSpace(req.DisplayName) ? username : req.DisplayName.Trim();
    p.Bio = (req.Bio ?? "").Trim();
    p.Avatar = string.IsNullOrWhiteSpace(req.Avatar) ? "user" : req.Avatar.Trim();
    p.AvatarData = req.AvatarData ?? "";
    if (!string.IsNullOrEmpty(p.AvatarData))
    {
        if (p.AvatarData.Length > 1400000 || !p.AvatarData.StartsWith("data:image/", StringComparison.OrdinalIgnoreCase))
            return Results.BadRequest(new { message = "รูปโปรไฟล์ไม่ถูกต้องหรือมีขนาดใหญ่เกินไป" });
    }
    p.UpdatedAt = DateTime.UtcNow;
    await db.SaveChangesAsync();
    return Results.Ok(new { username = p.Username, displayName = p.DisplayName, bio = p.Bio, avatar = p.Avatar, avatarData = p.AvatarData, updatedAt = p.UpdatedAt });
});
api.MapPut("/profile/password", (ClaimsPrincipal user, PasswordUpdate req) =>
{
    if (user.IsInRole("client")) return Results.BadRequest(new { message = "License session ไม่สามารถเปลี่ยนรหัสผ่านได้" });
    return Results.BadRequest(new { message = "บัญชี Owner ใช้ Railway Variables กรุณาเปลี่ยน OWNER_PASSWORD ใน Railway แล้ว Redeploy" });
});

api.MapGet("/settings", async (AppDb db) => Results.Ok(await db.Settings.ToDictionaryAsync(x => x.Key, x => x.Value)));
adminApi.MapPut("/settings", async (Dictionary<string, string> values, AppDb db) =>
{
    var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "brand", "description", "backgroundMode", "backgroundColor", "backgroundImage", "backgroundOverlay" };
    foreach (var kv in values)
    {
        if (!allowed.Contains(kv.Key)) continue;
        var value = kv.Value ?? "";
        if (kv.Key.Equals("backgroundMode", StringComparison.OrdinalIgnoreCase) && !new[] { "arctic", "midnight", "ocean", "solid", "image" }.Contains(value, StringComparer.OrdinalIgnoreCase))
            return Results.BadRequest(new { message = "รูปแบบพื้นหลังไม่ถูกต้อง" });
        if (kv.Key.Equals("backgroundColor", StringComparison.OrdinalIgnoreCase) && !(value.Length == 7 && value[0] == '#' && value.Skip(1).All(Uri.IsHexDigit)))
            return Results.BadRequest(new { message = "สีพื้นหลังไม่ถูกต้อง" });
        if (kv.Key.Equals("backgroundOverlay", StringComparison.OrdinalIgnoreCase) && (!double.TryParse(value, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var ov) || ov < 0 || ov > 0.75))
            return Results.BadRequest(new { message = "ค่าความเข้ม Overlay ต้องอยู่ระหว่าง 0 ถึง 0.75" });
        if (kv.Key.Equals("backgroundImage", StringComparison.OrdinalIgnoreCase) && value.Length > 2800000)
            return Results.BadRequest(new { message = "รูปพื้นหลังใหญ่เกินไป (สูงสุดประมาณ 2 MB)" });
        if (kv.Key.Equals("backgroundImage", StringComparison.OrdinalIgnoreCase) && value.Length > 0 && !value.StartsWith("data:image/", StringComparison.OrdinalIgnoreCase))
            return Results.BadRequest(new { message = "รูปพื้นหลังไม่ถูกต้อง" });
        var s = await db.Settings.SingleOrDefaultAsync(x => x.Key == kv.Key);
        if (s is null) db.Settings.Add(new Setting { Key = kv.Key, Value = value }); else s.Value = value;
    }
    await db.SaveChangesAsync(); return Results.Ok(await db.Settings.ToDictionaryAsync(x => x.Key, x => x.Value));
});

// Public endpoint intended for real desktop/mobile clients.
app.MapPost("/client/license/validate", async (ValidateRequest req, AppDb db) =>
{
    var l = await db.Licenses.SingleOrDefaultAsync(x => x.Key == req.Key);
    if (l is null) return Results.Ok(new { success = false, message = "License not found" });
    if (l.Status != "active" || l.ExpiresAt < DateTime.UtcNow) return Results.Ok(new { success = false, message = "License expired or disabled" });
    var ar = await db.Apps.FindAsync(l.AppId);
    if (ar is null || ar.Status != "active") return Results.Ok(new { success = false, message = "Application disabled" });
    return Results.Ok(new { success = true, license = l.Key, appId = l.AppId, appName = ar.Name, expiresAt = l.ExpiresAt, note = l.Note });
});

app.MapFallbackToFile("index.html");
app.Run();

static string MakeToken(string name, string role, int hours, string secret)
{
    var claims = new[] { new Claim(ClaimTypes.Name, name), new Claim(ClaimTypes.Role, role) };
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
    var token = new JwtSecurityToken(claims: claims, expires: DateTime.UtcNow.AddHours(hours), signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256));
    return new JwtSecurityTokenHandler().WriteToken(token);
}
static bool SecureEquals(string? a, string? b)
{
    if (a is null || b is null) return false;
    var ab = Encoding.UTF8.GetBytes(a);
    var bb = Encoding.UTF8.GetBytes(b);
    return ab.Length == bb.Length && CryptographicOperations.FixedTimeEquals(ab, bb);
}

static string Hash(string s)
{
    var salt = RandomNumberGenerator.GetBytes(16);
    var hash = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(s), salt, 120000, HashAlgorithmName.SHA256, 32);
    return $"v1${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
}
static bool Verify(string s, string h)
{
    try
    {
        var parts = h.Split('$');
        if (parts.Length == 3 && parts[0] == "v1")
        {
            var salt = Convert.FromBase64String(parts[1]);
            var expected = Convert.FromBase64String(parts[2]);
            var actual = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(s), salt, 120000, HashAlgorithmName.SHA256, expected.Length);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        return false;
    }
    catch { return false; }
}
static string CreateKey() => "KEYAUTH-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
static string BuildKeyCharset(bool lowercase, bool uppercase)
{
    var chars = (lowercase ? "abcdefghijklmnopqrstuvwxyz" : "") +
                (uppercase ? "ABCDEFGHIJKLMNOPQRSTUVWXYZ" : "") +
                "0123456789";
    return chars.Length == 10 ? "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" : chars;
}
static string CreateMaskedKey(string? mask, bool lowercase, bool uppercase)
{
    mask = string.IsNullOrWhiteSpace(mask) ? "KEYAUTH******" : mask.Trim();
    var chars = BuildKeyCharset(lowercase, uppercase);
    var output = new char[mask.Length];
    var bytes = RandomNumberGenerator.GetBytes(mask.Length);
    for (int i = 0; i < mask.Length; i++)
        output[i] = mask[i] == '*' ? chars[bytes[i] % chars.Length] : mask[i];
    return new string(output);
}

record LoginRequest(string Username, string Password);
record LicenseLoginRequest(string Key, string? HwId);
record LicenseCreate(int AppId, int Duration, string? Note, int Count = 1, string? Mask = "KEYAUTH******", bool Lowercase = false, bool Uppercase = false, int Level = 1, string? Unit = "days");
record LicenseUpdate(string Status, string? Note);
record ValidateRequest(string Key, string? HwId);
record ProfileUpdate(string? DisplayName, string? Bio, string? Avatar, string? AvatarData);
record PasswordUpdate(string CurrentPassword, string NewPassword);
class AppDb : DbContext
{
    public AppDb(DbContextOptions<AppDb> o) : base(o) { }
    public DbSet<Admin> Admins => Set<Admin>(); public DbSet<Profile> Profiles => Set<Profile>(); public DbSet<AppRecord> Apps => Set<AppRecord>(); public DbSet<License> Licenses => Set<License>(); public DbSet<User> Users => Set<User>(); public DbSet<Token> Tokens => Set<Token>(); public DbSet<Subscription> Subscriptions => Set<Subscription>(); public DbSet<Session> Sessions => Set<Session>(); public DbSet<Setting> Settings => Set<Setting>();
}
class Admin { public int Id { get; set; } public string Username { get; set; } = ""; public string PasswordHash { get; set; } = ""; }
class Profile { public int Id { get; set; } public string Username { get; set; } = ""; public string DisplayName { get; set; } = ""; public string Bio { get; set; } = ""; public string Avatar { get; set; } = "user"; public string AvatarData { get; set; } = ""; public DateTime UpdatedAt { get; set; } = DateTime.UtcNow; }
class AppRecord { public int Id { get; set; } public string Name { get; set; } = ""; public string OwnerId { get; set; } = ""; public string Version { get; set; } = "1.0"; public string Description { get; set; } = ""; public string Status { get; set; } = "active"; }
class License { public int Id { get; set; } public string Key { get; set; } = ""; public int AppId { get; set; } public DateTime CreatedAt { get; set; } public DateTime ExpiresAt { get; set; } public string Status { get; set; } = "active"; public string Note { get; set; } = ""; }
class User { public int Id { get; set; } public string Username { get; set; } = ""; public string Ip { get; set; } = ""; public string Status { get; set; } = "active"; }
class Token { public int Id { get; set; } public string Value { get; set; } = ""; public string AssignedTo { get; set; } = ""; public string Type { get; set; } = "license"; public string Status { get; set; } = "active"; }
class Subscription { public int Id { get; set; } public string Name { get; set; } = ""; public int Level { get; set; } public int Users { get; set; } }
class Session { public int Id { get; set; } public string Username { get; set; } = ""; public string Ip { get; set; } = ""; public bool Active { get; set; } = true; public DateTime LastSeen { get; set; } = DateTime.UtcNow; }
class Setting { public int Id { get; set; } public string Key { get; set; } = ""; public string Value { get; set; } = ""; }
