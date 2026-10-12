using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Shared.Models;

namespace IamLocal.Data;

public interface IRoleStore
{
    Task<IamRole?> GetRoleByNameAsync(string name);
    Task AddOrUpdateRoleAsync(IamRole role);
    Task SeedDefaultRolesAsync();
}

public class SqliteRoleStore : IRoleStore
{
    private readonly IamDbContext _db;
    private readonly ILogger<SqliteRoleStore> _logger;
    private static readonly SemaphoreSlim _seedLock = new(1, 1);

    public SqliteRoleStore(IamDbContext db, ILogger<SqliteRoleStore> logger)
    {
        _db = db;
        _logger = logger;
    }

    public async Task<IamRole?> GetRoleByNameAsync(string name)
    {
        var entity = await _db.Roles.AsNoTracking().FirstOrDefaultAsync(r => r.Name.ToLower() == name.ToLower());
        if (entity == null) return null;

        return new IamRole
        {
            Id = entity.Id,
            Name = entity.Name,
            Arn = entity.Arn,
            Description = entity.Description,
            Policies = JsonSerializer.Deserialize<List<IamPolicy>>(entity.PoliciesJson) ?? new(),
            TrustPolicy = string.IsNullOrWhiteSpace(entity.TrustPolicyJson)
                ? null
                : JsonSerializer.Deserialize<RoleTrustPolicy>(entity.TrustPolicyJson)
        };
    }

    public async Task AddOrUpdateRoleAsync(IamRole role)
    {
        var entity = await _db.Roles.FirstOrDefaultAsync(r => r.Name.ToLower() == role.Name.ToLower());
        if (entity == null)
        {
            entity = new RoleEntity
            {
                Id = role.Id,
                Name = role.Name,
                Arn = role.Arn,
                Description = role.Description,
                PoliciesJson = JsonSerializer.Serialize(role.Policies),
                TrustPolicyJson = SerializeTrustPolicy(role)
            };
            _db.Roles.Add(entity);
        }
        else
        {
            entity.Arn = role.Arn;
            entity.Description = role.Description;
            entity.PoliciesJson = JsonSerializer.Serialize(role.Policies);
            entity.TrustPolicyJson = SerializeTrustPolicy(role);
        }

        try
        {
            await _db.SaveChangesAsync();
        }
        catch (DbUpdateException ex)
        {
            _logger.LogDebug(ex, "Concurrency handled in AddOrUpdateRoleAsync for role {Role}", role.Name);
            _db.Entry(entity).State = EntityState.Detached;
            var reloaded = await _db.Roles.FirstOrDefaultAsync(r => r.Name.ToLower() == role.Name.ToLower());
            if (reloaded != null)
            {
                reloaded.Arn = role.Arn;
                reloaded.Description = role.Description;
                reloaded.PoliciesJson = JsonSerializer.Serialize(role.Policies);
                reloaded.TrustPolicyJson = SerializeTrustPolicy(role);
                await _db.SaveChangesAsync();
            }
        }
    }

    public async Task SeedDefaultRolesAsync()
    {
        await _seedLock.WaitAsync();
        try
        {
            await _db.Database.EnsureCreatedAsync();
            await EnsureTrustPolicyColumnAsync();

            var devRole = new IamRole
            {
                Name = "dev-role",
                Arn = "arn:aws:iam::123456789012:role/dev-role",
                Description = "Default developer role with full permissions for local simulation",
                Policies = new List<IamPolicy>
                {
                    new IamPolicy
                    {
                        Version = "2012-10-17",
                        Statement = new List<PolicyStatement>
                        {
                            new PolicyStatement
                            {
                                Sid = "AllowAllServices",
                                Effect = "Allow",
                                Action = new List<string> { "s3:*", "kms:*", "sts:*" },
                                Resource = new List<string> { "*" }
                            }
                        }
                    }
                }
            };

            var readOnlyRole = new IamRole
            {
                Name = "read-only-role",
                Arn = "arn:aws:iam::123456789012:role/read-only-role",
                Description = "Read-only role for S3 and KMS decryption",
                Policies = new List<IamPolicy>
                {
                    new IamPolicy
                    {
                        Version = "2012-10-17",
                        Statement = new List<PolicyStatement>
                        {
                            new PolicyStatement
                            {
                                Sid = "ReadOnlyAccess",
                                Effect = "Allow",
                                Action = new List<string> { "s3:Get*", "s3:List*", "kms:Decrypt" },
                                Resource = new List<string> { "*" }
                            }
                        }
                    }
                }
            };

            var adminRole = new IamRole
            {
                Name = "admin-role",
                Arn = "arn:aws:iam::123456789012:role/admin-role",
                Description = "Administrator role with wildcard permissions",
                Policies = new List<IamPolicy>
                {
                    new IamPolicy
                    {
                        Version = "2012-10-17",
                        Statement = new List<PolicyStatement>
                        {
                            new PolicyStatement
                            {
                                Sid = "AdministratorAccess",
                                Effect = "Allow",
                                Action = new List<string> { "*" },
                                Resource = new List<string> { "*" }
                            }
                        }
                    }
                }
            };

            // Trust policies, in the shape AWS requires. Roles Anywhere refuses a role whose
            // trust policy does not name the service principal with all three actions.
            devRole.TrustPolicy = RolesAnywhereTrustPolicy();
            adminRole.TrustPolicy = RolesAnywhereTrustPolicy();

            // Deliberately incomplete: sts:AssumeRole alone, with TagSession and
            // SetSourceIdentity missing. This is the most common Roles Anywhere
            // misconfiguration in production, where it surfaces as an unexplained 403.
            // Keeping one seeded role broken makes that failure reproducible on demand,
            // with a message that names the missing actions.
            readOnlyRole.TrustPolicy = new RoleTrustPolicy
            {
                Statement =
                [
                    new TrustStatement
                    {
                        Sid = "IntentionallyIncompleteForTesting",
                        Effect = "Allow",
                        Principal = new TrustPrincipal { Service = RoleTrustEvaluator.RolesAnywhereService },
                        Action = ["sts:AssumeRole"]
                    }
                ]
            };

            var rolesToSeed = new[] { devRole, readOnlyRole, adminRole };
            foreach (var role in rolesToSeed)
            {
                var existing = await _db.Roles.AsNoTracking().FirstOrDefaultAsync(r => r.Name.ToLower() == role.Name.ToLower());
                if (existing == null)
                {
                    await AddOrUpdateRoleAsync(role);
                }
            }
        }
        finally
        {
            _seedLock.Release();
        }
    }

    private static string SerializeTrustPolicy(IamRole role) =>
        role.TrustPolicy is null ? string.Empty : JsonSerializer.Serialize(role.TrustPolicy);

    /// <summary>The trust policy a Roles Anywhere role needs, matching the AWS documentation.</summary>
    private static RoleTrustPolicy RolesAnywhereTrustPolicy() => new()
    {
        Statement =
        [
            new TrustStatement
            {
                Sid = "AllowRolesAnywhere",
                Effect = "Allow",
                Principal = new TrustPrincipal { Service = RoleTrustEvaluator.RolesAnywhereService },
                Action = [.. RoleTrustEvaluator.RequiredActions]
            }
        ]
    };

    /// <summary>
    /// Adds the TrustPolicyJson column to an existing database.
    ///
    /// The simulator uses EnsureCreated rather than migrations, which creates a schema only
    /// when the file is absent and silently leaves an existing one alone. Without this, an
    /// already-provisioned dev database fails every role query with "no such column" after
    /// an upgrade -- and the obvious fix, deleting the database, throws away any roles that
    /// were seeded into it.
    /// </summary>
    private async Task EnsureTrustPolicyColumnAsync()
    {
        try
        {
            var columns = new List<string>();

            await using (var command = _db.Database.GetDbConnection().CreateCommand())
            {
                command.CommandText = "SELECT name FROM pragma_table_info('Roles');";
                await _db.Database.OpenConnectionAsync();

                await using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    columns.Add(reader.GetString(0));
                }
            }

            if (columns.Count > 0 && !columns.Contains("TrustPolicyJson"))
            {
                await _db.Database.ExecuteSqlRawAsync(
                    "ALTER TABLE Roles ADD COLUMN TrustPolicyJson TEXT NOT NULL DEFAULT '';");

                _logger.LogInformation(
                    "Added the TrustPolicyJson column to an existing Roles table. Seeded roles " +
                    "will have their trust policies populated; any roles you added yourself now " +
                    "have no trust policy and cannot be assumed until one is set.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not verify the Roles table schema.");
        }
        finally
        {
            await _db.Database.CloseConnectionAsync();
        }
    }
}
