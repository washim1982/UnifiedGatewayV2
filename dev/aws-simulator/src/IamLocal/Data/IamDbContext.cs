using Microsoft.EntityFrameworkCore;

namespace IamLocal.Data;

public class RoleEntity
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string Name { get; set; } = string.Empty;
    public string Arn { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string PoliciesJson { get; set; } = "[]";

    /// <summary>The role trust policy. Empty means nothing may assume this role.</summary>
    public string TrustPolicyJson { get; set; } = string.Empty;
}

public class IamDbContext : DbContext
{
    public IamDbContext(DbContextOptions<IamDbContext> options) : base(options) { }

    public DbSet<RoleEntity> Roles => Set<RoleEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.Entity<RoleEntity>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Name).IsUnique();
        });
    }
}
