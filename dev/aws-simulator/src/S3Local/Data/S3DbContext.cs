using Microsoft.EntityFrameworkCore;

namespace S3Local.Data;

public class S3Bucket
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Region { get; set; } = "us-east-1";
    public string? Owner { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

public class S3ObjectMetadata
{
    public int Id { get; set; }
    public string Bucket { get; set; } = string.Empty;
    public string Key { get; set; } = string.Empty;
    public string ETag { get; set; } = string.Empty;
    public long Size { get; set; }
    public string ContentType { get; set; } = "application/octet-stream";
    public string? MetadataJson { get; set; }
    public string? Owner { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}

public class S3DbContext : DbContext
{
    public S3DbContext(DbContextOptions<S3DbContext> options) : base(options) { }

    public DbSet<S3Bucket> Buckets => Set<S3Bucket>();
    public DbSet<S3ObjectMetadata> Objects => Set<S3ObjectMetadata>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.Entity<S3Bucket>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Name).IsUnique();
        });

        modelBuilder.Entity<S3ObjectMetadata>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => new { e.Bucket, e.Key }).IsUnique();
        });
    }
}
