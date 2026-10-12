using System.Text.Json;
using Microsoft.EntityFrameworkCore;

namespace S3Local.Data;

public record BucketSummaryDto(string Name, string Region, string? Owner, DateTime CreatedAt, int ObjectCount, long TotalBytes);

public interface IMetadataStore
{
    Task<S3ObjectMetadata> UpsertAsync(string bucket, string key, string etag, long size, string? contentType, IDictionary<string, string>? metadata, string? owner);
    Task<S3ObjectMetadata?> GetAsync(string bucket, string key);
    Task<bool> DeleteAsync(string bucket, string key);
    Task<List<BucketSummaryDto>> ListBucketsAsync();
    Task<bool> CreateBucketAsync(string bucket, string region = "us-east-1", string? owner = "dev-user");
    Task<bool> DeleteBucketAsync(string bucket);
    Task<List<S3ObjectMetadata>> ListObjectsAsync(string bucket, string? prefix = null);
}

public class SqliteMetadataStore : IMetadataStore
{
    private readonly S3DbContext _db;
    private readonly IConfiguration? _config;

    public SqliteMetadataStore(S3DbContext db, IConfiguration? config = null)
    {
        _db = db;
        _config = config;
    }

    public async Task<S3ObjectMetadata> UpsertAsync(string bucket, string key, string etag, long size, string? contentType, IDictionary<string, string>? metadata, string? owner)
    {
        // Ensure bucket exists
        var bucketEntity = await _db.Buckets.FirstOrDefaultAsync(b => b.Name.ToLower() == bucket.ToLower());
        if (bucketEntity == null)
        {
            bucketEntity = new S3Bucket
            {
                Name = bucket,
                Region = "us-east-1",
                Owner = owner ?? "dev-user",
                CreatedAt = DateTime.UtcNow
            };
            _db.Buckets.Add(bucketEntity);
        }

        var existing = await _db.Objects.FirstOrDefaultAsync(o => o.Bucket == bucket && o.Key == key);
        var metadataJson = metadata != null ? JsonSerializer.Serialize(metadata) : null;

        if (existing == null)
        {
            existing = new S3ObjectMetadata
            {
                Bucket = bucket,
                Key = key,
                ETag = etag,
                Size = size,
                ContentType = string.IsNullOrWhiteSpace(contentType) ? "application/octet-stream" : contentType,
                MetadataJson = metadataJson,
                Owner = owner,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };
            _db.Objects.Add(existing);
        }
        else
        {
            existing.ETag = etag;
            existing.Size = size;
            if (!string.IsNullOrWhiteSpace(contentType)) existing.ContentType = contentType;
            existing.MetadataJson = metadataJson;
            existing.UpdatedAt = DateTime.UtcNow;
        }

        await _db.SaveChangesAsync();
        return existing;
    }

    public async Task<S3ObjectMetadata?> GetAsync(string bucket, string key)
    {
        return await _db.Objects.AsNoTracking().FirstOrDefaultAsync(o => o.Bucket == bucket && o.Key == key);
    }

    public async Task<bool> DeleteAsync(string bucket, string key)
    {
        var existing = await _db.Objects.FirstOrDefaultAsync(o => o.Bucket == bucket && o.Key == key);
        if (existing == null) return false;

        _db.Objects.Remove(existing);
        await _db.SaveChangesAsync();
        return true;
    }

    public async Task<List<BucketSummaryDto>> ListBucketsAsync()
    {
        var existingBucketNames = (await _db.Buckets.Select(b => b.Name).ToListAsync())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        bool changes = false;

        // 1. Discover any existing buckets from filesystem DataRoot
        if (_config != null)
        {
            var dataRoot = _config.GetValue<string>("DataRoot") ?? "data/buckets";
            if (Directory.Exists(dataRoot))
            {
                foreach (var dir in Directory.GetDirectories(dataRoot))
                {
                    var dirName = Path.GetFileName(dir);
                    if (!string.IsNullOrWhiteSpace(dirName) && existingBucketNames.Add(dirName))
                    {
                        _db.Buckets.Add(new S3Bucket
                        {
                            Name = dirName,
                            Region = "us-east-1",
                            Owner = "dev-user",
                            CreatedAt = Directory.GetCreationTimeUtc(dir)
                        });
                        changes = true;
                    }
                }
            }
        }

        // 2. Also ensure any bucket in Objects table is represented in Buckets table
        var objectBuckets = await _db.Objects.Select(o => o.Bucket).Distinct().ToListAsync();
        foreach (var b in objectBuckets)
        {
            if (!string.IsNullOrWhiteSpace(b) && existingBucketNames.Add(b))
            {
                _db.Buckets.Add(new S3Bucket
                {
                    Name = b,
                    Region = "us-east-1",
                    Owner = "dev-user",
                    CreatedAt = DateTime.UtcNow
                });
                changes = true;
            }
        }

        if (changes)
        {
            await _db.SaveChangesAsync();
        }

        var buckets = await _db.Buckets.AsNoTracking().OrderBy(b => b.Name).ToListAsync();
        var objects = await _db.Objects.AsNoTracking().ToListAsync();

        var result = new List<BucketSummaryDto>();
        foreach (var b in buckets)
        {
            var bucketObjects = objects.Where(o => string.Equals(o.Bucket, b.Name, StringComparison.OrdinalIgnoreCase)).ToList();
            result.Add(new BucketSummaryDto(
                b.Name,
                b.Region,
                b.Owner,
                b.CreatedAt,
                bucketObjects.Count,
                bucketObjects.Sum(o => o.Size)
            ));
        }

        return result;
    }

    public async Task<bool> CreateBucketAsync(string bucket, string region = "us-east-1", string? owner = "dev-user")
    {
        var normalized = bucket.Trim();
        if (await _db.Buckets.AnyAsync(b => b.Name.ToLower() == normalized.ToLower()))
        {
            return false; // Already exists
        }

        _db.Buckets.Add(new S3Bucket
        {
            Name = normalized,
            Region = string.IsNullOrWhiteSpace(region) ? "us-east-1" : region,
            Owner = owner ?? "dev-user",
            CreatedAt = DateTime.UtcNow
        });

        await _db.SaveChangesAsync();

        // Ensure directory exists on disk
        if (_config != null)
        {
            var dataRoot = _config.GetValue<string>("DataRoot") ?? "data/buckets";
            var bucketDir = Path.Combine(dataRoot, normalized);
            Directory.CreateDirectory(bucketDir);
        }

        return true;
    }

    public async Task<bool> DeleteBucketAsync(string bucket)
    {
        var bucketEntity = await _db.Buckets.FirstOrDefaultAsync(b => b.Name.ToLower() == bucket.ToLower());
        if (bucketEntity != null)
        {
            _db.Buckets.Remove(bucketEntity);
        }

        var bucketObjects = await _db.Objects.Where(o => o.Bucket.ToLower() == bucket.ToLower()).ToListAsync();
        if (bucketObjects.Count > 0)
        {
            _db.Objects.RemoveRange(bucketObjects);
        }

        await _db.SaveChangesAsync();

        // Delete directory from disk
        if (_config != null)
        {
            var dataRoot = _config.GetValue<string>("DataRoot") ?? "data/buckets";
            var bucketDir = Path.Combine(dataRoot, bucket);
            if (Directory.Exists(bucketDir))
            {
                try { Directory.Delete(bucketDir, recursive: true); } catch { }
            }
        }

        return true;
    }

    public async Task<List<S3ObjectMetadata>> ListObjectsAsync(string bucket, string? prefix = null)
    {
        var query = _db.Objects.AsNoTracking().Where(o => o.Bucket.ToLower() == bucket.ToLower());

        if (!string.IsNullOrWhiteSpace(prefix))
        {
            query = query.Where(o => o.Key.StartsWith(prefix));
        }

        return await query.OrderBy(o => o.Key).ToListAsync();
    }
}
