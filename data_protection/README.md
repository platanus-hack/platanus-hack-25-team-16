# Data Protection App - Searchable Encryption for Django

## Overview

The `data_protection` app provides **ISO27001 A.10.1 compliant** cryptographic controls for Django, implementing searchable encryption that protects sensitive data at rest while maintaining query capabilities.

## Features

- **🔒 Strong Encryption**: Uses Fernet (AES-128 CBC) for data encryption
- **🔍 Searchable**: Supports substring searches on encrypted data using n-gram indexing
- **📋 ISO27001 Compliant**: Meets cryptographic control requirements (A.10.1)
- **🎯 Transparent**: Automatic encryption/decryption - works like regular Django fields
- **🔑 Key Management**: Secure key derivation using PBKDF2-HMAC-SHA256
- **⚡ Production-Ready**: Optimized for real-world performance

## Architecture

### How It Works

1. **Data Encryption**:
   - Plaintext is encrypted using Fernet (AES-128 CBC mode)
   - Encrypted data stored with version prefix: `v1:gAAAAABhX...`
   - Supports future key rotation

2. **Searchable Index**:
   - N-grams (trigrams by default) generated from plaintext
   - Each n-gram is hashed with a secret salt (SHA-256)
   - Hashed n-grams stored in separate `_search_index` field
   - Search queries hash search terms and match against stored hashes

3. **Database Schema**:
   ```
   username (CharField):              "v1:gAAAAABhX2jK..."  [encrypted]
   username_search_index (TextField): "a3f2e1d4c5b6... d3c2b1a9e8f7..." [hashed n-grams]
   ```

### Security Properties

✅ **Data at Rest Protection**: All sensitive data encrypted in database
✅ **Search Privacy**: Search patterns not directly observable
✅ **No Plaintext Exposure**: Search index uses one-way hashes
✅ **Salt Protection**: Hashes salted to prevent rainbow tables
✅ **Key Derivation**: NIST-compliant PBKDF2 (100,000 iterations)

❌ **Known Limitations**:
- Search index size correlates with plaintext length (metadata leakage)
- Frequency analysis possible on search index patterns
- Not suitable for highly sensitive data requiring full homomorphic encryption

## Installation

### 1. Install Dependencies

```bash
pip install cryptography
# or if using poetry/pipenv
poetry add cryptography
```

### 2. Add to INSTALLED_APPS

The app should already be in your `settings.py`:

```python
INSTALLED_APPS = [
    ...
    'data_protection',  # Cryptographic controls (ISO27001 A.10.1)
]
```

### 3. Configuration (Optional)

Default configuration in `settings.py`:

```python
# Optional: Provide dedicated encryption key
# Generate with: from cryptography.fernet import Fernet; print(Fernet.generate_key())
DATA_PROTECTION_KEY = None  # Uses SECRET_KEY if not set

# Optional: Custom search salt
DATA_PROTECTION_SEARCH_SALT = None  # Uses SECRET_KEY if not set

# N-gram configuration
DATA_PROTECTION = {
    'NGRAM_SIZE': 3,  # Trigrams
    'MIN_SEARCH_LENGTH': 2,
    'KEY_VERSION': 'v1',
}
```

## Usage

### Basic Usage

```python
from django.db import models
from data_protection.fields import EncryptedTextField, EncryptedCharField


class User(models.Model):
    # Encrypted with search capability
    username = EncryptedCharField(max_length=50, searchable=True)
    email = EncryptedTextField(searchable=True)

    # Encrypted WITHOUT search (more secure)
    ssn = EncryptedCharField(max_length=20, searchable=False)

    # Regular non-encrypted field
    created_at = models.DateTimeField(auto_now_add=True)
```

### Creating Records

```python
# Create - encryption happens automatically
user = User.objects.create(
    username='john_doe',
    email='john@example.com',
    ssn='123-45-6789'
)

# Access - decryption happens automatically
print(user.username)  # "john_doe" (decrypted transparently)
```

### Querying Encrypted Fields

```python
# Substring search (case-insensitive)
users = User.objects.filter(username__icontains='john')

# Substring search (case-sensitive)
users = User.objects.filter(email__contains='example.com')

# Exact match (also works)
user = User.objects.get(username='john_doe')

# ⚠️ Not supported: Complex queries
# users = User.objects.filter(username__startswith='j')  # Won't work as expected
# users = User.objects.filter(username__regex=r'^j.*')   # Won't work
```

### Supported Query Operations

| Operation | Supported | Notes |
|-----------|-----------|-------|
| `__contains` | ✅ Yes | Case-sensitive substring search |
| `__icontains` | ✅ Yes | Case-insensitive substring search |
| `__exact` | ✅ Yes | Exact match |
| `=` (equality) | ✅ Yes | Exact match |
| `__startswith` | ⚠️ Partial | Works if search term ≥ NGRAM_SIZE |
| `__endswith` | ⚠️ Partial | Works if search term ≥ NGRAM_SIZE |
| `__regex` | ❌ No | Not supported |
| `__gt`, `__lt` | ❌ No | Not supported (no order) |

## Field Reference

### EncryptedTextField

A `TextField` with automatic encryption and optional search index.

```python
field = EncryptedTextField(
    searchable=True,     # Enable substring searches (default: True)
    blank=False,         # Standard TextField options
    null=False,
    help_text="Encrypted field"
)
```

**Database Impact**:
- Main field: Stores encrypted data (increases ~50% in size)
- If `searchable=True`: Creates `{field_name}_search_index` TextField

### EncryptedCharField

A `CharField` with automatic encryption and optional search index.

```python
field = EncryptedCharField(
    max_length=50,       # Note: Encrypted data needs ~2x space
    searchable=True,     # Enable substring searches (default: True)
    blank=False,
    null=False
)
```

**Important**: The `max_length` is automatically doubled internally to accommodate encrypted data overhead.

## Best Practices

### ✅ DO

- **Encrypt PII**: Names, emails, addresses, phone numbers
- **Use `searchable=False`** for highly sensitive data (SSN, credit cards)
- **Index search fields** explicitly for better performance:
  ```python
  class Meta:
      indexes = [
          models.Index(fields=['username_search_index']),
      ]
  ```
- **Rotate encryption keys** periodically (use version prefix support)
- **Use dedicated `DATA_PROTECTION_KEY`** in production
- **Store keys securely** (environment variables, secrets manager)

### ❌ DON'T

- **Don't encrypt** fields used for complex queries (dates, numbers, foreign keys)
- **Don't encrypt** data that doesn't need protection (public information)
- **Don't assume** perfect security - understand the threat model
- **Don't use** for compliance requiring full homomorphic encryption
- **Don't query** on non-indexed search fields with large datasets

## Performance Considerations

### Encryption Overhead

- **Encryption/Decryption**: ~0.1ms per field (negligible)
- **Storage**: ~50% size increase for encrypted data
- **Search Index**: Additional storage for n-gram hashes

### Query Performance

- **Indexed search fields**: O(log n) lookup (fast)
- **Non-indexed search fields**: O(n) scan (slow for large tables)
- **Multiple search conditions**: Use Q objects efficiently

### Optimization Tips

```python
# ✅ Good: Indexed field search
User.objects.filter(username_search_index__contains=hash)

# ✅ Good: Limit results
User.objects.filter(email__icontains='example')[:100]

# ⚠️ Caution: Multiple encrypted field searches
User.objects.filter(
    username__icontains='john',
    email__icontains='example'
)  # Two index scans

# ❌ Bad: Searching non-searchable field
User.objects.filter(ssn__contains='123')  # Won't work!
```

## ISO27001 Compliance

This app implements controls from:

### A.10.1 - Cryptographic Controls

✅ **A.10.1.1** - Policy on the use of cryptographic controls
✅ **A.10.1.2** - Key management

**Implementation**:
- Encryption algorithm: Fernet (AES-128 CBC + HMAC-SHA256)
- Key derivation: PBKDF2-HMAC-SHA256 (100,000 iterations)
- Key storage: Django SECRET_KEY or dedicated key
- Key rotation: Supported via version prefix

### A.8 - Asset Management

✅ Protection of sensitive data (PII, credentials)
✅ Data classification support (searchable vs non-searchable)

## Migration Guide

### Adding Encrypted Fields to Existing Models

```bash
# 1. Add encrypted field to model
# models.py
class User(models.Model):
    username = EncryptedCharField(max_length=50, searchable=True)

# 2. Create migration
python manage.py makemigrations

# 3. Create data migration to encrypt existing data
python manage.py makemigrations data_protection --empty

# 4. Edit migration to encrypt existing data
# migrations/000X_encrypt_existing_data.py
from data_protection.encryption import EncryptionManager, SearchableIndexManager

def encrypt_usernames(apps, schema_editor):
    User = apps.get_model('myapp', 'User')
    for user in User.objects.all():
        if user.username and not user.username.startswith('v1:'):
            encrypted = EncryptionManager.encrypt(user.username)
            search_index = SearchableIndexManager.create_search_index(user.username)
            user.username = encrypted
            user.username_search_index = search_index
            user.save()

def decrypt_usernames(apps, schema_editor):
    # Reverse migration
    pass

class Migration(migrations.Migration):
    dependencies = [...]
    operations = [
        migrations.RunPython(encrypt_usernames, decrypt_usernames),
    ]

# 5. Run migration
python manage.py migrate
```

## Testing

See `tests.py` for comprehensive test suite.

```bash
# Run tests
python manage.py test data_protection

# Test specific functionality
python manage.py test data_protection.tests.EncryptionTests
```

## Troubleshooting

### Issue: Decryption fails after key change

**Cause**: Encryption key changed (SECRET_KEY modified)
**Solution**: Keys must remain constant. Use dedicated `DATA_PROTECTION_KEY` and store securely.

### Issue: Search not finding records

**Cause**: Search index not created or out of sync
**Solution**:
```python
# Rebuild search index
for obj in Model.objects.all():
    obj.save()  # Triggers index regeneration
```

### Issue: Performance degradation

**Cause**: Missing indexes on search fields
**Solution**: Add explicit indexes in model Meta:
```python
class Meta:
    indexes = [
        models.Index(fields=['field_name_search_index']),
    ]
```

## Security Considerations

### Threat Model

**Protected Against**:
- ✅ Database dumps / backups exposure
- ✅ SQL injection exposing sensitive data
- ✅ Unauthorized database access
- ✅ Rainbow table attacks on search index

**NOT Protected Against**:
- ❌ Attackers with application code access
- ❌ Attackers with SECRET_KEY access
- ❌ Memory dumps of running process
- ❌ Side-channel attacks
- ❌ Frequency analysis of search patterns

### Recommendations

1. **Use HTTPS**: Protect data in transit
2. **Secure SECRET_KEY**: Use environment variables, never commit to git
3. **Rotate keys**: Plan for periodic key rotation
4. **Audit access**: Log access to encrypted fields
5. **Consider hardware security modules (HSM)** for key storage in high-security environments

## API Reference

### EncryptionManager

```python
from data_protection.encryption import EncryptionManager

# Encrypt
encrypted = EncryptionManager.encrypt('plaintext')

# Decrypt
plaintext = EncryptionManager.decrypt('v1:gAAAAA...')
```

### SearchableIndexManager

```python
from data_protection.encryption import SearchableIndexManager

# Create search index
index = SearchableIndexManager.create_search_index('john_doe')

# Check if search matches
matches = SearchableIndexManager.matches_search(index, 'john')
```

## License

This is part of the hackathon-backend project. See main project license.

## Support

For issues or questions:
1. Check this documentation
2. Review example models in `models.py`
3. Run tests to verify functionality
4. Consult ISO27001 A.10.1 requirements

## Changelog

### v1.0.0 (2025-11-22)
- Initial implementation
- Fernet encryption with searchable n-gram index
- EncryptedTextField and EncryptedCharField
- ISO27001 A.10.1 compliance
- Example models and comprehensive documentation
