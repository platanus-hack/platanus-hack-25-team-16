# Users App - Custom User Model with Encrypted Fields

## Overview

This app implements a custom Django User model with comprehensive encryption for PII (Personally Identifiable Information), demonstrating both **searchable** and **non-searchable** encrypted fields for ISO27001 A.10.1 compliance.

## Features

- **Searchable Encrypted Fields**: Email, bio, and address fields with substring search capability
- **Standard Encrypted Fields**: SSN, phone numbers, DOB, names with maximum security
- **Automatic Encryption/Decryption**: Transparent field handling
- **Admin Interface**: Custom admin with encrypted field display
- **ISO27001 Compliant**: A.10.1 cryptographic controls

## Field Types

### 1. Searchable Encrypted Fields (`SearchableEncryptedTextField`)

These fields use n-gram indexing in separate tables for substring searches:

| Field | Type | Use Case | Searchable |
|-------|------|----------|------------|
| `email` | SearchableEncryptedTextField | User email address | ✅ Yes (`__icontains`) |
| `bio` | SearchableEncryptedTextField | User biography/description | ✅ Yes (`__contains`) |
| `address` | SearchableEncryptedTextField | Physical address | ✅ Yes (`__icontains`) |

**Search Tables Created:**
- `users_user_email_ngrams`
- `users_user_bio_ngrams`
- `users_user_address_ngrams`

### 2. Standard Encrypted Fields (`django-crypto-fields`)

These fields are encrypted with maximum security, no search capability:

| Field | Type | Use Case | Searchable |
|-------|------|----------|------------|
| `first_name` | EncryptedCharField | First name | ❌ No |
| `last_name` | EncryptedCharField | Last name | ❌ No |
| `phone_number` | EncryptedCharField | Phone number | ❌ No |
| `ssn` | EncryptedCharField | Social Security Number | ❌ No |
| `date_of_birth` | EncryptedDateField | Date of birth | ❌ No |
| `emergency_contact_name` | EncryptedCharField | Emergency contact | ❌ No |
| `emergency_contact_phone` | EncryptedCharField | Emergency phone | ❌ No |

### 3. Non-Encrypted Fields

| Field | Type | Use Case |
|-------|------|----------|
| `username` | CharField | Login identifier (indexed) |
| `password` | CharField | Hashed password (Django default) |
| `is_verified` | BooleanField | Email verification status |
| `account_tier` | CharField | Subscription level (free/premium/enterprise) |

Plus inherited Django fields: `is_staff`, `is_active`, `is_superuser`, `date_joined`, `last_login`, etc.

## Usage Examples

### Creating a User

```python
from users.models import User
from datetime import date

user = User.objects.create_user(
    username='johndoe',
    password='SecurePassword123!',

    # Searchable encrypted fields
    email='john@example.com',
    bio='Software engineer passionate about security',
    address='123 Main St, Springfield, IL 62701',

    # Standard encrypted fields
    first_name='John',
    last_name='Doe',
    phone_number='555-123-4567',
    ssn='123-45-6789',
    date_of_birth=date(1990, 5, 15),
    emergency_contact_name='Jane Doe',
    emergency_contact_phone='555-987-6543',

    # Non-encrypted metadata
    is_verified=True,
    account_tier='premium',
)
```

### Accessing Encrypted Data

```python
# Access is transparent - automatic decryption
print(user.email)         # 'john@example.com' (decrypted)
print(user.first_name)    # 'John' (decrypted)
print(user.ssn)           # '123-45-6789' (decrypted)
print(user.get_full_name())  # 'John Doe'
```

### Searching Encrypted Data

```python
# ✅ Searchable fields - substring search works
users = User.objects.filter(email__icontains='@example.com')
users = User.objects.filter(bio__contains='engineer')
users = User.objects.filter(address__icontains='Springfield')

# ❌ Standard encrypted fields - only exact match via username
user = User.objects.get(username='johndoe')
# Then access: user.ssn, user.phone_number, etc.
```

## Database Storage

### What's Actually Stored

```python
# Searchable field (email):
# Main field: "v1:gAAAAABhX2jK4y8..." (encrypted, ~2x size)
# N-gram table: users_user_email_ngrams
#   - Row 1: user_id=1, ngram_hash="a3f2e1d4c5b6..."
#   - Row 2: user_id=1, ngram_hash="d3c2b1a9e8f7..."
#   - ...

# Standard encrypted field (ssn):
# Main field: "hR3ypQQ+FPMz5HS..." (encrypted, ~2x size)
# No search index
```

## Admin Interface

Access the admin at: `http://localhost:8000/admin/`

### Login Credentials

**Superuser:**
- Username: `admin`
- Password: `admin123`

**Demo User:**
- Username: `johndoe`
- Password: `SecurePassword123!`

### Admin Features

- **List View**: Shows username, encrypted email, full name, status
- **Detail View**: Organized fieldsets with encryption indicators
- **Visual Indicators**: Encrypted fields marked with tooltips
- **Collapsed Sections**: Emergency contact info collapsed by default
- **Custom Methods**: `get_full_name()`, `has_complete_profile`

## Security Architecture

### Encryption Methods

1. **Searchable Fields** (`SearchableEncryptedTextField`):
   - **Encryption**: Fernet (AES-128 CBC + HMAC-SHA256)
   - **Search Index**: SHA-256 hashed n-grams (trigrams)
   - **Trade-off**: Searchability vs. metadata leakage (table size)
   - **Best for**: Emails, notes, addresses, descriptions

2. **Standard Fields** (`django-crypto-fields`):
   - **Encryption**: AES (via django-crypto-fields)
   - **Search Index**: None
   - **Trade-off**: Maximum security, no pattern matching
   - **Best for**: SSN, credit cards, highly sensitive IDs

### Threat Model

**Protected Against:**
- ✅ Database dumps/backups exposure
- ✅ SQL injection exposing sensitive data
- ✅ Unauthorized database access
- ✅ Rainbow table attacks on search index

**NOT Protected Against:**
- ❌ Attackers with application code access
- ❌ Attackers with SECRET_KEY/encryption keys
- ❌ Memory dumps of running process
- ❌ Frequency analysis of search patterns

## ISO27001 Compliance

This implementation satisfies:

### A.10.1 - Cryptographic Controls

✅ **A.10.1.1** - Policy on cryptographic controls
✅ **A.10.1.2** - Key management

**Implementation Details:**
- **Encryption**: Fernet (AES-128 CBC) + HMAC-SHA256
- **Key Derivation**: PBKDF2-HMAC-SHA256 (100,000 iterations)
- **Key Storage**: `crypto_keys/` directory (READ-ONLY in production)
- **Key Rotation**: Supported via version prefix

### A.8 - Asset Management

✅ Protection of sensitive data (PII, credentials)
✅ Data classification (searchable vs. non-searchable)

## Testing

```bash
# Test search functionality
python manage.py shell -c "
from users.models import User
users = User.objects.filter(email__icontains='@example')
print(f'Found {users.count()} users')
"

# View user data
python manage.py shell -c "
from users.models import User
user = User.objects.get(username='johndoe')
print(f'Name: {user.get_full_name()}')
print(f'Email: {user.email}')
print(f'Phone: {user.phone_number}')
"
```

## Performance Considerations

### Searchable Fields
- **Query Time**: O(log n) with proper indexing
- **Storage**: ~3x original size (encrypted + n-gram table)
- **Optimization**: Create indexes on n-gram tables for production

### Standard Encrypted Fields
- **Query Time**: O(1) for exact lookups
- **Storage**: ~2x original size (encrypted only)
- **Optimization**: No indexing possible on encrypted data

## Migration from Standard User

If migrating from Django's standard User model:

```bash
# 1. Backup database
python manage.py dumpdata auth.user > users_backup.json

# 2. Create custom User model (already done)

# 3. Update AUTH_USER_MODEL in settings.py (already done)
AUTH_USER_MODEL = 'users.User'

# 4. Create new database (fresh migrations required)
rm db.sqlite3
find . -path "*/migrations/*.py" -not -name "__init__.py" -delete
python manage.py makemigrations
python manage.py migrate

# 5. Create new superuser
python manage.py createsuperuser
```

## Best Practices

### ✅ DO

- Use `searchable=False` for highly sensitive data (SSN, credit cards)
- Create indexes on n-gram tables in production
- Store encryption keys securely (environment variables, secrets manager)
- Use HTTPS in production
- Make `crypto_keys/` directory READ-ONLY in production
- Rotate keys periodically (plan for key rotation)
- Test query performance on n-gram tables with large datasets

### ❌ DON'T

- Don't encrypt fields used for complex queries (dates, numbers, FKs)
- Don't encrypt non-sensitive public data
- Don't commit encryption keys to version control
- Don't assume perfect security - understand the threat model
- Don't query on non-indexed n-gram tables with large datasets
- Don't use same encryption key across environments

## File Structure

```
users/
├── __init__.py
├── admin.py              # Custom UserAdmin with encrypted field display
├── apps.py               # UsersConfig
├── models.py             # Custom User model with encrypted fields
├── migrations/
│   ├── __init__.py
│   └── 0001_initial.py   # User model + encrypted fields
├── README.md             # This file
└── tests.py              # Tests (to be implemented)
```

## Related Documentation

- [Data Protection App README](../data_protection/README.md) - Encryption implementation details
- [SearchableEncryptedTextField](../data_protection/fields.py) - N-gram searchable encryption
- [django-crypto-fields](https://github.com/erikvw/django-crypto-fields) - Battle-tested encryption
- [ISO27001 A.10.1](https://www.isms.online/iso-27001/annex-a-10-cryptography/) - Cryptographic controls

## Support

For issues or questions:
1. Check this documentation
2. Review `users/models.py` for field details
3. Review `data_protection/README.md` for encryption details
4. Test queries in Django shell

## Changelog

### v1.0.0 (2025-11-22)
- Initial implementation
- Custom User model with AbstractUser
- Searchable encrypted fields (email, bio, address)
- Standard encrypted fields (names, SSN, phone, DOB)
- Custom admin interface
- Comprehensive documentation
- Demo users with sample data
