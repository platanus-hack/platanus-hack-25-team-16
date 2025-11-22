# EncryptedFileField - Secure File Storage for Django

## Overview

The `EncryptedFileField` provides enterprise-grade secure file storage for Django applications, implementing ISO 27001 controls for data protection at rest. It offers automatic encryption, comprehensive validation, and signed URLs for temporary access.

## Features

### 🔐 Security Features
- **AES-256 Encryption**: Files are encrypted at rest using Fernet (symmetric encryption)
- **File Validation**: Multi-layer validation including size, extension, and MIME type
- **Dangerous File Detection**: Configurable blocking of potentially dangerous file types
- **Signed URLs**: Time-limited, cryptographically signed URLs for secure file access
- **Audit Logging**: Complete audit trail of all file operations
- **Hash Integrity**: SHA-256 hash verification for file integrity

### 🏢 ISO 27001 Compliance
- **A.10.1.1**: Cryptographic controls policy implementation
- **A.10.1.2**: Secure key management
- **A.12.2.1**: Malware protection through file validation
- **A.12.4.1**: Comprehensive event logging
- **A.13.2.1**: Secure information transfer via signed URLs
- **A.9.4.1**: Information access restriction

## Installation

The EncryptedFileField is part of the Django Security library. Ensure you have the required dependencies:

```bash
pip install cryptography>=41.0.0
pip install python-magic>=0.4.27
pip install itsdangerous>=2.1.0
```

## Configuration

### Basic Setup

Add to your Django settings:

```python
# settings.py
DJANGO_SEC = {
    # Encryption key (required in production)
    'FILE_ENCRYPTION_KEY': os.environ.get('FILE_ENCRYPTION_KEY'),

    # Encrypted Files Configuration
    'ENCRYPTED_FILES': {
        'ENABLED': True,
        'MAX_SIZE': 10 * 1024 * 1024,  # 10MB default
        'ALLOWED_EXTENSIONS': ['.pdf', '.docx', '.xlsx', '.jpg', '.png'],
        'VALIDATE_MIME': True,

        # Configurable dangerous extensions
        'DANGEROUS_EXTENSIONS': [
            '.exe', '.dll', '.bat', '.sh', '.ps1',  # Executables/Scripts
            '.jar', '.app', '.msi',                  # Packages
            '.xlsm', '.docm',                        # Macros
            # Add your custom dangerous extensions
        ],

        # Signed URLs Configuration
        'SIGNED_URLS': {
            'ENABLED': True,
            'DEFAULT_EXPIRY': 3600,  # 1 hour
            'BIND_TO_IP': False,     # Bind URLs to requester's IP
            'DOWNLOAD_ENDPOINT': '/api/secure-download/',
        },
    },
}
```

### Generating Encryption Key

Generate a secure encryption key:

```python
from cryptography.fernet import Fernet

# Generate a new key
key = Fernet.generate_key()
print(key.decode())  # Save this in your environment variables
```

Set the key as an environment variable:

```bash
export FILE_ENCRYPTION_KEY="your-generated-key-here"
```

⚠️ **Important**: Never commit encryption keys to version control. Always use environment variables or secure key management systems.

## Usage

### Basic Model Implementation

```python
from django.db import models
from app.security.storage import EncryptedFileField

class SecureDocument(models.Model):
    title = models.CharField(max_length=200)

    # Basic encrypted file field
    file = EncryptedFileField(
        upload_to='secure_documents/',
        max_upload_size=50 * 1024 * 1024,  # 50MB
        allowed_extensions=['.pdf', '.docx', '.xlsx'],
        signed_url_expiry=1800,  # 30 minutes
    )

    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE)
    uploaded_at = models.DateTimeField(auto_now_add=True)
```

### Advanced Configuration

```python
class HighSecurityDocument(models.Model):
    # Highly restricted file field
    classified_file = EncryptedFileField(
        upload_to='classified/',
        max_upload_size=10 * 1024 * 1024,    # 10MB max
        allowed_extensions=['.pdf'],          # Only PDFs
        allowed_mimetypes=['application/pdf'], # Strict MIME checking
        validate_mime=True,                    # Enable MIME validation
        signed_url_expiry=300,                 # 5 minute URLs
        audit_access=True,                     # Full audit logging
    )

    classification = models.CharField(
        max_length=20,
        choices=[
            ('PUBLIC', 'Public'),
            ('INTERNAL', 'Internal'),
            ('CONFIDENTIAL', 'Confidential'),
            ('SECRET', 'Secret'),
        ]
    )
```

### Handling File Uploads

```python
# views.py
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import SecureDocument
from .forms import DocumentUploadForm

@login_required
def upload_document(request):
    if request.method == 'POST':
        form = DocumentUploadForm(request.POST, request.FILES)

        if form.is_valid():
            document = form.save(commit=False)
            document.uploaded_by = request.user

            try:
                document.save()
                messages.success(request, 'Document uploaded securely.')
                return redirect('document_list')
            except ValidationError as e:
                messages.error(request, f'Upload failed: {e}')
    else:
        form = DocumentUploadForm()

    return render(request, 'upload.html', {'form': form})
```

### Generating Signed URLs

```python
# views.py
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required

@login_required
def get_download_url(request, document_id):
    """Generate a temporary download URL for a document."""

    document = SecureDocument.objects.get(
        id=document_id,
        uploaded_by=request.user  # Ensure user owns the document
    )

    # Generate signed URL valid for 5 minutes
    signed_url = document.get_file_signed_url(expires_in=300)

    # Log the URL generation
    FileAccessLog.objects.create(
        file_path=document.file.name,
        action='generate_url',
        user=request.user,
        ip_address=get_client_ip(request),
        status='success'
    )

    return JsonResponse({
        'download_url': signed_url,
        'expires_in': 300,
        'filename': document.title
    })
```

### Serving Files via Signed URLs

```python
# views.py
from django.http import Http404
from app.security.storage import SignedURLManager

def download_with_signed_url(request):
    """Handle downloads via signed URLs."""

    token = request.GET.get('token')
    if not token:
        raise Http404("Invalid download link")

    manager = SignedURLManager()
    client_ip = get_client_ip(request)

    try:
        # Validate and serve the file
        return manager.serve_file(token, client_ip)
    except PermissionDenied:
        raise Http404("Download link expired or invalid")
```

### URL Configuration

```python
# urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('upload/', views.upload_document, name='upload_document'),
    path('download/<int:document_id>/', views.get_download_url, name='get_download_url'),
    path('api/secure-download/', views.download_with_signed_url, name='secure_download'),
]
```

## Validation Examples

### Custom Validation Rules

```python
class RestrictedDocument(models.Model):
    # Very restrictive validation
    secure_file = EncryptedFileField(
        upload_to='restricted/',
        max_upload_size=1 * 1024 * 1024,      # 1MB only
        allowed_extensions=['.pdf', '.txt'],   # Limited formats
        allowed_mimetypes=[
            'application/pdf',
            'text/plain'
        ],
        validate_mime=True,  # Strict MIME validation
    )
```

### Overriding Dangerous Extensions

```python
# settings.py
DJANGO_SEC = {
    'ENCRYPTED_FILES': {
        # Add custom dangerous extensions for your use case
        'DANGEROUS_EXTENSIONS': [
            # Default dangerous extensions
            '.exe', '.dll', '.bat', '.sh',
            # Add organization-specific restrictions
            '.zip', '.rar',  # Block archives
            '.html', '.htm',  # Block HTML files
            '.sql',          # Block database scripts
        ],
    }
}
```

## Working with Encrypted Files

### Decrypting Files for Processing

```python
def process_document(document_id):
    """Process an encrypted document."""

    document = SecureDocument.objects.get(id=document_id)

    # Get decrypted content
    decrypted_content = document.get_file_decrypted()

    # Process the content (e.g., extract text from PDF)
    # ... processing logic ...

    # The original file remains encrypted on disk
```

### Batch Operations

```python
from django.core.management.base import BaseCommand
from app.models import SecureDocument

class Command(BaseCommand):
    help = 'Generate report from encrypted documents'

    def handle(self, *args, **options):
        documents = SecureDocument.objects.filter(
            classification='PUBLIC'
        )

        for doc in documents:
            # Each file is decrypted only when accessed
            content = doc.get_file_decrypted()

            # Process content...
            self.process_document(content)

            # Log access for audit
            FileAccessLog.objects.create(
                file_path=doc.file.name,
                action='batch_processing',
                status='success'
            )
```

## Admin Integration

```python
# admin.py
from django.contrib import admin
from .models import SecureDocument, FileAccessLog

@admin.register(SecureDocument)
class SecureDocumentAdmin(admin.ModelAdmin):
    list_display = ['title', 'uploaded_by', 'uploaded_at', 'file_size']
    list_filter = ['uploaded_at', 'uploaded_by']
    search_fields = ['title', 'uploaded_by__username']
    readonly_fields = ['file_hash', 'encrypted_size']

    def file_size(self, obj):
        """Display human-readable file size."""
        if obj.file:
            size = obj.file.size
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size < 1024.0:
                    return f"{size:.1f} {unit}"
                size /= 1024.0
        return "N/A"

    def file_hash(self, obj):
        """Display file hash for verification."""
        if obj.file:
            return obj.file.name.split('_')[0][:16]
        return "N/A"

@admin.register(FileAccessLog)
class FileAccessLogAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'action', 'user', 'ip_address', 'status']
    list_filter = ['action', 'status', 'timestamp']
    search_fields = ['user__username', 'ip_address', 'file_path']
    readonly_fields = ['timestamp', 'metadata']

    def has_add_permission(self, request):
        # Audit logs should not be manually created
        return False

    def has_delete_permission(self, request, obj=None):
        # Audit logs should not be deleted
        return False
```

## Security Best Practices

### 1. Key Management

```python
# Use environment variables
FILE_ENCRYPTION_KEY = os.environ.get('FILE_ENCRYPTION_KEY')

# Or use a key management service
from app.security.secrets import get_secret
FILE_ENCRYPTION_KEY = get_secret('file_encryption_key')
```

### 2. Access Control

```python
@login_required
@permission_required('documents.view_securedocument')
def view_document(request, document_id):
    """Ensure proper access control."""
    document = get_object_or_404(
        SecureDocument,
        id=document_id,
        uploaded_by=request.user  # User can only access their own files
    )
    # ...
```

### 3. Rate Limiting

```python
from app.security.decorators import rate_limit

@rate_limit('10/h')  # Max 10 downloads per hour
def download_file(request, document_id):
    # ...
```

### 4. Monitoring

```python
# Monitor suspicious activity
def check_suspicious_downloads():
    from datetime import timedelta
    from django.utils import timezone

    # Find users with excessive downloads
    suspicious = FileAccessLog.objects.filter(
        action='download',
        timestamp__gte=timezone.now() - timedelta(hours=1)
    ).values('user').annotate(
        download_count=Count('id')
    ).filter(
        download_count__gt=50  # More than 50 downloads per hour
    )

    for user_data in suspicious:
        # Alert security team
        send_security_alert(user_data)
```

## Troubleshooting

### Common Issues

1. **ValidationError: File type not allowed**
   - Check `ALLOWED_EXTENSIONS` in settings
   - Verify the file extension is not in `DANGEROUS_EXTENSIONS`

2. **Invalid encryption key**
   - Ensure `FILE_ENCRYPTION_KEY` is properly set
   - Check the key format (must be a valid Fernet key)

3. **MIME type mismatch**
   - File extension doesn't match actual file content
   - Disable MIME validation with `validate_mime=False` if needed

4. **Signed URL expired**
   - Increase `signed_url_expiry` value
   - Generate new URL if expired

### Debug Logging

Enable debug logging to troubleshoot issues:

```python
# settings.py
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': 'encrypted_files.log',
        },
    },
    'loggers': {
        'app.security.storage': {
            'handlers': ['file'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}
```

## Testing

Run the included tests:

```bash
python manage.py test app.security.storage.tests
```

Example test case:

```python
from django.test import TestCase
from django.core.files.uploadedfile import SimpleUploadedFile
from app.security.storage import EncryptedFileField

class EncryptedFileTestCase(TestCase):
    def test_file_encryption(self):
        field = EncryptedFileField(upload_to='test/')

        # Create test file
        test_file = SimpleUploadedFile(
            "test.pdf",
            b"PDF content here"
        )

        # Encrypt the file
        encrypted = field._encrypt_file(test_file)

        # Verify it's encrypted
        self.assertNotEqual(encrypted, b"PDF content here")

        # Verify it can be decrypted
        decrypted = field.cipher.decrypt(encrypted)
        self.assertEqual(decrypted, b"PDF content here")
```

## Migration Guide

### Migrating from FileField to EncryptedFileField

1. **Add the new field**:
```python
class Document(models.Model):
    old_file = models.FileField(upload_to='documents/')
    encrypted_file = EncryptedFileField(upload_to='encrypted/', null=True)
```

2. **Create migration script**:
```python
from django.core.management.base import BaseCommand

class Command(BaseCommand):
    def handle(self, *args, **options):
        for doc in Document.objects.filter(encrypted_file__isnull=True):
            if doc.old_file:
                # Read old file
                doc.old_file.open()
                content = doc.old_file.read()

                # Save to encrypted field
                doc.encrypted_file.save(
                    doc.old_file.name,
                    ContentFile(content)
                )
                doc.save()
```

3. **Remove old field** after verification

## Performance Considerations

- **Encryption overhead**: ~10-20ms for 1MB files
- **Decryption overhead**: ~10-20ms for 1MB files
- **MIME validation**: ~5-10ms per file
- **Hash calculation**: ~5ms per MB

For large files, consider:
- Async processing with Celery
- Chunked encryption/decryption
- Caching decrypted content temporarily

## License

This module is part of the Django Security library, released under the MIT License.

## Support

For issues or questions, please refer to the main Django Security documentation or create an issue in the repository.