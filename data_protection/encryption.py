"""
Encryption utilities for data protection.

Implements searchable encryption as per ISO27001 A.10.1 (Cryptographic Controls)
for protecting sensitive data at rest while maintaining query capabilities.
"""

import hashlib
import logging
from typing import Optional, Set

from django.conf import settings

logger = logging.getLogger(__name__)


class SearchableIndexManager:
    """
    Manages searchable indexes for encrypted data using n-gram tokenization.

    This allows substring searches on encrypted data without exposing the
    plaintext values. Implements a privacy-preserving search mechanism
    suitable for ISO27001 compliance.

    Approach:
    - Tokenize plaintext into n-grams (substrings of length n)
    - Hash each n-gram with a secret salt
    - Store hashed n-grams for searching
    - For queries, hash search term n-grams and match against stored hashes

    Security properties:
    - Cannot reverse hashed n-grams to recover plaintext
    - Search patterns are not directly observable
    - Salted hashes prevent rainbow table attacks
    """

    # Configuration
    NGRAM_SIZE = 3  # Trigrams (3-character substrings)
    MIN_SEARCH_LENGTH = 2  # Minimum search term length

    @classmethod
    def _get_salt(cls) -> bytes:
        """
        Get salt for n-gram hashing.

        Returns:
            Salt bytes derived from SECRET_KEY
        """
        salt = getattr(settings, 'DATA_PROTECTION_SEARCH_SALT', None)
        if salt:
            return salt.encode('utf-8') if isinstance(salt, str) else salt

        # Derive from SECRET_KEY
        secret = settings.SECRET_KEY.encode('utf-8')
        return hashlib.sha256(secret + b'_search_salt').digest()

    @classmethod
    def generate_ngrams(cls, text: str, n: Optional[int] = None) -> Set[str]:
        """
        Generate n-grams from text.

        Args:
            text: Input text
            n: N-gram size (defaults to NGRAM_SIZE)

        Returns:
            Set of n-gram strings
        """
        if not text:
            return set()

        n = n or cls.NGRAM_SIZE
        text_lower = text.lower().strip()

        # Generate n-grams
        ngrams = set()

        # Add full text as one token (for exact matches)
        ngrams.add(text_lower)

        # Add n-grams
        for i in range(len(text_lower) - n + 1):
            ngram = text_lower[i : i + n]
            ngrams.add(ngram)

        # Add smaller n-grams for short texts
        if len(text_lower) < n:
            ngrams.add(text_lower)

        return ngrams

    @classmethod
    def hash_ngram(cls, ngram: str) -> str:
        """
        Hash an n-gram with secret salt.

        Args:
            ngram: N-gram string to hash

        Returns:
            Hex-encoded hash
        """
        salt = cls._get_salt()
        hash_input = ngram.encode('utf-8') + salt
        return hashlib.sha256(hash_input).hexdigest()

    @classmethod
    def create_search_index(cls, plaintext: str) -> str:
        """
        Create searchable index from plaintext.

        Args:
            plaintext: Original text to index

        Returns:
            Space-separated string of hashed n-grams
        """
        if not plaintext:
            return ""

        ngrams = cls.generate_ngrams(plaintext)
        hashed_ngrams = [cls.hash_ngram(ngram) for ngram in ngrams]

        # Return as space-separated string for DB storage
        return " ".join(sorted(hashed_ngrams))

    @classmethod
    def create_search_tokens(cls, search_term: str) -> Set[str]:
        """
        Create search tokens from query term.

        Args:
            search_term: Search query

        Returns:
            Set of hashed n-grams to search for
        """
        if not search_term or len(search_term) < cls.MIN_SEARCH_LENGTH:
            return set()

        ngrams = cls.generate_ngrams(search_term)
        return {cls.hash_ngram(ngram) for ngram in ngrams}

    @classmethod
    def matches_search(cls, index: str, search_term: str) -> bool:
        """
        Check if search term matches the searchable index.

        Args:
            index: Stored searchable index (space-separated hashes)
            search_term: Query term

        Returns:
            True if search term matches index
        """
        if not search_term or not index:
            return False

        search_tokens = cls.create_search_tokens(search_term)
        if not search_tokens:
            return False

        index_tokens = set(index.split())

        # Match if any search token is in the index
        return bool(search_tokens & index_tokens)
