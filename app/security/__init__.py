"""
Django Security Module

Módulo de seguridad extensible para proyectos Django.
Proporciona configuración segura por defecto, middlewares de protección HTTP,
y protección contra CSRF/XSS/Clickjacking/Injection.

Version: 1.0.0
Compatible con: Django 5.2+
"""

__version__ = "1.0.0"
__author__ = "Security Team"

# Las importaciones se realizarán cuando los módulos estén implementados
__all__ = ["conf", "middleware", "validation", "utils", "decorators", "checks"]
