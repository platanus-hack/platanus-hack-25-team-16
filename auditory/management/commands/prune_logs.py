from django.core.management.base import BaseCommand, CommandError

from auditory.registry import security_state


class Command(BaseCommand):
    help = "Aplica política de retención y elimina logs antiguos (archivado opcional)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            help="Días de retención; si no se indica usa la configuración.",
        )

    def handle(self, *args, **options):
        cfg = security_state.get_config()
        backend = security_state.get_backend()
        if not backend:
            raise CommandError("Backend de auditoría no inicializado.")

        retention = options.get("days") or cfg.get("AUDIT_LOG", {}).get(
            "RETENTION_DAYS", 180
        )
        deleted = backend.prune(retention)
        self.stdout.write(
            self.style.SUCCESS(
                f"Eliminados {deleted} registros anteriores a {retention} días."
            )
        )
