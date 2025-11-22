from django.core.management.base import BaseCommand, CommandError

from auditory.registry import security_state


class Command(BaseCommand):
    help = "Verifica la cadena de hash de auditoría y reporta inconsistencias."

    def handle(self, *args, **options):
        backend = security_state.get_backend()
        if not backend:
            raise CommandError("Backend de auditoría no inicializado.")

        result = backend.verify_chain()
        if result["ok"]:
            self.stdout.write(self.style.SUCCESS(f"Cadena verificada. Registros revisados: {result['checked']}"))
        else:
            mismatches = ", ".join(map(str, result["mismatches"]))
            raise CommandError(f"Inconsistencias detectadas en IDs: {mismatches}")
