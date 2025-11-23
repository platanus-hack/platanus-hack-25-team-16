"""
Management command to seed the database with sample users.

Creates 50 users with encrypted PII data for testing and demonstration.
"""

import random
from datetime import date, timedelta

from django.core.management.base import BaseCommand
from django.db import transaction

from users.models import User


class Command(BaseCommand):
    help = 'Seeds the database with 50 sample users with encrypted data'

    def add_arguments(self, parser):
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing users before seeding (keeps superusers)',
        )

    def handle(self, *args, **options):
        if options['clear']:
            self.stdout.write('Clearing existing users (keeping superusers)...')
            deleted = User.objects.filter(is_superuser=False).delete()
            self.stdout.write(self.style.SUCCESS(f'Deleted {deleted[0]} users'))

        self.stdout.write('Seeding 50 users with encrypted data...')

        with transaction.atomic():
            # Create the 3 specific users
            specific_users = self.create_specific_users()

            # Create 47 additional random users
            random_users = self.create_random_users(47)

            total_created = len(specific_users) + len(random_users)

        self.stdout.write(self.style.SUCCESS(f'\n✓ Successfully created {total_created} users'))
        self.stdout.write('\nSpecific users created:')
        for user in specific_users:
            self.stdout.write(f'  - {user.username} ({user.email}) - {user.get_full_name()}')

        self.stdout.write(f'\n✓ {len(random_users)} additional random users created')
        self.stdout.write('\n=== LOGIN CREDENTIALS ===')
        self.stdout.write('Xpendit team (superusers): password = 1234')
        self.stdout.write('All other users: password = Test1234!')

    def create_specific_users(self):
        """Create the 3 specific Xpendit users."""
        specific_data = [
            {
                'username': 'ignacio',
                'email': 'ignacio@xpendit.com',
                'first_name': 'Ignacio',
                'last_name': 'Gerardo Engelberger',
                'phone': '+56 9 1234 5678',
                'ssn': '12.345.678-9',
                'dob': date(1990, 3, 15),
                'bio': 'Software engineer and co-founder of Xpendit. Passionate about fintech and secure systems.',
                'address': 'Av. Providencia 1234, Santiago, Chile',
            },
            {
                'username': 'nicolas',
                'email': 'nicolas@xpendit.com',
                'first_name': 'Nicolas',
                'last_name': 'José Ramos',
                'phone': '+56 9 8765 4321',
                'ssn': '98.765.432-1',
                'dob': date(1992, 7, 22),
                'bio': 'Full-stack developer at Xpendit. Expert in Django, React, and cloud infrastructure.',
                'address': 'Av. Apoquindo 4567, Las Condes, Santiago',
            },
            {
                'username': 'david',
                'email': 'david@xpendit.com',
                'first_name': 'David',
                'last_name': 'Esteban El Loco',
                'phone': '+56 9 5555 1234',
                'ssn': '11.222.333-4',
                'dob': date(1988, 12, 5),
                'bio': 'DevOps wizard and security enthusiast. Known for creative problem-solving and automation.',
                'address': 'Av. Vitacura 8901, Vitacura, Santiago',
            },
        ]

        users = []
        for data in specific_data:
            # Skip if user already exists
            if User.objects.filter(username=data['username']).exists():
                self.stdout.write(self.style.WARNING(f'  User {data["username"]} already exists, skipping...'))
                continue

            # Create user with basic fields as superuser
            user = User.objects.create_user(
                username=data['username'],
                password='1234',  # Password for Xpendit team
            )

            # Make superuser with staff access
            user.is_superuser = True
            user.is_staff = True

            # Set encrypted and additional fields
            user.email = data['email']
            user.first_name = data['first_name']
            user.last_name = data['last_name']
            user.save()

            users.append(user)

        return users

    def create_random_users(self, count):
        """Create random users with Xpendit emails."""
        users = []

        # Common Chilean cities for addresses
        cities = [
            'Santiago', 'Valparaíso', 'Concepción', 'La Serena', 'Antofagasta',
            'Temuco', 'Viña del Mar', 'Rancagua', 'Talca', 'Arica',
            'Iquique', 'Puerto Montt', 'Coyhaique', 'Punta Arenas'
        ]

        # Common Chilean streets
        streets = [
            'Av. Libertador Bernardo O\'Higgins', 'Av. Providencia', 'Av. Apoquindo',
            'Av. Vicuña Mackenna', 'Av. Santa Rosa', 'Av. Grecia',
            'Calle Estado', 'Paseo Ahumada', 'Calle Huérfanos', 'Calle Agustinas'
        ]

        # Tech/business related bios
        bio_templates = [
            'Backend developer specializing in Python and Django.',
            'Frontend engineer with expertise in React and Vue.js.',
            'Data scientist working with machine learning and AI.',
            'Product manager with a passion for user experience.',
            'DevOps engineer automating infrastructure and deployments.',
            'Security analyst focused on application security.',
            'Mobile developer building iOS and Android apps.',
            'Technical writer creating documentation and tutorials.',
            'QA engineer ensuring quality and reliability.',
            'Business analyst bridging technology and business.',
            'UX designer creating intuitive user interfaces.',
            'Database administrator optimizing performance.',
            'Cloud architect designing scalable solutions.',
            'Scrum master facilitating agile development.',
            'Technical lead mentoring and guiding teams.',
        ]

        for i in range(count):
            # Generate unique username
            first = self.generate_first_name()
            last = self.generate_last_name()
            username = f"{first.lower()}.{last.lower()}{i+1}"

            # Create user with basic fields
            user = User.objects.create_user(
                username=username,
                password='Test1234!',
            )

            # Set encrypted and additional fields
            tier = random.choice(["free", "premium", "enterprise"])
            user.email = f"{tier}@xpendit.com"
            user.first_name = first
            user.last_name = last
            user.phone_number = self.generate_phone()
            user.ssn = self.generate_rut()
            user.date_of_birth = self.generate_dob()
            user.bio = random.choice(bio_templates)
            user.address = self.generate_address(streets, cities)
            user.is_verified = random.choice([True, True, False])  # 66% verified
            user.account_tier = tier
            user.emergency_contact_name = self.generate_name()
            user.emergency_contact_phone = self.generate_phone()
            user.save()

            users.append(user)

        return users

    def generate_first_name(self):
        """Generate a random first name."""
        names = [
            'Matías', 'Sofía', 'Sebastián', 'Valentina', 'Diego', 'Martina',
            'Tomás', 'Isidora', 'Benjamín', 'Emilia', 'Lucas', 'Josefa',
            'Joaquín', 'Catalina', 'Agustín', 'Antonella', 'Vicente', 'Florencia',
            'Maximiliano', 'Fernanda', 'Felipe', 'Javiera', 'Cristóbal', 'Magdalena',
            'Andrés', 'Constanza', 'Gabriel', 'Camila', 'Rodrigo', 'Daniela',
            'Pablo', 'Carolina', 'José', 'María', 'Juan', 'Francisca',
        ]
        return random.choice(names)

    def generate_last_name(self):
        """Generate a random last name."""
        surnames = [
            'González', 'Muñoz', 'Rodríguez', 'García', 'Martínez', 'López',
            'Fernández', 'Pérez', 'Sánchez', 'Ramírez', 'Torres', 'Flores',
            'Rivera', 'Gómez', 'Díaz', 'Morales', 'Contreras', 'Silva',
            'Rojas', 'Gutiérrez', 'Núñez', 'Vargas', 'Castro', 'Pino',
            'Vega', 'Campos', 'Sepúlveda', 'Espinoza', 'Valdés', 'Herrera',
        ]
        return random.choice(surnames)

    def generate_name(self):
        """Generate a full name."""
        return f"{self.generate_first_name()} {self.generate_last_name()}"

    def generate_phone(self):
        """Generate a Chilean phone number."""
        return f"+56 9 {random.randint(1000, 9999)} {random.randint(1000, 9999)}"

    def generate_rut(self):
        """Generate a fake Chilean RUT."""
        num = random.randint(10000000, 25000000)
        # Simple check digit (not real algorithm, just for demo)
        check = random.choice(['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'K'])
        return f"{num//1000000}.{(num//1000)%1000:03d}.{num%1000:03d}-{check}"

    def generate_dob(self):
        """Generate a random date of birth (18-65 years old)."""
        today = date.today()
        years_ago = random.randint(18, 65)
        days_variation = random.randint(0, 365)
        birth_date = today - timedelta(days=years_ago * 365 + days_variation)
        return birth_date

    def generate_address(self, streets, cities):
        """Generate a random Chilean address."""
        street = random.choice(streets)
        number = random.randint(100, 9999)
        city = random.choice(cities)
        return f"{street} {number}, {city}, Chile"
