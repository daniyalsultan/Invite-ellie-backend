from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0015_add_subscription_plan'),
    ]

    operations = [
        migrations.RunSQL(
            sql="ALTER TABLE profiles ALTER COLUMN subscription_plan SET DEFAULT 'free';",
            reverse_sql="ALTER TABLE profiles ALTER COLUMN subscription_plan DROP DEFAULT;",
        ),
    ]
