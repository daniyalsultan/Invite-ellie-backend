"""Start the right process for whichever Railway service this container is.

All services in this project deploy from the same repository, and a
`startCommand` in railway.json applies to every one of them — it overrides the
per-service Custom Start Command set in the dashboard. Adding one here to get
migrations running at boot therefore silently pointed the Celery worker at
gunicorn too, and the scheduled maintenance tasks stopped running for nine days
before anyone noticed.

Branching on RAILWAY_SERVICE_NAME (which Railway sets for every service) keeps
the single start command honest: each service still runs what it is for.
"""

import os
import subprocess
import sys


def _exec(command):
    print(f'[run] {os.getenv("RAILWAY_SERVICE_NAME", "unknown")}: exec {" ".join(command)}', flush=True)
    os.execvp(command[0], command)


def main():
    service = (os.getenv('RAILWAY_SERVICE_NAME') or '').strip().lower()
    port = os.getenv('PORT', '8000')

    if service == 'celery':
        # -B runs beat in the same process, which is what actually fires
        # CELERY_BEAT_SCHEDULE. Concurrency is pinned because the prefork pool
        # otherwise reads the host's CPU count rather than this container's
        # limit and gets OOM-killed seconds after startup.
        concurrency = os.getenv('CELERY_WORKER_CONCURRENCY', '4')
        _exec(['celery', '-A', 'core', 'worker', '-B', '-E', '-l', 'info',
               '--concurrency', concurrency])

    if service == 'flower':
        _exec(['celery', '-A', 'core', 'flower', f'--port={port}'])

    # Everything else is the web service: apply migrations, then serve.
    print('[run] applying migrations', flush=True)
    subprocess.run([sys.executable, 'manage.py', 'migrate', '--noinput'], check=True)
    _exec(['gunicorn', 'core.wsgi:application', '--bind', f'0.0.0.0:{port}'])


if __name__ == '__main__':
    main()
