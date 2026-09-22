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

    # Everything else is the web service: apply migrations, collect static
    # files, then serve.
    print('[run] applying migrations', flush=True)
    subprocess.run([sys.executable, 'manage.py', 'migrate', '--noinput'], check=True)

    # Without this there is no static manifest, so anything rendering a
    # template that references a static file raises "Missing staticfiles
    # manifest entry" — which turned every API response to a browser into a
    # 500, because DRF renders its browsable page for an HTML request. The
    # API itself answers fine; it was the page around it that failed. Serving
    # still starts if this fails: a missing stylesheet must not take the API
    # down with it.
    print('[run] collecting static files', flush=True)
    collected = subprocess.run([sys.executable, 'manage.py', 'collectstatic', '--noinput'])
    if collected.returncode != 0:
        print(f'[run] WARNING collectstatic failed ({collected.returncode}); serving anyway', flush=True)

    _exec(['gunicorn', 'core.wsgi:application', '--bind', f'0.0.0.0:{port}'])


if __name__ == '__main__':
    main()
