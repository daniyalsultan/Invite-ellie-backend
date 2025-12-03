### Stage deployment
Check username and project directory name.
```
sudo dnf update -y
sudo dnf install -y python3.11 python3.11-pip git redis6 nginx
sudo systemctl enable --now redis6  # Broker for Celery
```
```
cd ~
git clone --branch stage https://github.com/yourusername/Invite-ellie-backend.git app
cd app
```
```
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt gunicorn whitenoise psycopg2-binary python-decouple
deactivate
```
- Edit .env: `nano .env`
- Paste your env vars
```
source .venv/bin/activate
python manage.py collectstatic --noinput
python manage.py migrate
deactivate
```
- Save and close.
```
sudo tee /etc/systemd/system/celery.service > /dev/null <<EOF
[Unit]
Description=Invite Ellie Celery Worker
After=network.target redis6.service

[Service]
User=ec2-user
Group=ec2-user
WorkingDirectory=/home/ec2-user/app
Environment="PATH=/home/ec2-user/app/.venv/bin"
ExecStart=/home/ec2-user/app/.venv/bin/celery -A core worker --loglevel=info
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/celerybeat.service > /dev/null <<EOF
[Unit]
Description=Invite Ellie Celery Beat
After=network.target redis6.service

[Service]
User=ec2-user
Group=ec2-user
WorkingDirectory=/home/ec2-user/app
Environment="PATH=/home/ec2-user/app/.venv/bin"
ExecStart=/home/ec2-user/app/.venv/bin/celery -A core beat --loglevel=info
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now celery celerybeat
```
```
sudo mkdir /etc/nginx/ssl
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/selfsigned.key \
  -out /etc/nginx/ssl/selfsigned.crt \
  -subj "/CN=$(curl -s https://ipinfo.io/ip)"
```
```
sudo tee /etc/systemd/system/django.service > /dev/null <<'EOF'
[Unit]
Description=Invite Ellie Django
After=network.target

[Service]
User=ec2-user
Group=ec2-user
WorkingDirectory=/home/ec2-user/app
Environment=PATH=/home/ec2-user/app/.venv/bin
ExecStart=/home/ec2-user/app/.venv/bin/gunicorn core.wsgi:application --bind 127.0.0.1:8000 --workers 3 --timeout 120
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
```
```
sudo mkdir -p /var/www/static
sudo rsync -av /home/ec2-user/app/staticfiles/ /var/www/static/
sudo chown -R ec2-user:nginx /var/www/static
sudo chmod -R 755 /var/www/static

# Point Nginx to the new location (SELinux allows /var/www by default)
sudo tee /etc/nginx/conf.d/invite-ellie.conf > /dev/null <<'EOF'
server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name _;

    ssl_certificate     /etc/nginx/ssl/selfsigned.crt;
    ssl_certificate_key /etc/nginx/ssl/selfsigned.key;

    proxy_connect_timeout 300s;
    proxy_send_timeout    300s;
    proxy_read_timeout    300s;
    send_timeout          300s;

    location /static/ {
        alias /var/www/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

# Start everything
sudo systemctl daemon-reload
sudo systemctl start django nginx
```
- Test
```
curl -I http://127.0.0.1/api/docs/
```
- Should return a 200 or a 301




### Debugging
```
# Follow logs
sudo journalctl -u celery -f
```
```
# Gunicorn/Django access & error logs (since we log to stdout/stderr)
sudo journalctl -u django -n 50 --no-pager

# Last 50 lines + follow new ones live (super useful)
sudo journalctl -u django -n 50 -f

# Celery worker logs
sudo journalctl -u celery -n 50 --no-pager

# Celery beat logs
sudo journalctl -u celerybeat -n 50 --no-pager

# Nginx error log (if you ever get 502/504 again)
sudo tail -n 50 /var/log/nginx/error.log
```