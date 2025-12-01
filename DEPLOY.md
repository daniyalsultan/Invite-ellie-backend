### Celery Beat Service
Check username and project directory name.
```
sudo tee /etc/systemd/system/celerybeat.service > /dev/null <<EOF
[Unit]
Description=Celery Beat
After=network.target redis6.service

[Service]
User=ec2-user
Group=ec2-user
WorkingDirectory=/home/ec2-user/Invite-ellie-backend
Environment="PATH=/home/ec2-user/Invite-ellie-backend/.venv/bin"
ExecStart=/home/ec2-user/Invite-ellie-backend/.venv/bin/celery -A core beat --loglevel=info
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```
### Celery Service
Check username and project directory name.
```
sudo tee /etc/systemd/system/celery.service > /dev/null <<EOF
[Unit]
Description=Celery Worker
After=network.target redis6.service

[Service]
User=ec2-user
Group=ec2-user
WorkingDirectory=/home/ec2-user/Invite-ellie-backend
Environment="PATH=/home/ec2-user/Invite-ellie-backend/.venv/bin"
ExecStart=/home/ec2-user/Invite-ellie-backend/.venv/bin/celery -A core worker --loglevel=info
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

```
sudo systemctl daemon-reload
sudo systemctl enable --now celery celerybeat
sudo systemctl status celery
```

```
sudo journalctl -u celery -f
```

```
# 1. Gunicorn/Django access & error logs (since we log to stdout/stderr)
sudo journalctl -u django -n 50 --no-pager

# 2. Last 50 lines + follow new ones live (super useful)
sudo journalctl -u django -n 50 -f

# 3. Celery worker logs
sudo journalctl -u celery -n 50 --no-pager

# 4. Celery beat logs
sudo journalctl -u celerybeat -n 50 --no-pager

# 5. Nginx error log (if you ever get 502/504 again)
sudo tail -n 50 /var/log/nginx/error.log
```