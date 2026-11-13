df -h /srv/backup
ls -lh /srv/backup/postgres | tail
tail -n 20 /var/log/pg-backup.log
cat /etc/cron.d/pg-backup
systemctl status cron
apt update
apt upgrade -y
reboot
