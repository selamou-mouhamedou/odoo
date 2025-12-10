# Stop Odoo
pkill -f odoo-bin

# Start Odoo manually
cd ~/odoo/18.0 && ./venv/bin/python ./odoo/odoo-bin -c odoo.conf

# View logs
tail -f ~/odoo/18.0/odoo.log