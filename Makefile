install-vault-svc:
	sudo cp vault.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable vault

install-requirements:
	python3 -m pip install -r requirements.txt

start:
	sudo systemctl start vault

restart:
	sudo systemctl restart vault

wipe:
	sudo systemctl stop vault
	sudo rm -rf /tmp/data
	sudo systemctl start vault