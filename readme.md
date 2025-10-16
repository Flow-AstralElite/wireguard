# Run
```bash
curl -fsSL https://raw.githubusercontent.com/flow-astralelite/wireguard/main/install.sh | sudo bash
```
## Get client config
```bash
cat /etc/wireguard/clients/client1.conf
```
## Get QR to scan in mobile
```bash
qrencode -t ansiutf8 < /etc/wireguard/clients/client1.conf
```
