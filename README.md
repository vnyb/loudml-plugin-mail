# loudml-plugin-mail

Plug-in for LoudML for sending e-mail notifications on anomaly detection.

# Installation

```bash
./setup.py install
```
# Static configuration

Copy example file to LoudML configuration directory:

```
cp mail.yml /etc/loudml/plugins.d/
```

Edit `/etc/loudml/plugins.d/mail.yml` to configure the SMTP client.

# Hook configuration

Copy example file:

```
cp example.json my-email-hook.json
```

Edit hook file to configure:
 - sender/recipient addresses
 - subject template
 - content template

Create hook on LoudML instance:
 ```
curl -X PUT -H 'Content-Type: application/json' localhost:8077/models/hooks -d @my-email-hook.json
```
