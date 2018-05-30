# This file is part of LoudML mail plug-in. LoudML mail plug-in is free software:
# you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, version 2.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright Red Mint Network

import logging
import json
import smtplib
import ssl

from email.message import EmailMessage
from email.headerregistry import Address

from loudml.api import (
    Hook,
    Plugin,
)

from voluptuous import (
    All,
    Any,
    Email,
    Invalid,
    Optional,
    Range,
    Required,
    Schema,
)

class MailPlugin(Plugin):
    """
    LoudML mail plug-in
    """

    CONFIG_SCHEMA = Schema({
        Required('smtp'): Schema({
            Required('host'): str,
            Optional('port', default=0): All(int, Range(min=0, max=65535)),
            Optional('tls', default=False): bool,
            Optional('user'): str,
            Optional('password', default=''): str,
        }),
    })


class MailHook(Hook):
    """
    Send e-mail notifications on anomaly detection
    """

    TEMPLATES = {
        'anomaly_start': {
            'subject': \
"""
[LoudML] anomaly detected! (model={model}, score={score})"
""",
            'content': \
"""
Anomaly detected by LoudML!

date={date}
model={model}
score={score}
predicted={predicted}
observed={observed}
"""
        },
        'anomaly_end': {
            'subject': \
"""
[LoudML] anomaly end (model={model}, score={score})"
""",
            'content':
"""
Anomaly end

date={date}
model={model}
score={score}
""",
        },
    }

    CONFIG_SCHEMA = Schema({
        Required('from'): Schema({
            Optional('name', default=""): str,
            Required('address'): Email(),
        }),
        Required('to'): Schema({
            Optional('name', default=""): str,
            Required('address'): Email(),
        }),
        Optional('templates', default=TEMPLATES): Schema({
            Optional('anomaly_start', default=TEMPLATES['anomaly_start']): {
                Optional('subject', default=TEMPLATES['anomaly_start']['subject']): str,
                Optional('content', default=TEMPLATES['anomaly_start']['content']): str,
            },
            Optional('anomaly_end', default=TEMPLATES['anomaly_end']): {
                Optional('subject', default=TEMPLATES['anomaly_end']['subject']): str,
                Optional('content', default=TEMPLATES['anomaly_end']['content']): str,
            },
        }),
    })

    def send_mail(self, template_name, *args, **kwargs):
        """
        Build e-mail from template and send it
        """

        plugin_cfg = MailPlugin.instance.config

        if plugin_cfg is None:
            logging.error("mail plug-in is not configured")
            return

        smtp_cfg = plugin_cfg['smtp']
        template = self.config['templates'][template_name]

        msg = EmailMessage()

        addr = self.config['from']['address'].split('@')
        msg['From'] = Address(
            self.config['from']['name'],
            addr[0],
            addr[1],
        )
        addr = self.config['to']['address'].split('@')
        msg['To'] = Address(
            self.config['to']['name'],
            addr[0],
            addr[1],
        )
        msg['Subject'] = template['subject'].strip().format(**kwargs)
        msg.set_content(template['content'].strip().format(**kwargs))

        if smtp_cfg['tls']:
            smtp_cls = smtplib.SMTP_SSL
        else:
            smtp_cls = smtplib.SMTP

        try:
            client = smtp_cls(
                host=smtp_cfg['host'],
                port=smtp_cfg['port'],
            )

            user = smtp_cfg.get('user')
            if user:
                password = smtp_cfg.get('password')
                client.login(user, password)

            logging.info("sending alert to %s", self.config['to']['address'])

            client.send_message(msg)
        except (
            smtplib.SMTPException,
            ssl.SSLError,
        ) as exn:
            logging.error("cannot execute %s.%s hook: %s",
                          kwargs['model'], self.name, str(exn))

    def on_anomaly_start(
        self,
        model,
        dt,
        score,
        predicted,
        observed,
        anomalies,
        *args,
        **kwargs
    ):
        ano_desc = [
            "feature '{}' is too {} (score = {:.1f})".format(
                 feature,
                 ano['type'],
                 ano['score']
            )
            for feature, ano in anomalies.items()
        ]

        self.send_mail(
            'anomaly_start',
            model=model,
            date=str(dt.astimezone()),
            score=score,
            predicted=json.dumps(predicted),
            observed=json.dumps(observed),
            reason="\n".join(ano_desc),
            **kwargs
        )

    def on_anomaly_end(
        self,
        model,
        dt,
        score,
        *args,
        **kwargs
    ):
        self.send_mail(
            'anomaly_end',
            model=model,
            date=str(dt.astimezone()),
            score=score,
            **kwargs
        )
