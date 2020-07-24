config = {
	"attacker_site": b"attack.com", # attack.com
	"legitimate_site_address": b"admin@legitimate.com", # From header address displayed to the end-user
	"victim_address": b"victim@victim.com", # RCPT TO and message.To header address, 
	"case_id": b"server_a2", #  You can find all case_id using -l option.

	# The following fields are optional
	"server_mode":{
		"recv_mail_server": "", # If no value, espoofer will query the victim_address to get the mail server ip
		"recv_mail_server_port": 25,
		"starttls": False,
	},
	"client_mode": {
		"sending_server": ("smtp.gmail.com", 587),
		"username": b"attacker@gmail.com",
		"password": b"",
	},

	# You can customize the email message header or body here
	"subject_header": b"", 
	"to_header": b"", #  e.g., <alice@example.com>
	"body": b"", 

	# Set the raw email message you want to sent. It's used for replay attacks
	"raw_email": b"", 
}



