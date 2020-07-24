import dkim


def bs64encode(value):
	import base64
	return b"=?utf-8?B?"+ base64.b64encode(value) + b"?="

def quoted_printable(value):
	import quopri
	return b"=?utf-8?Q?"+ quopri.encodestring(value)  + b"?="

def id_generator(size=6):
	import random
	import string
	chars=string.ascii_uppercase + string.digits
	return (''.join(random.choice(chars) for _ in range(size))).encode("utf-8")

def get_date():
	from time import gmtime, strftime
	mdate= strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime())
	return (mdate).encode("utf-8")

def query_mx_record(domain):
	import dns.resolver
	try:
		mx_answers = dns.resolver.query(domain, 'MX')
		for rdata in mx_answers:
			a_answers = dns.resolver.query(rdata.exchange, 'A') 
			for data in a_answers:
				return str(data)
	except Exception as e:
		import traceback
		traceback.print_exc()

def get_mail_server_from_email_address(e):
	domain = e.split(b"@")[1]
	return query_mx_record(domain.decode("utf-8"))

def recursive_fixup(input, old, new):
    if isinstance(input, dict):
        items = list(input.items())
    elif isinstance(input, (list, tuple)):
        items = enumerate(input)
    else:
        return input.replace(old, new)

    # now call ourself for every value and replace in the input
    for key, value in items:
        input[key] = recursive_fixup(value, old, new)
    return input


def generate_dkim_header(dkim_msg, dkim_para):
	d = dkim.DKIM(dkim_msg)
	dkim_header = d.sign(dkim_para["s"], dkim_para["d"], open("dkimkey","rb").read(), canonicalize=(b'simple',b'relaxed'), include_headers=[b"from"]).strip()+b"\r\n"
	return dkim_header
