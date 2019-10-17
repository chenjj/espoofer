#!/usr/bin/env python
# -*- coding: utf-8 -*-

from socket import *
import time
import ssl

try:
    from StringIO import StringIO ## for Python 2
except ImportError:
    from io import StringIO ## for Python 3

class mailsender(object):
	mail_server =""
	rcpt_to = ""
	email_data = ""
	helo = ""
	mail_from = ""
	starttls = False

	client_socket = None
	tls_socket = None

	def __init__(self):
		pass

	def set_param(self, mail_server, rcpt_to, email_data, helo, mail_from, starttls=False):
		self.mail_server = mail_server
		self.rcpt_to = rcpt_to
		self.email_data = email_data
		self.helo = helo
		self.mail_from = mail_from
		self.starttls = starttls

	
	def establish_socket(self):
		client_socket = socket(AF_INET, SOCK_STREAM)
		client_socket.connect(self.mail_server)
		self.print_recv_msg(client_socket)

		if self.starttls == True:
			client_socket.send(b"ehlo "+ self.helo +b"\r\n")
			self.print_recv_msg(client_socket)
			client_socket.send(b"starttls\r\n")
			self.print_recv_msg(client_socket)
			tls_socket = ssl.wrap_socket(client_socket, ssl_version=ssl.PROTOCOL_TLS)
			self.tls_socket = tls_socket
		self.client_socket = client_socket

	def send_msg(self, client_socket):
		client_socket.send(b"ehlo "+self.helo+b"\r\n")
		print("ehlo "+ self.helo.decode("utf-8")+"\r\n") 
		self.print_recv_msg(client_socket)
		client_socket.send(b'mail from: '+self.mail_from+b'\r\n')
		#time.sleep(5)
		print('mail from: '+self.mail_from.decode("utf-8")+'\r\n')
		self.print_recv_msg(client_socket)
		#time.sleep(5)
		client_socket.send(b"rcpt to: "+self.rcpt_to+b"\r\n")
		print("rcpt to: "+self.rcpt_to.decode("utf-8")+"\r\n")
		#time.sleep(2)
		self.print_recv_msg(client_socket)
		

		client_socket.send(b"data\r\n")
		print( "data\r\n")
		self.print_recv_msg(client_socket)
		client_socket.send(self.email_data+b"\r\n.\r\n")
		print( self.email_data.decode("utf-8")+"\r\n.\r\n")
		time.sleep(1)
		self.print_recv_msg(client_socket)

	def send_quit_msg(self, client_socket):
		client_socket.send(b"quit\r\n")
		self.print_recv_msg(client_socket)

	def close_socket(self):
		if self.tls_socket != None:
			self.tls_socket.close()
		if self.client_socket != None:
			self.client_socket.close()

	def read_line(self, sock):
		buff = StringIO()
		while True:
			data = (sock.recv(1)).decode("utf-8")
			buff.write(data)
			if '\n' in data: break
		return buff.getvalue().splitlines()[0]

	def print_recv_msg(self, client_socket):
		time.sleep(1)

		while True:
			line  = self.read_line(client_socket)
			print(line) 
			if "-" not in line:
				break
			else:
				if len(line) > 5 and "-" not in line[:5]:
					break
			time.sleep(0.1)

	def send_email(self):
		self.establish_socket()
		try:
			if self.starttls == True:
				self.send_msg(self.tls_socket)
				self.send_quit_msg(self.tls_socket)
			else:
				self.send_msg(self.client_socket)
				self.send_quit_msg(self.client_socket)
			self.close_socket()
		except Exception as e:
			import traceback
			traceback.print_exc()
		
	def __del__(self):
		self.close_socket()
