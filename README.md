# espoofer

*espoofer* is an open-source testing tool to bypass SPF, DKIM, and DMARC authentication in email systems. It helps mail server administrators and penetration testers to check whether the target email server and client are vulnerable to email spoofing attacks or can be abused to send spoofing emails.

<!-- ![Gmail spoofing demo](images/gmail-spoofing-demo.png "espoofer demo" )
 -->
<p align="center">
<kbd>
<img src="images/gmail-spoofing-demo.png" height="300">
</kbd>
<br>Figure 1. A case of our spoofing attacks on Gmail (Fixed, <a href="https://youtu.be/xuKZpT0rsd0">Demo video</a>)
</p>

## Why build this tool?

Email spoofing is a big threat to both individuals and organizations ([Yahoo breach](https://arstechnica.com/tech-policy/2017/03/fbi-hints-that-hack-of-semi-privileged-yahoo-employee-led-to-massive-breach/), [John podesta](https://www.cbsnews.com/news/the-phishing-email-that-hacked-the-account-of-john-podesta/)). To address this problem, modern email services and websites employ authentication protocols -- SPF, DKIM, and DMARC -- to prevent email forgery. 

Our latest research shows that the implementation of those protocols suffers a number of security issues, which can be exploited to bypass SPF/DKIM/DMARC protections. Figure 1 demonstrates one of our spoofing attacks to bypass DKIM and DMARC in Gmail. For more technical details, please see our [Black Hat USA 2020 talk](https://www.blackhat.com/us-20/briefings/schedule/#you-have-no-idea-who-sent-that-email--attacks-on-email-sender-authentication-19902) (with [presentation video](https://www.youtube.com/watch?v=ar_lVqkWcHk&list=PL--A-gWJV1dJ19SyhkzklMC3C8ra1kK5-&index=5&t=30s&ab_channel=BlackHat))
 or [USENIX security 2020 paper](https://www.jianjunchen.com/publication/composition-kills-a-case-study-of-email-sender-authentication/). 

- Black Hat USA 2020 slides (PDF): [You have No Idea Who Sent that Email: 18 Attacks on Email Sender Authentication](http://i.blackhat.com/USA-20/Thursday/us-20-Chen-You-Have-No-Idea-Who-Sent-That-Email-18-Attacks-On-Email-Sender-Authentication.pdf) 
- USENIX security 2020 paper (PDF): [Composition Kills:
A Case Study of Email Sender Authentication](https://www.usenix.org/system/files/sec20fall_chen-jianjun_prepub_0.pdf)
    - [Distinguished Paper Award Winner](https://www.usenix.org/conference/usenixsecurity20/presentation/chen-jianjun)

In this repo, we summarize all test cases we found and integrate them into this tool to help administrators and security-practitioners quickly identify and locate such security issues.

<details><summary>Please use the following citation if you do scentific research (Click me).  </summary>
<p>

*Latex version:*

```tex
@inproceedings{chen-email,
author = {Jianjun Chen and Vern Paxson and Jian Jiang},
title = {Composition Kills: A Case Study of Email Sender Authentication},
booktitle = {29th {USENIX} Security Symposium ({USENIX} Security 20)},
year = {2020},
isbn = {978-1-939133-17-5},
pages = {2183--2199},
url = {https://www.usenix.org/conference/usenixsecurity20/presentation/chen-jianjun},
publisher = {{USENIX} Association},
month = aug,
}
```

*Word version:*

Jianjun Chen, Vern Paxson, and Jian Jiang. "Composition kills: A case study of email sender authentication." In 29th USENIX Security Symposium (USENIX Security 20), pp. 2183-2199. 2020.

</p>
</details>

## Installation
- Download this tool
```
git clone https://github.com/chenjj/espoofer
```

- Install dependencies
```
sudo pip3 install -r requirements.txt
```
> *Python version: Python 3 (**>=3.7**).*

## Usage
espoofer has three work modes: *server* ('s', default mode), *client* ('c') and *manual* ('m'). In *server* mode, espoofer works like a mail server to test validation in receiving services. In *client* mode, espoofer works as an email client to test validation in sending services. *Manual* mode is used for debug purposes. 

<p align="center">
<img src="images/email-authentication-flow.png" ><br>
Figure 2. Three types of attackers and their work modes
</p>

#### Server mode
To run espoofer in server mode, you need to have: 1) an IP address (`1.2.3.4`), which outgoing port 25 is not blocked by the ISP, and 2) a domain (`attack.com`). 


1. Domain configuration

- Set DKIM public key for `attack.com`

```
selector._domainkey.attacker.com TXT  "v=DKIM1; k=rsa; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDNjwdrmp/gcbKLaGQfRZk+LJ6XOWuQXkAOa/lI1En4t4sLuWiKiL6hACqMrsKQ8XfgqN76mmx4CHWn2VqVewFh7QTvshGLywWwrAJZdQ4KTlfR/2EwAlrItndijOfr2tpZRgP0nTY6saktkhQdwrk3U0SZmG7U8L9IPj7ZwPKGvQIDAQAB"
```

- Set SPF record for `attack.com`

```
attack.com TXT "v=spf1 ip4:1.2.3.4 +all"
```

2. Configure the tool in config.py

```
config ={
	"attacker_site": b"attack.com", # attack.com
	"legitimate_site_address": b"admin@bank.com", # legitimate.com
	"victim_address": b"victim@victim.com", # victim@victim.com
	"case_id": b"server_a1", # server_a1
}
```

You can list find the case_id of all test cases using `-l` option:

```
python3 espoofer.py -l
```

3. Run the tool to send a spoofing email

```
python3 espoofer.py
```

You can change case_id in the config.py or use `-id` option in the command line to test different cases:

```
python3 espoofer.py -id server_a1
```

#### Client mode 

To run epsoofer in client mode, you need to have an account on the target email services. This attack exploits the failure of some email services to perform sufficient validation of emails received from local MUAs. For example, `attacker@gmail.com` tries to impersonate `admin@gmail.com`. 
1. Configure the tool in config.py

```
config ={
	"legitimate_site_address": b"admin@gmail.com",  
	"victim_address": b"victim@victim.com", 
	"case_id": b"client_a1",

	"client_mode": {
		"sending_server": ("smtp.gmail.com", 587),  # SMTP sending serve ip and port
		"username": b"attacker@gmail.com", # Your account username and password
		"password": b"your_passward_here",
	},
}
```

You can list find the case_id of all test cases using `-l` option:

```
python3 espoofer.py -l
```

> Note: `sending_server` should be the SMTP sending server address, not the receiving server address.


2. Run the tool to send a spoofing email

```
python3 espoofer.py -m c
```

You can change case_id in the config.py and run it again, or you can use `-id` option in the command line:

```
python3 espoofer.py -m c -id client_a1
```

#### Manual mode

Here is an example of manual mode:

```
python3 espoofer.py -m m -helo attack.com -mfrom <m@attack.com> -rcptto <victim@victim.com> -data raw_msg_here -ip 127.0.0.1 -port 25
```

### Screenshots

1. A brief overview of test cases.

<p align="center">
<kbd>
<img src="images/list_caseid.png">
</kbd>
</p>

## Bugs found with this tool

* Gmail.com DMARC bypass demo video, https://youtu.be/xuKZpT0rsd0
* Outlook.com DMARC bypass video, https://youtu.be/IsWgAEbPaK0
* Yahoo.com DMARC bypass video, https://youtu.be/DRepfStOruE
* Protonmail.com DMARC bypass video, https://youtu.be/bh4_SoPniMA
* CVE-2020-12272, OpenDMARC bypass bug report, https://sourceforge.net/p/opendmarc/tickets/237/
* CVE-2019-20790, OpenDMARC and pypolicyd-spf bypass bug report, https://sourceforge.net/p/opendmarc/tickets/235/
* Mail.ru DMARC bypass bug report on HackerOne, https://hackerone.com/reports/731878

Welcome to send a pull request to file your bug report here. 

## Q&A

1. How do I know if the email has bypassed DMARC authentication successfully? 

You can check it in the Authentication-results header in the raw message headers. If the header shows `dmarc=pass`, it means the email has passed the DMARC authentication.  You can check some demos video [here](https://www.youtube.com/playlist?list=PL--A-gWJV1dJ19SyhkzklMC3C8ra1kK5-).

2. Why do emails fail to send?

There are several possible reasons if you fail to send an email: 1) your ISP blocks outgoing emails to port 25 to prevent spam. In this case, you need to ask for permission from the ISP; 2) the IP address is in the spam list of the target email services. In many cases, you resolve the problem here, https://www.spamhaus.org/lookup/ ;  3) some email services check if there is a PTR record for the sending IP, you may also need to set the PTR record to bypass this check; 4) the email cannot pass the format validation of the target email service, you may want to try a different test case. 

3. Why the email goes to the spam folder? Any way to avoid this?

Currently, espoofer focuses on bypassing SPF/DKIM/DMARC authentication and doesn't aim for spam filter bypass. But you could try to use a reputable sending IP address, domain, and benign message content to bypass the spam filter.

4. Why I send an email successfully but the email didn't show up in either inbox or spam folder?

In our prior experiences, some email services filter suspicious emails silently.

5. When testing server_a5/a6, why I cannot set specical characters like "(" in the domain?

You will need to set up your own authority DNS server, rather than use third-party DNS hosting services,  as some DNS hosting services have restrictions on setting specical characters. See [issue](https://github.com/chenjj/espoofer/issues/2#issuecomment-686918954).

## Credits

Welcome to add more test cases.



<!-- *This repo is created for the vendors to reproduce our reported issues, so this tool is not useable without additional instructions. We will update it after the affected vendors have fixed our reported bugs.*
 -->
