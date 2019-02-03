import logging
import sys
import datetime
import certstream
from tld import get_tld
from suspicious import keywords, tlds
from difflib import SequenceMatcher
import smtplib
from cred import credmail
s = smtplib.SMTP('smtp.gmail.com', 587)
s.starttls()
s.login(credmail["mail"],credmail["pass"])

def score_domain(domain,check):

    #bad tld
    score = 0
    for t in tlds:
        if domain.endswith(t):
            score += 5

    try:
        res = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)
        domain = '.'.join([res.subdomain, res.domain])
    except Exception:
        pass

    if domain.startswith('.'):
        domain = domain[1:]

    if domain.startswith('*.'):
        domain = domain[2:]


    score += SequenceMatcher(None, check, domain).ratio()*100

    bad_chars = ['\u0430', '\u03F2', '\u0435', '\u043E', '\u0440', '\u0455', '\u0501', '\u051B', '\u051D']
    result = [bad_chars[i] for i in range(len(bad_chars)) if bad_chars[i] in domain]
    if result:
        score+= 50

    return score

def print_callback(message, context):
    logging.debug("Message -> {}".format(message))

    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        if len(all_domains) == 0:
            domain = "NULL"
        else:
            domain = all_domains[0]

        print(domain)
        print(score_domain(domain,'facebook'))
        scn = message["data"]["chain"][0]["subject"]["CN"]
        cii = message["data"]["cert_index"]
        clname = message["data"]["source"]["name"]


        dc = "facebook"
        mto = "alok760@gmail.com"
        print("checking for " + dc)

        if score_domain(domain,dc) > 65:
            message = "Subject: Phishing report for Your Subscribed Domain : '%s' \n\n" % (dc)
            message += "URL detected: '%s'   |   Certification Authority: '%s'   |   Certificate Index: '%s'   |   Certificate Log: '%s'" % (domain, str(scn), str(cii), str(clname))

            s.sendmail("internship760@gmail.com", str(mto, message))
            print("mail sent")

            print(".")
            print(".")
            print(".")
            print(".")
        sys.stdout.flush()

logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)

certstream.listen_for_events(print_callback, 'wss://certstream.calidog.io')
