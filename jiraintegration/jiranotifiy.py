#!/usr/bin/python

import logging
import logging.handlers
import argparse
import os
import ConfigParser
import requests, json
import sys
import random
reload(sys)
sys.setdefaultencoding('utf-8')
import re
import urllib3
from jira import JIRA

# disable invalid certificate warnung (icina2)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#
# SETUP LOGGING
#
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s ['+str("%08d" % random.randint(0,99999999))+'] %(levelname)s %(message)s', datefmt="%Y-%m-%d %H:%M:%S")
ch = logging.handlers.WatchedFileHandler("/tmp/jiranotifiy.log", mode='a')
ch.setLevel(logging.DEBUG)
ch.setFormatter(formatter)
logger.addHandler(ch)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

MANDATORY_CONFIG_ENTRIES = [
    'jira_url', 'jira_username', 'jira_password', 'icinga2_url', 'icinga2_apiuser', 'icinga2_apipassword', 'icinga2_author']

def arg_pars():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', action='store', dest='configfile',  required=True,
                    help='This configuration file contains the Jira connection parameters')
    parser.add_argument('-p', action='store', dest='project',  required=True,
                    help='Set the project in Jira\
                    Use the correct id or name')
    parser.add_argument('-s', action='store', dest='summary',
                    help='Set the summary for the Jira issue')
    parser.add_argument('-t', action='store', dest='issuetype',  required=True,
                    help='Set the issuetype \
                    Use the correct id or name')
    parser.add_argument('-c', action='store', dest='components', nargs='*', type=str,
                    help='Set the components \
                    Use the correct id or name')
    parser.add_argument('-pr', action='store', dest='priority',
                    help='Set the priority for WARNING and CRITICAL of the jira issue\
                        Write for exmaple Low:High important is the notation <Waring issue priority>:<Critical issue priority>\
                        Otherwise always be used the onle one which is configured.')
    parser.add_argument('-d', action='store', dest='description',  required=True,
                    help='Set the description ')
    parser.add_argument('-nt', action='store', dest='notifytype',  required=True,
                    help='Set the notification type from icinga2')
    parser.add_argument('-nh', action='store', dest='host', 
                    help='Set the hostname from icinga2')
    parser.add_argument('-nrt', action='store', dest='requesttype', 
                    help='Set the custom filed for request type in Jira to see the issue in the portal\
                     Ask your Jira admin about the internal id')
    parser.add_argument('-sid', action='store', dest='servicedeskid',
                    help='Set the JIRA service desk id')
    parser.add_argument('-nst', action='store', dest='servicestate', 
                    help='Set the service state from icinga2')
    parser.add_argument('-ns', action='store', dest='service', 
                    help='Set the service from icinga2')
    parser.add_argument('-nc', action='store', dest='comment', 
                    help='Set notification comment from icinga2')
    parser.add_argument('-no', action='store', dest='organisation', 
                    help='Set the custom field for organisation. \
                    This field must be created in Jira\
                    Ask your Jira admin about the internal id')
    parser.add_argument('-ne', action='store', dest='environment', 
                    help='Set the custom field for envirionment. \
                    This field must be created in Jira\
                    Ask your Jira admin about the internal id')

    return parser.parse_args()

def read_configuration_file(cfgfile):
    with open(cfgfile) as file_pointer:
        return parse_and_validate_config_file(file_pointer)

def parse_and_validate_config_file(file_pointer):
    config_parser = ConfigParser.ConfigParser()
    config_parser.readfp(file_pointer)
    config = dict(config_parser.items('settings'))
    for key in MANDATORY_CONFIG_ENTRIES:
        if key not in config:
            raise ValueError('config file is missing: %s' % key)
    return config

def color_jira_summary(summary):
    summary = summary.replace('WARNING', '{color:#f79232}WARNING{color}')
    summary = summary.replace('OK', '{color:#14892c}OK{color}')
    summary = summary.replace('CRITICAL', '{color:#d04437}CRITICAL{color}')
    return summary

def open_jira_issue(config, args):
    components = list()
    try:
        if ":" not in args.priority:
            prio = args.priority
        else:         
            prio = args.priority.split(":")
            if "WARNING" in args.servicestate:
                prio = prio[0]
            elif "CRITICAL" in args.servicestate:
                prio = prio[1]
    except Exception as error:
        logger.error('failed to open jira issue: ' + str(error))

    for ele in args.components:
        components.append({'name': ele})

    # create jira ticket
    jira = JIRA(config['jira_url'], config['jira_username'], config['jira_password'])
    return jira.create_ticket(args.servicedeskid, args.requesttype, args.summary, color_jira_summary(args.description), components, args.environment, prio)

def resolve_jira_issue(config, args):
    pattern = re.compile("^(\w+)-(\d+)$")
    headers = {'Accept': 'application/json', 'X-HTTP-Method-Override': 'GET'}
    data = {'type': 'Service', 'filter': "host.name == filterHost && service.name == filterService", "filter_vars": { "filterHost": args.host, "filterService": args.service}}
    r = requests.post(config['icinga2_url'] + "objects/comments", headers=headers, json=data, verify=False, auth=(config['icinga2_apiuser'], config['icinga2_apipassword']))
    if (r.status_code == 200):
        num_comments = 0
        for ele in  r.json()['results']:
            if pattern.match(ele['attrs']['text']):
                num_comments += 1
                ticket_key = ele['attrs']['text']
                logger.info('jira ticket key in icinga comment found: ' + ticket_key)
                try:
                    jira = JIRA(config['jira_url'], config['jira_username'], config['jira_password'])
                    if jira.is_resolveable(ticket_key):
                        jira.do_transition_resolve(ticket_key, args.summary)
                    elif jira.is_progressable(ticket_key):
                        jira.do_transition_progress(ticket_key, 'Set in progress in order to resolve ticket')
                        if jira.is_resolveable(ticket_key):
                            jira.do_transition_resolve(ticket_key, args.summary)
                        else:
                            logger.error('could not resolve ticket ' + ticket_key + ', ticket is not resolveable after starting progress')
                            raise Exception('could not resolve ticket ' + ticket_key)
                    else:
                        logger.error('could not resolve ticket ' + ticket_key + ', ticket is neither resolveable nor progressable')
                        raise Exception('could not resolve ticket ' + ticket_key)
                    logger.info('successfully resolved jira ticket ' + ticket_key)
                    try:
                        logger.debug('removing icinga comment: ' + ele['attrs']['name'] + ' / ' + ele['attrs']['text'] + ' (' + ticket_key + ')')
                        icinga2_remove_comment(config, args, ele['attrs']['name'])
                        logger.info('removed icinga comment: ' + ele['attrs']['name'] + ' (' + ticket_key + ')')
                    except Exception as e:
                        logger.error('failed to remove icinga comment ' + ele['attrs']['name'] + ' (' + ticket_key + ')' + ': ' + str(e))
                except Exception as e:
                    logger.error('failed to resolve jira ticket ' + ticket_key + ': ' + str(e))
        if num_comments == 0:
            logger.warning('resolve_jira_issue: found no comment matching jira ticket key pattern')
    else:
        logger.error('icinga ticket not found: ' + str(r.text))
        r.raise_for_status()

def icinga2_remove_comment(config, args, comment_name):
    headers = {'Accept': 'application/json'}
    commentmatch = args.host + "!" + args.service + "!" + comment_name
    data = {"comment": commentmatch }
    r = requests.post(config['icinga2_url'] + "actions/remove-comment", headers=headers, json=data, verify=False, auth=(config['icinga2_apiuser'], config['icinga2_apipassword']))
    if r.status_code != 200:
        logger.error('failed to remove icinga comment "' + comment_name + '": ' + str(r.status_code) + ', ' + str(r.text))
    else:
        logger.info('successfully removed icinga comment: "' + comment_name + '"')

def icinga2_service_add_comment(config, args, comment):
    headers = {'Accept': 'application/json'}
    data = {'type': 'Service', 'filter': "host.name == filterHost && service.name == filterService", "filter_vars": { "filterHost": args.host, "filterService": args.service}, "author": config['icinga2_author'], "comment": comment}
    r = requests.post(config['icinga2_url'] + "actions/add-comment", headers=headers, json=data, verify=False, auth=(config['icinga2_apiuser'], config['icinga2_apipassword']))
    if r.status_code != 200:
        logger.error('failed to add icinga comment "' + comment + '": ' + str(r.status_code) + ', ' + str(r.text))
    else:
        logger.info('successfully added icinga comment: "' + comment + '"')

if __name__ == '__main__':

    args = arg_pars()

    logger.debug(str(vars(args)))

    try:
        config = read_configuration_file(args.configfile)
    except IOError as e:
        print("Could not find configuration file: %s" % e)
        logger.error("Could not find configuration file: " + str(e))
        sys.exit(2)
    except ValueError as e:
        print(e)
        logger.error(str(e))
        sys.exit(2)
    except ConfigParser.NoSectionError as e:
        print("Configuration file is corrupt: %s" % e)
        logger.error("Configuration file is corrupt: " + str(e))
        sys.exit(2)

    if args.notifytype.lower() == "problem":
        try:
            new_issue = open_jira_issue(config, args)
            icinga2_service_add_comment(config, args, new_issue) 
        except Exception as e:
            print "There is an exception in creating jira issue and comment issue number in icinga2\n", e
            logger.error("There is an exception in creating jira issue and comment issue number in icinga2: " + str(e))
            sys.exit(2)
        
    elif args.notifytype.lower() == "recovery":
        try:
            resolve_jira_issue(config, args)
        except Exception as e:
            print "There is an exception in creating jira comment and removing comment in icinga2\n", e
            logger.error("There is an exception in resolving jira issue and removing comment in icinga2: " + str(e))
            sys.exit(2)

