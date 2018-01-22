#! /usr/bin/python

#import modules
import argparse
import os
import ConfigParser
import requests, json
import sys
reload(sys)
sys.setdefaultencoding('utf-8')
import re
from jira import JIRA

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

def open_jira_session(server, username, password, verify=False):
    return JIRA(options={'server': server, 'verify': verify},
                basic_auth=(username, password))

def color_jira_summary(summary):
    summary = summary.replace('WARNING', '{color:#f79232}WARNING{color}')
    summary = summary.replace('OK', '{color:#14892c}OK{color}')
    summary = summary.replace('CRITICAL', '{color:#d04437}CRITICAL{color}')
    return summary
def open_jira_issue(jira, args):
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
        print error
    for ele in args.components:
        components.append({'name': ele})
    issue_dict = {
        'project': {'key': args.project},
        'summary': args.summary,
        'description': color_jira_summary(args.description),
        'issuetype': {'name': args.issuetype},
        'priority': {'name': prio},
        'components': components,
        'customfield_10502': { 'value': args.environment},
        }
    try:
         issue = jira.create_issue(fields=issue_dict)
    except Exception as error:
        print error
    return issue

#update jira issue for organisation and requesttype does not work at the moment
def update_jira_issue(jira, issue, args):
    issue_fields = {'customfield_10003': args.organisation,
              'customfield_10002': args.requesttype,
             }
    try:
        issue.update(fields=issue_fields)
    except Exception as error:
        print error


def comment_jira_issue(jira, args, config):
    pattern = re.compile("^(\w+)-(\d+)$")
    headers = {'Accept': 'application/json', 'X-HTTP-Method-Override': 'GET'}
    data = {'type': 'Service', 'filter': "host.name == filterHost && service.name == filterService", "filter_vars": { "filterHost": args.host, "filterService": args.service}}
    r = requests.post(config['icinga2_url'] + "objects/comments", headers=headers, json=data, verify=False, auth=(config['icinga2_apiuser'], config['icinga2_apipassword']))
    if (r.status_code == 200):
        for ele in  r.json()['results']:
            if pattern.match(ele['attrs']['text']):
                jiracomment = jira.add_comment(ele['attrs']['text'], args.summary)    # no Issue object required
                return  ele['attrs']['name']
    else:
        print r.text
        r.raise_for_status()

def icinta2_remove_comment(config, args, comment_name):
    headers = {
    'Accept': 'application/json',}
    commentmatch = args.host + "!" + args.service + "!" + comment_name
    data = {"comment": commentmatch }
    r = requests.post(config['icinga2_url'] + "actions/remove-comment", headers=headers, json=data, verify=False, auth=(config['icinga2_apiuser'], config['icinga2_apipassword']))

def icinga2_service_add_comment(config, args, comment):
    headers = {
    'Accept': 'application/json',}
    data = {'type': 'Service', 'filter': "host.name == filterHost && service.name == filterService", "filter_vars": { "filterHost": args.host, "filterService": args.service}, "author": config['icinga2_author'], "comment": comment}
    r = requests.post(config['icinga2_url'] + "actions/add-comment", headers=headers, json=data, verify=False, auth=(config['icinga2_apiuser'], config['icinga2_apipassword']))

if __name__ == '__main__':
    args = arg_pars()
    try:
        config = read_configuration_file(args.configfile)
    except IOError as e:
        print("Could not find configuration file: %s" % e)
        sys.exit(2)
    except ValueError as e:
        print(e)
        sys.exit(2)
    except ConfigParser.NoSectionError as e:
        print("Configuration file is corrupt: %s" % e)
        sys.exit(2)

    try:
        jira = open_jira_session(config['jira_url'], config['jira_username'], config['jira_password'])
    except Exception as e:
        print e
        sys.exit(2)
    if args.notifytype.lower() == "problem":
        try:
            new_issue = open_jira_issue(jira, args)
            icinga2_service_add_comment(config, args, str(new_issue)) 
        except Exception as e:
            print "There is a exception in creating jira issue and comment issue number in icinga2\n", e
            sys.exit(2)
        
    elif args.notifytype.lower() == "recovery":
        try:
            comment_name = comment_jira_issue(jira, args, config)
            icinta2_remove_comment(config, args, comment_name)              
        except Exception as e:
            print "There is a exception in creating jira comment and removing comment in icinga2\n", e
            sys.exit(2)

