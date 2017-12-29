#! /usr/bin/python

#import modules
import argparse
import os
import ConfigParser
from jira import JIRA

MANDATORY_CONFIG_ENTRIES = [
    'url', 'username', 'password', 'jira_project_key', 'jira_issue_type']

def arg_pars():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', action='store', dest='configfile',  required=True,
                    help='This configuration file contains the Jira connection parameters')
    parser.add_argument('-r', action='store', dest='reporter',  required=True,
                    help='Set the reporter in Jira for create the issue')
    parser.add_argument('-i', action='store', dest='issue', 
                    help='Set the issue to close or modify the issue\
                    Use the correct id or name')
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
    parser.add_argument('-d', action='store', dest='description',  required=True,
                    help='Set the description ')
    parser.add_argument('-nt', action='store', dest='notifytype',  required=True,
                    help='Set the notification type from icinga2')
#    parser.add_argument('-ns', action='store', dest='notifystate',  required=True,
#                    help='Set the description ')
#    parser.add_argument('-nn', action='store', dest='notifyname',  required=True,
#                    help='Set the description ')
#    parser.add_argument('-nd', action='store', dest='notifydisplayname',  required=True,
#                    help='Set the description ')
    

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


if __name__ == '__main__':
    args = arg_pars()
    for arg in vars(args):
        print arg, getattr(args, arg)
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

    jira = open_jira_session(config['url'],
                             config['username'],
                             config['password'])

    jira.create_issue(project=args.project, summary=args.summary,
                              description=args.description, issuetype={'name': args.issuetype}, reporter=args.reporter, components=args.components)
#    if 
    
#    print config['url'], config['username'], config['password'], config['jira_project_key'], config['jira_issue_type']
