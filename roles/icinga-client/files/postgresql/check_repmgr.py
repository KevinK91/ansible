#! /usr/bin/python

#import modules
import argparse
import subprocess
import sys
import os
from pwd import getpwnam  

def arg_pars():
    parser = argparse.ArgumentParser()
    parser.add_argument('-rs', action='store', dest='rolestate', 
                    help='This parameter is only needed if the action is role\
                   primary or standby are allowed')
    parser.add_argument('-f', action='store', dest='file', default='/etc/repmgr/10/repmgr.conf',
                    help=' Defines the replication configuration file\
                   Default is /etc/repmgr/10/repmgr.conf')
    parser.add_argument('-a', action='store', dest='action', required=True,
                    help=' Define which kind of check should be done\
                  role: checks if the node has the expected role\
                  replication-lag: checks if the node is lagging by more than replication_lag_warning or replication_lag_critical\
                  archive-ready: checks for WAL files which have not yet been archived\
                  downstream: checks that the expected downstream nodes are attached\
                  slots: checks there are no inactive replication slots')
    return parser.parse_args()



def repmgr_check(args):
    cmd = '/usr/bin/repmgr node check -f ' + args.file + ' --nagios --' + args.action
    try: 
        proc = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        result = proc.communicate()[0]
        print result
        if proc.wait() == 6:
            sys.exit(2)
        if args.rolestate not in result:
            sys.exit(2)
        sys.exit(proc.wait())
    except OSError, error:
        error = str(error)
        if error == "No such file or directory":
            print "UNKNOWN: Cannot find utility '%s" % error
            sys.exit(3)
        else:
            print "UNKNOWN: Error trying to run utility %s" % error
            sys.exit(3)


def main():
    repmgr_check(arg_pars()) 

if __name__ == '__main__':
  main()
