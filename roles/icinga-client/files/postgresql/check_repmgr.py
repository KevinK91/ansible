#! /usr/bin/python

#import modules
import argparse
import subprocess
import sys
import os
from pwd import getpwnam  

def arg_pars():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', action='store', dest='user', default='postgres',
                    help='To execute the replication commands on localhost\
                   Default user is postgres')
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

def demote(user):
    """Pass the function 'set_ids' to preexec_fn, rather than just calling
    setuid and setgid. This will change the ids for that subprocess only"""

    def set_ids():
        os.setgid(getpwnam(user).pw_gid)
        os.setuid(getpwnam(user).pw_uid)

    return set_ids


def repmgr_check(args):
    cmd = '/usr/bin/repmgr node check -f ' + args.file + ' --nagios --' + args.action
    try: 
        proc = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, preexec_fn=demote(args.user))
        print proc.communicate()[0]
        if proc.wait() == 6:
            sys.exit(2)
        sys.exit(proc.wait())
    except OSError, error:
        error = str(error)
        if error == "No such file or directory":
            print "UNKNOWN: Cannot find utility '%s" % error
            sys.exit
        else:
            print "UNKNOWN: Error trying to run utility %s" % error


def main():
    repmgr_check(arg_pars()) 

if __name__ == '__main__':
  main()
