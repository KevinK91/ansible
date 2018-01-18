#! /usr/bin/python

#import modules
import argparse
import os
import sys
import subprocess

def arg_pars():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', action='store', dest='config',  required=True,
                    help='Set the business configuration which contains all business processes ')
    parser.add_argument('--process', action='store', dest='process',  required=True,
                    help='Define which process needs to be checked. \
                        Only processes which have subrpocesses can be used otherwise will the check fail \
                        Command to list all processes:  \ 
                        icingacli businessprocess process list <Name of the config> \
                        ')

    return parser.parse_args()


if __name__ == '__main__':
    args = arg_pars()
    cmd = 'icingacli businessprocess process --details --colors --config ' + args.config + ' check ' + args.process
    try:
        proc = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, preexec_fn=demote(args.user))
        print proc.communicate()[0]
    except OSError, error:
        error = str(error)
        print "CRITICAL: Error trying to run utility %s" % error
        sys.exit

