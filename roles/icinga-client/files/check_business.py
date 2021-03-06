#! /usr/bin/python

#import modules
import argparse
import os
import sys
import subprocess
import re

def arg_pars():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', action='store', dest='config',  required=True,
                    help='Set the business configuration which contains all business processes ')
    parser.add_argument('--process', action='store', dest='process',  required=True,
                    help='Define which process needs to be checked.\
                        Only processes which have subrpocesses can be used otherwise will the check fail\
                        Command to list available processes\
                        icingacli businessprocess process list <Name of the config>\
                        ')
    parser.add_argument('--color', dest='color', action='store_true', default=False, 
                    help='Activate colored output')
    return parser.parse_args()

#This colored output only wirks in the shell and the normal output is colored in Icingaweb2
def color_output(result):
    result = result.replace("CRITICAL", "\033[1;31;40mCRITICAL\033[0m")
    result = result.replace("WARNING", "\033[1;33;40mWARNING\033[0m")
    result = result.replace("OK", "\033[1;32;40mOK\033[0m")
    return result

def check_business(result, color):
    if re.search('CRITICAL', result) or re.search('WARNING', result) :
	result = result.replace('OK', 'WARNING',1)
        if color: 
            print(color_output(result))
            sys.exit(1)
        print result
        sys.exit(1)
    if color: 
        print(color_output(result))
        sys.exit(0)
    print result
    sys.exit(0)

if __name__ == '__main__':
    args = arg_pars()
    cmd = '/usr/bin/icingacli#businessprocess#process#--details#--config#' + args.config + '#check#' + args.process 
    try:
        proc = subprocess.Popen(cmd.split("#"), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if proc.wait() == 0:
            check_business(proc.communicate()[0], args.color)
        if args.color: 
            print(proc.communicate()[0])
            sys.exit(proc.wait())
        print(proc.communicate()[0])
        sys.exit(proc.wait())		
    except Exception as error:
        error = str(error)
        print "CRITICAL: Error trying to run utility %s" % error
        sys.exit

