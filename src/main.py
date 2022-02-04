#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import base64
import sys
import traceback
from colorama import Fore, Style 
from kubernetes import client, config
from prettytable import PrettyTable

__version__ = "1.1.1"

class dfsecrets:

    def __init__(self, namespace, output, allns, secret, key, secretList, keyList):
        config.load_kube_config()
        self.outputTable = PrettyTable()
        self.v1 = client.CoreV1Api()
        self.namespace = namespace
        self.allns = allns
        self.output = output
        self.secret= secret
        self.secretKey = key
        self.secretList = secretList
        self.keyList = keyList

        # set up the table for PrettyTable()
        self.configureOutputTable()


    def getKubernetesSecretsFromNamespace(self):
        """
        Gets data about Kubernetes secrets and return dict

        uses default namespace unless --namespace is set in the command
        """
        try:
            if self.secret == '':
                secretData = self.v1.list_namespaced_secret(self.namespace)
            else:
                secretData = self.v1.read_namespaced_secret(self.secret, self.namespace)
                    
        except Exception as e:
            print(f"Could not fetch secrets from {self.namespace}\n\t{e}")
            sys.exit(1)
        return secretData


    def getKubernetesSecretsAllNamespaces(self):
        """
        Gets data about secrets across all namespaces and returns dict

        requires --all-namespaces to be set in the command
        """
        try:
            secretData = self.v1.list_secret_for_all_namespaces()
            if self.secret != "":
               """
               This will only find the first match of the secret
               """
               for d in secretData.items:
                   if self.secret == d.metadata.name:
                       return d
            else:
                return secretData

        except Exception as e:
            print(f"Could not fetch secrets\n\t{e}")
            sys.exit(1)

   
    def outputAsTable(self, data):
        """
        Print a table with secret information.

        turned on with --output table flag

        data: v1Secret data from kubernetes.client

        Handles the following conditions:
        secret set to '' (any):
        $kubectl dfsecret '' --output table
            prints decoded secrets values for all secrets data
        
        secret set to 'mysecret':
        $kubectl dfsecret mysecret --output table
            prints decoded values for keys for the given secret

        secret set to 'mysecret' and key set to 'mykey'
        $kubectl dfsecret mysecret --key mykey --output table
            prints decoded value for just the required key of the secret

        list secret names only
        $kubectl dfsecret --list --output table
            prints out the secret names

        list keys for secrets
        $kubectl dfsecret mysecret --list-keys --output table
            prints out keys for a secret
        """
        try:
            # handle empty secret argument, meaning all secrets
            if self.secret == '':
                for i in data.items:
                    # check for empty secret data
                    if i.data is None:
                        self.addOutputRow(i.metadata.creation_timestamp, i.metadata.name, "No Data", "No Data")
                    else:
                        for d in i.data:
                            self.addOutputRow(i.metadata.creation_timestamp, i.metadata.name, d, i.data[d])
            # handle given secret name
            else:
                # check for empty secret data
                if data.data is None:
                    self.addOutputRow(data.metadata.creation_timestamp, data.metadata.name, "No Data", "No Data")
                else:
                    for d in data.data:
                        # check if -k has been passed and only show that key if it is
                        if self.secretKey == '':
                            self.addOutputRow(data.metadata.creation_timestamp, data.metadata.name, d, data.data[d])
                        else:
                            if d == self.secretKey:
                                self.addOutputRow(data.metadata.creation_timestamp, data.metadata.name, d, data.data[d])
            # print the table for the user to see
            print(self.outputTable)
        except TypeError as te:
            print(f"{te}\nCheck for empty secrets")
        except Exception as e:
            print(f"Error trying to print table\n\t{e}")


    def outputAsRaw(self, data):
        """
        Prints out secret data as strings, no formatting (except to make it readable)

        default behaviour or using --output raw

        data: v1Secret data from kubernetes.client

        Handles the following conditions:
        secret set to '' (any):
        $kubectl dfsecret '' --output raw
            prints decoded secrets values for all secrets data
        
        secret set to 'mysecret':
        $kubectl dfsecret mysecret --output raw
            prints decoded values for keys for the given secret

        secret set to 'mysecret' and key set to 'mykey'
        $kubectl dfsecret mysecret --key mykey --output raw
            prints decoded value for just the required key of the secret

        list secret names only
        $kubectl dfsecret --list --output raw
            prints out the secret names

        list keys for secrets
        $kubectl dfsecret mysecret --list-keys --output raw
            prints out keys for a secret
        """
        try:
            if self.secret == '':
                for i in data.items:
                    print(f'{i.metadata.creation_timestamp}\t{Fore.GREEN}{self.namespace}/{i.metadata.name}{Style.RESET_ALL}')
                    if not self.secretList:
                        for d in i.data:
                            self.rawOutputHandler(d, i.data[d])
            else:
                print(f'{data.metadata.creation_timestamp}\t{Fore.GREEN}{self.namespace}/{data.metadata.name}{Style.RESET_ALL}')
                if not self.secretList:
                    for d in data.data:
                        if self.secretKey == '':
                            self.rawOutputHandler(d, data.data[d])
                        else:
                            if d == self.secretKey:
                                self.rawOutputHandler(d, data.data[d])


        except Exception as e:
            print(f"Error trying to output secrets\n\t{e}")
            traceback.print_exc()


    def configureOutputTable(self):
        """
        Configures the field names for PrettyTable()

        Uses different field names depending on what flags are passed
        """
        # --list
        if self.secretList:
            self.outputTable.field_names = ["Created", "Namespace", "Secret"]
        # --list-keys
        elif self.keyList:
            self.outputTable.field_names = ["Created", "Namespace", "Secret", "Key"]
        # default behaviour
        else:
            self.outputTable.field_names = ["Created", "Namespace", "Secret", "Key", "Value"]


    def addOutputRow(self, created, secret, key, value):
        """
        Adds rows to self.outputTable holding the secrets data

        Different information is added depnding on what flags are passed
        """
        # --list
        if self.secretList:
            self.outputTable.add_row([created,
                                    self.namespace,
                                    secret])
        # --list-keys
        elif self.keyList:
            self.outputTable.add_row([created,
                                    self.namespace,
                                    secret,
                                    key])
        # default behaviour
        else:
            # we're checking if value is coming in as a string or b64 encoded
            # as the secret might be coming in empty
            v = value if isinstance(value, str) else str(base64.b64decode(value), encoding='utf-8')
            self.outputTable.add_row([created,
                                    self.namespace,
                                    secret,
                                    key,
                                    v])
        


    def rawOutputHandler(self, key, value):
        """
        Handles printing secret information to stdout

        Lists keys when using --list-keys
        Shows decoded secret value by default
        """
        if self.keyList:
            print(f"\t{key}")
        else:
            print(f"\t{key}: {str(base64.b64decode(value), encoding='utf-8')}")


    def main(self):
        """
        Entry into the dfsecrets class

        Gathers secret data and output functions
        """
        if self.allns == False:
            secretData = self.getKubernetesSecretsFromNamespace()
        elif self.allns == True:
            secretData = self.getKubernetesSecretsAllNamespaces()
        #print(secretData)
        if self.output == "table":
            self.outputAsTable(secretData)
        elif self.output == "raw":
            self.outputAsRaw(secretData)
        else:
            print(f"Unknown output {self.output}, if you're seeing this error something went very wrong")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(allow_abbrev=True, 
                                    description="Show decoded secrets information")
    version = "%(prog)s " + __version__
    parser.add_argument("--version", "-v",
                        action="version",
                        version=version)
    parser.add_argument("--namespace", "-n",
                        dest="ns",
                        type=str,
                        default="default",
                        help="Set namespace",
                        )
    parser.add_argument("--all-namespaces", "-A",
                        action="store_true",
                        dest="allns",
                        help="Collect secrets from all namespaces",
                        )
    parser.add_argument("--output", "-o", 
                        choices=["table", "raw"],
                        default="raw", type=str, help="Output format: table or as raw (default) string")
    parser.add_argument("--key", "-k",
                        dest="secretKey",
                        default="", type=str, help="Specify a key from the secret")
    parser.add_argument("--list", "-l",
                        dest="secretList",
                        action="store_true",
                        default=False,
                        help="List secret names")
    parser.add_argument("--list-keys", "-L",
                        dest="secretListKeys",
                        action="store_true",
                        default=False,
                        help="List secret keys")
    parser.add_argument("secret",
                        default="",
                        nargs="?",
                        help="Name of the secret")
    parser.set_defaults(allns=False)
    args = parser.parse_args()

    dfs = dfsecrets(output=args.output,
                    namespace=args.ns,
                    allns=args.allns,
                    secret=args.secret,
                    key=args.secretKey,
                    secretList=args.secretList,
                    keyList=args.secretListKeys)
    dfs.main()
