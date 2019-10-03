#!/usr/bin/python3

'''
    This crawler will log into the Fakebook website site provided by NEU.
    You can pass the username and password as a command line argument when you are about to start the program.
    Syntax: ./webcrawler [username] [password]
'''

import sys
import socket
import re
import time
import gzip

'''
    Below are the global variables data for which have been accessed and manipulated through out the program.

    visited_sites: It is a list that holds all the links that our crawler has crawled to. It is initialized with 
    two links that we don't our crawler to ever visit. Any link that out crawler visits gets added to this list.
    This list is also used when we want our program to check whether any new scrapped linked has been already 
    visited or not.

    flags: This is initialized as an empty list which holds all the found flags throught-out our crawling process.
    We we crawl to a new link our program also search for any flags within it. If found it appends the flag value 
    to this list.

    s = It is an uninitialized variable that will be later used to store in the socket object.

    username = Gets intialized with value of username provided in the arguments

    password = Gets intialized with value of password provided in the arguments

'''

visited_sites = ["http://www.northeastern.edu", "mailto:cbw@ccs.neu.edu",]
flags = []
s = None
username = sys.argv[1]
password = sys.argv[2]

'''

    Function Name: convert_response
    Arguments: Byte string
    Return: ASCII string if supplied byte string is not empty. Else 'Empty' string

    Used for converting the received compressed byte string.  

'''

def convert_response(data):

    if (data == b''):
        return 'Empty'
    
    data = data.split(b'\r\n\r\n')
    result = str(data[0].decode("UTF-8")) + '\r\n\r\n' + str(gzip.decompress(data[1]).decode("UTF-8"))
    return result


'''

    Function Name: reConnect
    Arguments: None
    Return: None

    This function is to connect to the server.
    Through the program this function is only used to connect back to the server if the received response is 
    500 INTERNAL ERROR or when the socket connection is dropped by the server abruptly.

    We reference the global 's' variable. Close any existing connection and reconnect with the server. 

'''

def reConnect():
    global s
    hostname = 'cs5700f16.ccs.neu.edu'
    s.close()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip = socket.gethostbyaddr(hostname)[2][0]
    s.connect((ip, 80))
    return

'''

    Function Name: Connect
    Arguments: None
    Return:   csrf_token,new_session_id, hostname, 'http://'+'hostname'+'/accounts/login/?next=/fakebook/', main_page, new_link

    This function is used to connect to the fakebook site and login the website with provided credentials.
    The function works in a loop so as to avoid any disconnect or 500 error.
    It the program received an error it retries till it logs in and return the values mentioned above.

'''

def Connect():
    global s, username, password

    while True:

        received_data = ''
        hostname = 'cs5700f16.ccs.neu.edu'

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ip = socket.gethostbyaddr(hostname)[2][0]
        s.connect((ip, 80))
    
        hello_string = 'GET /accounts/login/?next=/fakebook/ HTTP/1.1\r\nHost: {0}\r\nUser-Agent: python-requests/2.22.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n'.format(hostname).encode('UTF-8')
        s.send(hello_string)
        received_data = convert_response(s.recv(4096))

        if not(re.findall(r"HTTP\/1\.1.(\d{3})", received_data)):
            continue

        csrf_token = re.findall(r"csrftoken=(\w*)", received_data)[0]
        session_id = re.findall(r"sessionid=(\w*)", received_data)[0]

        login_post_request = 'POST /accounts/login/ HTTP/1.1\r\nHost: cs5700f16.ccs.neu.edu\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:69.0) Gecko/20100101 Firefox/69.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 109\r\nDNT: 1\r\nConnection: keep-alive\r\nReferer: http://cs5700f16.ccs.neu.edu/accounts/login/?next=/fakebook/\r\nCookie: csrftoken={0}; sessionid={1}\r\nUpgrade-Insecure-Requests: 1\r\n\nusername={2}&password={3}&csrfmiddlewaretoken={0}&next=%2Ffakebook%2F'.format(csrf_token, session_id, username, password)
        
        s.send(login_post_request.encode("UTF-8"))
        received_data = convert_response(s.recv(4096))

        if not(re.findall(r"HTTP\/1\.1.(\d{3})", received_data)):
            continue

        response_code = int(re.findall(r"HTTP\/1\.1.(\d{3})", received_data)[0])

        if response_code == 302 or response_code == 301:
            new_session_id = re.findall(r"sessionid=(\w*)", received_data)[0]
            new_link = re.findall(r"Location:.http:\/\/cs5700f16\.ccs\.neu\.edu(.*)\r\n", received_data)[0]
            referer = re.findall(r"Referer:.(.*)\r\nCookie", login_post_request)[0]
            host = re.findall(r"Host:.(.*)\r\nUser-Agent", login_post_request)[0]

        
        redirect_get_request = 'GET {0} HTTP/1.1\r\nHost: {1}\r\nUser-Agent: python-requests/2.22.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nReferer: {2}\r\nDNT: 1\r\nConnection: keep-alive\r\nCookie: csrftoken={3}; sessionid={4}\r\nUpgrade-Insecure-Requests: 1\n\n'.format(new_link, host, referer, csrf_token, new_session_id)

        s.sendall(redirect_get_request.encode("UTF-8"))
        main_page = convert_response(s.recv(4096))

        if not(re.findall(r"HTTP\/1\.1.(\d{3})", main_page)):
            continue
    
        elif(int(re.findall(r"HTTP\/1\.1.(\d{3})", main_page)[0]) == 200):
            break

        else:
            continue

    return csrf_token,new_session_id, hostname, 'http://'+'hostname'+'/accounts/login/?next=/fakebook/', main_page, new_link


'''

    Function Name: goCrawl
    Arguments: csrf_token,new_session_id, hostname, referer, home_page, home_link
    Return: None

    This function is used to crawl the web links an collect flags.
    The function works in a loop and exits only when there are no more links to crawl.
    The web links to crawl are stored in a list called web_links_queue.
    Function is designed so as to handle response code 200,301,302,404, and 500.

'''

def goCrawl(csrf_token, session_id, host, referer, home_page, home_link):
    global visited_sites, s, flags

    web_links_queue = []

    if home_link.strip() not in visited_sites: 
        visited_sites.append(home_link.strip())

    scrapped_web_links = re.findall(r"\<a.(?:[^>]*?\s+)?href=\"(.*?)\"\>", home_page)

    for each in scrapped_web_links:
        if each not in visited_sites:
            web_links_queue.append(each)

    while(web_links_queue != []):

        link_to_visit = web_links_queue.pop(0)

        if (link_to_visit in visited_sites):
            continue
        
        get_request = 'GET {0} HTTP/1.1\r\nHost: {1}\r\nUser-Agent: python-requests/2.22.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: keep-alive\r\nCookie: csrftoken={2}; sessionid={3}\r\nUpgrade-Insecure-Requests: 1\r\n\n'.format(link_to_visit, host, csrf_token, session_id)

        s.sendall(get_request.encode("UTF-8"))
         
        received_data = convert_response(s.recv(4096))

        if received_data == 'Empty':
            web_links_queue.insert(0, link_to_visit)
            reConnect()
            continue
 
        response_code = int(re.findall(r"HTTP\/1\.1.(\d{3})", received_data)[0])

        if(response_code == 200):

            visited_sites.append(link_to_visit.strip())
            scrapped_web_links = re.findall(r"\<a.(?:[^>]*?\s+)?href=\"(.*?)\"\>", received_data)

            flag_in_file = re.findall(r"FLAG:(?:\s+)([0-9a-zA-Z]{64})",received_data)

            if(flag_in_file):
                flags.extend(flag_in_file)

            for each in scrapped_web_links:
                if (each not in visited_sites):
                    web_links_queue.append(each.strip())

        elif(response_code == 301 or response_code == 302):
            visited_sites.append(link_to_visit.strip())
            new_location = re.findall(r"Location:.http:\/\/cs5700f16\.ccs\.neu\.edu(.*)\r\n", received_data)[0]

            if (new_location not in visited_sites):
                web_links_queue.insert(0,new_location)
            else:
                continue

        elif(response_code == 404 or response_code == 403):
            continue

        elif(response_code == 500):
            web_links_queue.insert(0, link_to_visit.strip())
            time.sleep(1)
            reConnect()

    print(*flags, sep="\n")

    return

'''

    Main function and this is where the program begins. 
    First it calls the Connect() function and collects the return values.
    Next it passes on this value to goCrawl() function. 
    And finally, when the program goCrawl() returns it closes the active connection.

'''

if __name__ == '__main__':

    csrfToken, newSessionID, host, referer, homePage, homeLink = Connect()

    goCrawl(csrfToken, newSessionID, host, referer, homePage, homeLink)

    s.close()



