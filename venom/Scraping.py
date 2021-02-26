from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
import time
driver=webdriver.Safari()
# reach a webpage
driver.get('http://www.example.com')

link = driver.find_element_by_xpath('//*[@href="https://www.iana.org/domains/example"]')
link.click()
time.sleep(1)
top_img = driver.find_element_by_xpath('//*[@src="/_img/2013.1/iana-logo-header.svg"]')
top_img.click()
time.sleep(1)
searchbar = driver.find_element_by_xpath('//*[@id="gsc-i-id1"]')
searchbar.send_keys("hello")
searchbar.send_keys(Keys.ENTER)
