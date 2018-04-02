#!/usr/bin/python3.6

from sys import argv
import requests
from bs4 import BeautifulSoup
import time

TIME_TO_CRAWL = 180 # seconds

def check_ver(r):
	''' Takes in a request and returns True if the request was made using HTTPS '''
	return r.url.split(":")[0] == "https"

def get_pagesize(r):
	''' Returns the size of the request r in Kbytes '''
	return len(r.content) / 1024

def process_response(r, domain):
	print("Processing " + domain)
	res_url = ''
	res_size = 0
	visited = []
	wanted_page = (domain, get_pagesize(r))
	soup = BeautifulSoup(r.text,"html5lib")
	urls = [link.get('href') for link in soup.find_all('a')] + ["http://www." + domain]
	starting = time.time()
	while len(urls):
		if time.time() - starting > TIME_TO_CRAWL:
			break
		# print("urls size = ", len(urls))
		curr_url = urls.pop(0)
		# print("curr_url = ", curr_url)
		if curr_url in visited:
			continue
		visited.append(curr_url)
		if curr_url[0] == "/":
			if len(curr_url) == 1 or curr_url[1] != "/": # relative link
				curr_url = "http://www." + domain + curr_url
			else:
				curr_url = "http:" + curr_url # weird link
		else:
			if not domain in curr_url or curr_url == "#":
				continue
		try:
			# time.sleep(10)
			# print("opening ", curr_url)
			curr_r = requests.get(curr_url, timeout = TIMEOUT)
			size = get_pagesize(curr_r)
			# print("MIN_PAGESIZE = " + str(MIN_PAGESIZE) + ", size = " + str(size))
			'''
			if size >= MIN_PAGESIZE:
				print("Found page " + curr_url)
				return curr_url
			'''
			if size > wanted_page[1]:
				wanted_page = (curr_url, size)
			curr_soup = BeautifulSoup(curr_r.text,"html5lib")
			curr_urls = [link.get('href') for link in curr_soup.find_all('a')]
			for cu in curr_urls:
				urls.append(cu)
		except Exception as e:
			print("BAD LINK: " + curr_url)
			sys.exc_clear()
			gerr.write(curr_url + "\n")
			print("Returning " + wanted_page[0]+ ", page size " + str(wanted_page[1]))
			return wanted_page[0]
	# print("Exhausted " + domain)
	print("Returning " + wanted_page[0]+ ", page size " + str(wanted_page[1]))
	return wanted_page[0]

ARGS_NO = 5
TIMEOUT = 200 # timeout value for get requests in seconds
BAD_LINKS = 0
FOUND_LINKS = 0

if len(argv) != ARGS_NO:
    print("Incorrect number of arguments, exiting...\nUsage ./crawler <input-file> <min-page-size(KB)> <required-pages> <output-file>")
    exit()

# input file, csv format
f = open(argv[1], "r")
# minimum page size required (in KB)
MIN_PAGESIZE = int(argv[2])
# desired number of pages
pages = int(argv[3])
print("pages = " + str(pages))
# output file
g = open(argv[4] + ".http", "w") # http sites
gs = open(argv[4] + ".https", "w") # https sites
gerr = open(argv[4] + ".err", "w") # urls that weren't reached

try:
	for line in f.readlines():
		domain = line.split(",")[1][:-1] # to remove the carriage return or some other weird character stuck at the end
		url = "http://" + domain
		try:
			# print("url = " + url)
			r = requests.get(url, timeout = TIMEOUT)
			url = process_response(r, domain)
			if url == None:
				continue
			pages -= 1
			r = requests.get(url, timeout = TIMEOUT)
			if check_ver(r):
				gs.write(url + "\n")
			else:
				g.write(url + "\n")
			# print(url, check_ver(r), len(r.content), get_pagesize(r))
		except Exception as e:
			gerr.write(url + "\n")
		print("pages = " + str(pages))
		if pages == 0:
			break
finally:
	f.close()
	g.close()
	gs.close()
	gerr.close()


f.close()
g.close()
gs.close()
gerr.close()