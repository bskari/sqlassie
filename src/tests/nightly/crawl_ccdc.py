#!/usr/bin/env python
"""Crawls the CCDC Mediawiki page for stress testing SQLassie and MySQL."""

from BeautifulSoup import BeautifulSoup
import sys
import urllib2

all_pages_ccdc_url = "http://localhost/mediawiki/index.php/Special:AllPages"

def get_soup(url):
    page = urllib2.urlopen(url)
    soup = BeautifulSoup(page)
    return soup

def get_all_pages_links(soup):
    tables = soup.findAll('table')
    links_table = tables[2]
    raw_links = [link['href'] for link in links_table.findAll('a')]

    def relative_to_localhost(link):
        if link[0] == '/':
            return 'http://localhost' + link
        return link

    links = [relative_to_localhost(link) for link in raw_links]
    return links

def run():
    front_page = get_soup(all_pages_ccdc_url)
    links = get_all_pages_links(front_page)
    for url in links:
        sys.stdout.write('.')
        urllib2.urlopen(url)
    sys.stdout.write('\n')

if __name__ == '__main__':
    run()
