import requests
from bs4 import BeautifulSoup
from Cache import Cache

class HtmlCleaner:
    def __init__(self, html):
        self.content = BeautifulSoup(html, "html.parser") 
        self.report = []
        
    def html_filter(self):
        for key, value in self.report.items():
            if  isinstance(value, str):
                self.report[key] = value.replace('\n', '').replace('\t', '').replace('\r', '').strip()
            else:
                for inner_key, inner_value in zip(range(len(value)),value):
                    for inner_key_cvss, inner_value_cvss in inner_value.items():
                        if  isinstance(inner_value_cvss, str):
                            self.report[key][inner_key][inner_key_cvss] = inner_value_cvss.replace('\n', '').replace('\t', '').replace('\r', '').strip()
                        else:
                            for inner_key_cvss2, inner_value_cvss2 in zip(range(len(inner_value_cvss)),inner_value_cvss):
                                if  isinstance(inner_value_cvss2, str):
                                    self.report[key][inner_key][inner_key_cvss][inner_key_cvss2] = inner_value_cvss2.replace('\n', '').replace('\t', '').replace('\r', '').strip()
    def defaultSearch(self):

        self.report = {
            'cve' : self.content.find('h1').find('a').text,
            'description' : self.content.find('div', 'cvedetailssummary-text').text,
            'published' : self.content.find('div', 'col-auto flex-fill').findAll('div')[0].text,
            'updated' : self.content.find('div', 'col-auto flex-fill').findAll('div')[1].text,
            'CVSS' : [
                        {
                            'base_score' : x[0].find('div', 'cvssbox').text,
                            'base_severity' : x[0].find_all('td', 'ps-2')[1].text,
                            'CVSS_vector' : x[0].find('a').text,
                            'exploitability_score' : x[0].find('div', 'cvssbox score_2').text, 
                            'impact_score' : x[0].find('div', 'cvssbox score_5').text,
                            'score_source' : x[0].find_all('td')[-2].text,
                            'first_seen' : x[0].find_all('td')[-1].text,
                            'details' : [y for y in [ x.text for x in x[1].find_all('div')]]
                        } for x in [self.content.find('tbody').find_all('tr')[i:i + 2] 
                                    for i in range(0, len(self.content.find('tbody').find_all('tr')), 2)] 
                    ]
        }
        self.html_filter()
        print(self.report)

class Scrapper:
    def __init__(self):
        self.aggregator = "CveDetails"
        self.url = "https://www.cvedetails.com"
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.142.86 Safari/537.36"
        }
        self.session = requests.Session()
        

    def search_cve(self, cve, options = ['EPSS', 'product_affected', 'references', 'CWE', 'exploits']):
        html = self.session.get(self.url+"/cve/"+cve+"/", headers=self.headers).content

        cleaner = HtmlCleaner(html).defaultSearch()
        
        # if 'EPSS' in options:
        
        # if 'product_affected' in options:
        
        # if 'references' in options:
        
        # if 'CWE' in options:
        
        # if 'exploits' in options:
        
        
scrp = Scrapper()
scrp.search_cve('CVE-2024-24747')