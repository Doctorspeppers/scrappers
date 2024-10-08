import requests
from bs4 import BeautifulSoup
from Cache import Cache

class HtmlCleaner:
    def __init__(self, html):
        self.content = BeautifulSoup(html, "html.parser") 
        self.report = []
        
    def text_filter(self, text):
        return text.replace('\n', '').replace('\t', '').replace('\r', '').strip()
        
    def html_filter(self, report):
        print(report, "\n\n\n\n")
        if isinstance(report, list):
            for inner_key, inner_value in zip(range(len(report)),report):
                if  isinstance(inner_value, str):
                    report[inner_key] = self.text_filter(inner_value)
                else:
                    for inner_key_var, inner_value_var in inner_value.items():
                        if  isinstance(inner_value_var, str):
                            report[inner_key][inner_key_var] = self.text_filter(inner_value_var)
                        else:
                            report[inner_key][inner_key_var] = self.html_filter(inner_value_var)
        elif isinstance(report, dict):
            for key, value in report.items():
                if  isinstance(value, str):
                    report[key] = self.text_filter(value)
                else:
                    for inner_key, inner_value in zip(range(len(value)),value):
                        for inner_key_var, inner_value_var in inner_value.items():
                            if  isinstance(inner_value_var, str):
                                report[key][inner_key][inner_key_var] = self.text_filter(inner_value_var)
                            else:
                                report[key][inner_key][inner_key_var] = self.html_filter(inner_value_var)
        return report

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

        self.report = self.html_filter(self.report)


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
        
        if 'EPSS' in options:
            cleaner.search_epss()
        
        if 'product_affected' in options:
            cleaner.search_product_affected()
        if 'references' in options:
            cleaner.search_references()
        if 'CWE' in options:
            cleaner.search_cwe()
        if 'exploits' in options:
            cleaner.search_exploits()

        return cleaner.report
        
scrp = Scrapper()
scrp.search_cve('CVE-2024-24747')