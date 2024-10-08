import requests
from bs4 import BeautifulSoup
from Cache import Cache

class HtmlCleaner:
    def __init__(self, html):
        self.content = BeautifulSoup(html, "html.parser") 
        self.report = []
        
    def clean_table(self, table):
        table_data = []
        header = table.find_all('th')
        for i in range(len(header)):
            header[i] = self.text_filter(header[i].text)
        
        rows = table.find_all('tr')
        for i,row in zip(range(len(rows)),rows):
            cells = row.find_all('td')
            table_data.insert(i,{})
            for key, value in zip(header, cells):
                table_data[i][key] = self.text_filter(value.text)
                
        return table_data
        
    def text_filter(self, text):
        return text.replace('\n', '').replace('\t', '').replace('\r', '').strip()
        
    def html_filter(self, report):
        if isinstance(report, dict):
            for key, value in report.items():
                if isinstance(value, str):
                    report[key] = self.text_filter(value)
                else:
                    report[key] = self.html_filter(value)
        elif isinstance(report, list):
            report[:] = [self.html_filter(item) for item in report]
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
        
        
    def search_epss(self, history_html):
        history_html_parsed = BeautifulSoup(history_html, "html.parser")
        
        self.report['epss'] = {
            'probability': self.content.find('span', 'epssbox score_6 text-dark').text,
            'proportion': self.content.find('span', 'epssbox text-bg-secondary').text
        }
        
        self.report['epss']['history'] = self.clean_table(history_html_parsed.find('table')) 
        
        
    def search_references(self):
        references = self.content.find('div', 'cvedetailssummary-references')
        self.report['references'] = 
    def search_cwe(self):
        self.report['cwe'] = self.clean_table(self.content.find('div', 'cvedetailssummary-cwes').find('table'))
        


class Scrapper:
    def __init__(self):
        self.aggregator = "CveDetails"
        self.url = "https://www.cvedetails.com"
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.142.86 Safari/537.36"
        }
        self.session = requests.Session()
        

    def search_cve(self, cve, options = ['EPSS', 'product_affected', 'references', 'CWE', 'exploits']):
        search_url = self.url+"/cve/"+cve+"/"
        html = self.session.get(search_url, headers=self.headers).content

        cleaner = HtmlCleaner(html)
        cleaner.defaultSearch()
        
        if 'EPSS' in options:
            print(search_url+"epss-score-history.html")
            epss_history_html = self.session.get(self.url+"/epss/"+cve+"/epss-score-history.html", headers=self.headers).content

            cleaner.search_epss(epss_history_html)
        print(cleaner.report)
        if 'product_affected' in options:
            cleaner.search_product_affected()
        if 'references' in options:
            cleaner.search_references()
        if 'CWE' in options:
            cleaner.search_cwe()


        return cleaner.report
        
scrp = Scrapper()
scrp.search_cve('CVE-2024-24747')