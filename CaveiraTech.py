import requests
from bs4 import BeautifulSoup
import json 
def html_decode(s):
    """
    Returns the ASCII decoded version of the given HTML string. This does
    NOT remove normal HTML tags like <p>.
    """
    htmlCodes = [
            ["'", '&#39;'],
            ['"', '&quot;'],
            ['>', '&gt;'],
            ['<', '&lt;'],
            ['&', '&amp;']
    ]
    for code in htmlCodes:
        s = s.replace(code[1], code[0])
    return s


class Scrapper:
    def __init__(self):
        self.url = "https://caveiratech.com"
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.142.86 Safari/537.36"
        }
        self.session = requests.Session()
        self.content = BeautifulSoup(self.session.get(self.url, headers=self.headers).content, "html.parser") 
        self.page = 1
        
        def __cve_catcher(self, cve_html):
        fixed_cve = html_decode(str(cve_html.get('data-html')))
        cve = BeautifulSoup(fixed_cve, "html.parser")
        cve_entity = {
            'title': cve.find('h4').text,
            'description': cve.find('div', 'sixteen wide summary computer only cve-description column').find('span').text,
            'cvss_version': cve_html.get('data-cvss-version'),
            'cvss_score': cve_html.get('data-cvss'),
            'infos' : self.__format_infos(cve.find('span', 'ui small text').text)

        }
        return cve_entity
    
    def __format_infos(self, infos):
        infos = infos.split('\n')
        formated_infos = {}
        for info in infos:
            if(info != ''):
                info = info.split(':')
                formated_infos[info[0].replace('  ', '')] = info[1].replace('  ', '')
        return formated_infos
        
    def paginate(self, page = None):
        if page == None:
            return f"/page/{self.page}"
        else:
            self.page += page
            return f"/page/{self.page}"
        
    def pageUp(self):
        self.content = BeautifulSoup(self.session.get(self.url+self.paginate(1), headers=self.headers).content, "html.parser")
        return self
    
    def pageDown(self):
        self.content = BeautifulSoup(self.session.get(self.url+self.paginate(-1), headers=self.headers).content, "html.parser")
        return self
    
    def toPage(self, page):
        self.page = page
        self.content = BeautifulSoup(self.session.get(self.url+self.paginate(), headers=self.headers).content, "html.parser")
    


    def getLastNews(self):
        content = self.getContent()
        post_array = []
        for post in content.find_all('div', 'post'):
            post_content = {
                'title': post.find('b', 'post').text,
                'content': post.find('p').text,
                'more': post.find('a').get('href')
            }

            if(post.find('span', 'cve-tooltip cursor-pointer')):
                cves_array = []
                for cve_html in post.find_all('span', 'cve-tooltip cursor-pointer'):
                    cve_entity = self.__cve_catcher(cve_html)
                    cves_array.append(cve_entity)
                post_content['cves'] = cves_array
            post_array.append(post_content)
        return post_array
    

    
    def getLastCves(self):
        content = self.getContent()
        cve_array = []
        for cve_html in content.find_all('span', 'cve-tooltip cursor-pointer'):
            cve_entity = self.__cve_catcher(cve_html)
            cve_array.append(cve_entity)
        return cve_array
    
    def cves_highlighted(self):
        content = self.getContent()
        cve_array = []
        for segment in content.find_all('div', 'ui inverted segment'):
            if(segment.find('h4', 'ui header')):
                for cve_html in segment.find_all('span', 'cve-tooltip cursor-pointer'):
                    cve_entity = self.__cve_catcher(cve_html)
                    cve_array.append(cve_entity)
        return cve_array
