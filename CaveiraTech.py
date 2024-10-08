import requests
from bs4 import BeautifulSoup
from Cache import Cache



class Scrapper:
    def __init__(self):
        self.aggregator = "CaveiraTech"
        self.url = "https://caveiratech.com"
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.142.86 Safari/537.36"
        }
        self.session = requests.Session()
        self.content = BeautifulSoup(self.session.get(self.url, headers=self.headers).content, "html.parser") 
        self.page = 1
        self.cache = Cache('caveira_tech')
        
    def html_decode(self, s):
        """
        Returns the ASCII decoded version of the given HTML string. This does
        NOT remove normal HTML tags like <p>.
        """
        htmlCodes = [
                ["'", '&#39;'],
                ['"', '&quot;'],
                ['>', '&gt;'],
                ['<', '&lt;'],
                ['&', '&amp;'],
                ['\\n', '<br>']
                ['<a>', ''],
                ['</a>', ''],
                ['<script>', ''],
                ['</script>', ''],
        ]
        for code in htmlCodes:
            s = s.replace(code[1], code[0])
        return s
    
    def __cve_catcher(self, cve_html):
        fixed_cve = self.html_decode(str(cve_html.get('data-html')))
        cve = BeautifulSoup(fixed_cve, "html.parser")
        if(cve.find('div', 'sixteen wide summary computer only cve-description column')):
            cve_entity = {
                'title': cve.find('h4').text.replace(' ', ''),
                'description': cve.find('div', 'sixteen wide summary computer only cve-description column').find('span').text.replace(' ', ''),
                'cvss_version': cve_html.get('data-cvss-version'),
                'cvss_score': cve_html.get('data-cvss'),
                'infos' : self.__format_infos(cve.find('span', 'ui small text').text)
            }
            return cve_entity
        return None

    def __format_infos(self, infos):
        infos = infos.split('\n')
        formated_infos = {}
        for info in infos:
            if(info != ''):
                info = info.split(':')
                formated_infos[info[0].replace('  ', '')] = info[1].replace(' ', '').replace(' ', '')
        return formated_infos
    
    def filter_text(self, text):

        for tag in text.findAll(True):
            if tag.name not in ['br']:
                s = tag.text

                tag.replaceWith(s)

        return text
    
    def __content_catcher(self, url):
        content = BeautifulSoup(self.session.get(self.url+url, headers=self.headers).content, "html.parser")
        return self.filter_text(content.find('p','post_details')).prettify()
        
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
        return self


    def getNews(self):
        content = self.content
        post_array = []
        cachedData = self.cache.getContent(self.page)
        if cachedData != None:
            return cachedData
        for post in content.find_all('div', 'post'):
            post_content = {
                'title': post.find('b', 'post').text,
                'abstract': post.find('p').text,
                'content' : self.__content_catcher(post.find('a').get('href')),
                'date': post.find('span', 'ui text grey').text,
                'more': self.url + post.find('a').get('href')
            }

            if(post.find('span', 'cve-tooltip cursor-pointer')):
                cves_array = []
                for cve_html in post.find_all('span', 'cve-tooltip cursor-pointer'):
                    cve_entity = self.__cve_catcher(cve_html)
                    if cve_entity != None:
                        cves_array.append(cve_entity)
                post_content['cves'] = cves_array
            post_array.append(post_content)
        self.cache.setContent(post_array, self.page)
        return post_array
    

    
    def getLastCves(self):
        content = self.content
        cves_array = []
        for cve_html in content.find_all('span', 'cve-tooltip cursor-pointer'):
            cve_entity = self.__cve_catcher(cve_html)
            if cve_entity != None:
                cves_array.append(cve_entity)
        return cves_array
    
    def cves_highlighted(self):
        content = self.content
        cves_array = []
        for segment in content.find_all('div', 'ui inverted segment'):
            if(segment.find('h4', 'ui header')):
                for cve_html in segment.find_all('span', 'cve-tooltip cursor-pointer'):
                    cve_entity = self.__cve_catcher(cve_html)
                    if cve_entity != None:
                        cves_array.append(cve_entity)
        return cves_array
