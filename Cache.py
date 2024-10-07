import redis
import json
from datetime import datetime

class Cache:
    
    def __init__(self, scrapper, size = 10):
        self.redis = redis.Redis(host='localhost', port=6379, decode_responses=True)
        self.scrapper = scrapper
        self.size = size
        if self.redis.get('pageCounter:' + self.scrapper) != None:
            self.pageCounter = int(self.redis.get('pageCounter:' + self.scrapper))
        else:
            self.pageCounter = 1
            self.pageCounter = self.redis.set('pageCounter:' + self.scrapper, self.pageCounter)
    
    def getContent(self, page):
        
        if self.redis.get('contentData:' + self.scrapper + ':' + str(page)) != None:
            self.contentData = json.loads(self.redis.get('contentData:' + self.scrapper + ':' + str(page)))
        else:
            return None
        if datetime.strptime(self.contentData['date'], '%d/%m/%Y').strftime('%d/%m/%Y') != datetime.now().strftime('%d/%m/%Y'):
            return None
        return self.contentData['content']
        
    def setContent(self, content,page):
        self.contentData = {
            'date': datetime.now().strftime('%d/%m/%Y'),
            'content': content
        }
        self.redis.set('contentData:' + self.scrapper+":"+str(page), json.dumps(self.contentData, default=str, ensure_ascii=False, indent=4), ex = 86400)