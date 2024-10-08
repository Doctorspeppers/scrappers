from flask import Flask
import CaveiraTech

app = Flask(__name__)


scrappers = {
    'CaveiraTech': CaveiraTech.Scrapper()
}

"""

Scrappers Response template:

    def getNews(self): {
        'title': 'title',
        'abstract': 'abstract',
        'content': 'content',
        'date': 'date',
        'more': 'more'
    }

"""

@app.route('/aggregators', methods=['GET'])
def get_all_tech_news():
    return {
        "aggregators": [ {'url':x.url,'aggregator':x.aggregator}  for x in scrappers.values()],
        "query_example": {
            "caveiratech": "/news/caveiratech",
            "caveiratech": "/news/caveiratech/<page>"
        }
    }

@app.route('/news/<scrapper>', methods=['GET'])
def get_tech_news(scrapper):
    if scrapper in scrappers.keys():
        return scrappers[scrapper].getNews()
    return {'error': 'scrapper not found'}
    
@app.route('/news/<scrapper>/<page>', methods=['GET'])
def get_page_tech_news(page, scrapper):
    if scrapper in scrappers.keys():
        scrappers[scrapper].toPage(int(page))
        return scrappers[scrapper].getNews()
    return {'error': 'scrapper not found'}
    
