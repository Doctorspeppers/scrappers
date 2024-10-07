from flask import Flask
import CaveiraTech

app = Flask(__name__)
alias = [
    {
        'aggregator': 'CaveiraTech',
        'url': 'https://caveiratech.com'
    }
]

scrappers = {
    'caveiratech': CaveiraTech.Scrapper()
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
        "aggregators": list(scrappers.keys()),
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
    
