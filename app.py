from flask import Flask
import CaveiraTech
app = Flask(__name__)

@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"

@app.route('/news/tech', methods=['GET'])
def get_tech_news():
    scrapper = CaveiraTech.Scrapper()
    return scrapper.getNews()
    
@app.route('/news/tech/<page>', methods=['GET'])
def get_page_tech_news(page):
    scrapper = CaveiraTech.Scrapper()
    scrapper.toPage(int(page))
    return scrapper.getNews()
    
    
