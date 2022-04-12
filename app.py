from flask import Flask, render_template
from markupsafe import escape
app = Flask(__name__)

@app.route('/')
def hello():
    return render_template('index.html')

@app.route('/home/')
def home():
    return render_template('home.html')

@app.route('/capitalize/<word>/')
def capitalize(word):
    return '<h1>{}</h1>'.format(escape(word.capitalize()))
if __name__ == '__main__':
    app.run()