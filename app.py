from flask import Flask, render_template, request, jsonify
import time
import pickle
from preprocessing import *
from tld import get_tld
import numpy as np

app = Flask(__name__)
model = pickle.load(open('model.pkl', 'rb'))

def preprocess_url(url):

    status = []
    status.append(having_ip_address(url))
    status.append(abnormal_url(url))
    status.append(count_dot(url))
    status.append(count_www(url))
    status.append(count_atrate(url))
    status.append(no_of_dir(url))
    status.append(no_of_embed(url))

    status.append(shortening_service(url))
    status.append(count_https(url))
    status.append(count_http(url))

    status.append(count_per(url))
    status.append(count_ques(url))
    status.append(count_hyphen(url))
    status.append(count_equal(url))

    status.append(url_length(url))
    status.append(hostname_length(url))
    status.append(suspicious_words(url))
    status.append(digit_count(url))
    status.append(letter_count(url))
    status.append(fd_length(url))
    tld = get_tld(url,fail_silently=True)

    status.append(tld_length(tld))

    return status

def get_prediction_from_url(test_url):
    features_test = preprocess_url(test_url)
    features_test = np.array(features_test).reshape((1, -1))

    pred = model.predict(features_test)
    if int(pred[0]) == 0:

        res="SAFE"
        return res
    elif int(pred[0]) == 1.0:

        res="DEFACEMENT"
        return res
    elif int(pred[0]) == 2.0:
        res="PHISHING"
        return res

    elif int(pred[0]) == 3.0:

        res="MALWARE"
        return res
    
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process_url', methods=['POST'])
def process_url():
    if request.method == 'POST':
        url = request.form['url']
        res=get_prediction_from_url(url)
        print("The result is ",res)
        return jsonify({'result': f"Prediction: {res}"})
        # Simulate processing with a 5-second delay
        #time.sleep(5)
        
        result = f"The entered URL is {url}"
        return jsonify({'result': result})

if __name__ == '__main__':
    app.run(debug=True)
