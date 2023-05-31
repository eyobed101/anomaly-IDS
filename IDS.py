import time
from flask import Flask, redirect, url_for
import os
import subprocess
import datetime
import logging
from subprocess import Popen
import pandas as pd
from flow_loader.csv_flow_loader import CSVFlowLoader

from preprocessing import constants, data_preprocessor
from sklearn.preprocessing import StandardScaler
from preprocessing.constants import PredictLabel
import joblib
# import iptc
MODEL_FILEPATH = "model.pkl"
path =""
import re
from threading import Lock
from flask import Flask, render_template, session
from flask_socketio import SocketIO, emit
import json
######################################################################
########################Flask_setup###################################
######################################################################
async_mode = None
app = Flask(__name__)

socketio = SocketIO(app, async_mode=async_mode)
thread = None
thread_lock = Lock()


CSVFILEPATH = "CICFlowMeter-4.0/bin/data/daily"
csvfilename = ""


output_filename = "prediction_log.txt"
columns = constants.COLUMNS
mlmodel = MODEL_FILEPATH


def runIDS():
    print("Starting IDS...")
    count = 0
    while True:

        try:
            # Create log file if it does not exist.
            # if not os.path.exists("./logs/idslogs/ids.log"):
            #     # os.makedirs('./logs/idslogs/')
            #     file = open(os.path.join("./logs/idslogs/", "ids.log"), 'w')
            #     file.close()
            # logging.basicConfig(filename=os.path.join(r'logs/idslogs/ids.log'), level=logging.INFO)
            csvloader = CSVFlowLoader(os.path.join(CSVFILEPATH, csvfilename))
            # mlengine = MLEngine(MODEL_FILEPATH, DATACLEAN_PIPELINE_FILEPATH, DATAPREP_PIPELINE_FILEPATH)
            while True:

                    for flowline in csvloader.tailFile():
                        csValsArray = [list(flowline.split(","))]

                        csValsDF = pd.DataFrame(csValsArray, columns=columns)

                        mlmodel = joblib.load(MODEL_FILEPATH)

                        ######## filtering Private Ip address outgoing  traffic #########

                        cmd = 'ifconfig'

                        temp1 = subprocess.Popen([cmd, "wlan0"], stdout=subprocess.PIPE)
                        temp2 = subprocess.Popen(['grep', '192'], stdin=temp1.stdout, stdout=subprocess.PIPE)
                        dropped = []
                        output = str(temp2.communicate())
                        out = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
                        private_ip = out.search(output)[0]


                        # for h in csValsDF:
                        #     if (h["Src IP"] == private_ip):
                        #         continue

                        for ip in csValsDF["Src IP"]:
                            if (ip == private_ip):
                                continue
                            # else :
                            #     break






                            # if (ip == private_ip) :
                            #     csValsDF =
                            # else :
                            #     print(ip)
                            #     csValsDF = csValsDF
                        # print(output)

                        ####### End of filtering command #############


                            l=csValsDF
                            csValsDF = csValsDF.drop(["Flow ID","Src IP","Src Port","Dst IP","Dst Port","Protocol","Timestamp","Label"], axis=1)
                            for ii in csValsDF:
                                csValsDF[ii] = csValsDF[ii].replace('Infinity', -1)
                                csValsDF[ii] = csValsDF[ii].replace('NaN', 0)
                                number_or_not = []
                                for iii in csValsDF[ii]:
                                    try:
                                        k = int(float(iii))
                                        number_or_not.append(int(k))
                                    except:
                                        number_or_not.append(iii)
                                csValsDF[ii] = number_or_not
                            features = ["Flow Duration", "Total Fwd Packets", "Packet Length Std", "Subflow Fwd Bytes",
                                                     "Subflow Bwd Bytes",
                                                     "Packet Length Variance", "Bwd Packet Length Mean", "Avg Bwd Segment Size",
                                                     "Bwd Packet Length Max",
                                                     "Init_Win_bytes_backward", "Total Length of Fwd Packets",
                                                     "Init_Win_bytes_forward", "Average Packet Size",
                                                     "Packet Length Mean", "Max Packet Length", "Fwd Packet Length Max",
                                                     "Flow IAT Max", "Bwd Header Length"]
                            displayed = ["Timestamp","Src IP","Src Port","Dst IP","Dst Port"]
                            # others = ["Bwd Packet Length Std", "Flow Bytes/s", "Total Length of Fwd Packets",
                            #           "Fwd Packet Length Std",
                            #           "Flow IAT Std", "Flow IAT Min", "Fwd IAT Total"]
                            # for i in csValsDF:
                            #     df = pd.read_csv(path + i, usecols=others)

                            df = csValsDF[features]


                            # del df["Label"]
                            # features.remove('Label')
                            X = df
                            # X_stand = StandardScaler().fit_transform(X)

                            # socketio.sleep(0.1)
                            count += 1
                            filtered_ip = []
                            # Actual detection and printing results out in stdout.
                            if mlmodel.predict(X.values) == 1:
                                # print("BENIGN: %s" % (parsePredictionDF(l)))
                                # logging.info("ANOMALY: %s" % (parsePredictionDF(l)))
                                time = l["Timestamp"].fillna('').str.strip().str.cat(sep=' ')
                                source_ip = l["Src IP"].fillna('').str.strip().str.cat(sep=' ')
                                source_port = l["Src Port"].fillna('').str.strip().str.cat(sep=' ')
                                dest_ip = l["Dst IP"].fillna('').str.strip().str.cat(sep=' ')
                                dest_port = l["Dst Port"].fillna('').str.strip().str.cat(sep=' ')
                                label = "BENIGN"
                                all = [time,source_ip,source_port,dest_ip,dest_port,label]


                                # data = l[displayed]
                                # data = data[data["Label"]== "Anomaly"]

                                # d = json.loads(data)
                                # df_json = data.to_json(orient='records')
                                # # result = {"objects": d}
                                # result = {"objects": df_json}
                                # d = data.values.tolist()
                                # d.append("BENIGN")
                                # result = json.dumps(d)
                                socketio.emit('my_response', {'data': all, 'count': count})

                            else:
                                time = l["Timestamp"].fillna('').str.strip().str.cat(sep=' ')
                                source_ip = l["Src IP"].fillna('').str.strip().str.cat(sep=' ')
                                source_port = l["Src Port"].fillna('').str.strip().str.cat(sep=' ')
                                dest_ip = l["Dst IP"].fillna('').str.strip().str.cat(sep=' ')
                                dest_port = l["Dst Port"].fillna('').str.strip().str.cat(sep=' ')
                                label = "ANOMALY"
                                all = [time,source_ip,source_port,dest_ip,dest_port,label]
                                # data = [parsePredictionDF(l)]
                                # data = l[displayed]

                                # d = json.loads(data)
                                # df_json = data.to_json(orient='records')
                                # d = data.values.tolist()
                                # d.append("ANOMALY")
                                # result = json.dumps(d)
                                # print("ANOMALY: %s" % (parsePredictionDF(l)))

                                socketio.emit('my_response',
                                              {'data': all,'count':count})
                                # drop_ip = csValsDF.iloc[1]
                                # rule = iptc.Rule()
                                # rule.src = drop_ip
                                # target = iptc.Target(rule,"DROP")
                                # rule.target = target
                                # tables= iptc.Table(iptc.Table.FILTER)
                                # chain = iptc.Chain(tables, "INPUT")
                                # iptc.Chain.set_policy(chain, "ACCEPT")
                                # chain.insert_rule(rule)


                                # for ip in l["Src IP"]:
                                #     ip = str(ip)
                                #
                                #
                                #     he = '{}'.format(ip)
                                #
                                #     print(he)
                                #     if(ip in filtered_ip):
                                #         break
                                #     else:
                                #
                                #         sub1 = subprocess.Popen(['iptables', '-A', 'INPUT', '-s',he,'-j','DROP'], stdout=subprocess.PIPE)
                                #         # sub2 = subprocess.Popen(, stdin=sub1.stdout, stdout=subprocess.PIPE)
                                #
                                #         sub1.communicate()
                                #         filtered_ip.append(ip)
        except KeyboardInterrupt:
            print("Exiting...")
            csvloader.destroy()


@app.route('/')
def index():
    return render_template('index.html', async_mode=socketio.async_mode)

@socketio.event
def my_event(message):
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response',
         {'data': message['data'], 'count': session['receive_count']})

# Receive the test request from client and send back a test response
@socketio.on('test_message')
def handle_message(data):
    print('received message: ' + str(data))
    emit('test_response', {'data': 'Test response sent'})

# Broadcast a message to all clients
@socketio.on('broadcast_message')
def handle_broadcast(data):
    print('received: ' + str(data))
    emit('broadcast_response', {'data': 'Broadcast sent'}, broadcast=True)

@socketio.event
def connect():
    global thread
    with thread_lock:
        if thread is None:
            thread = socketio.start_background_task(runIDS)
    emit('my_response', {'data': 'Connected', 'count': 0})

def parsePredictionDF(dataframe):
    src_ip = dataframe["Src IP"].values[0]
    src_port = dataframe["Src Port"].values[0]
    dst_ip = dataframe["Dst IP"].values[0]
    dst_port = dataframe["Dst Port"].values[0]
    timestamp = dataframe["Timestamp"].values[0]
    return "%s %s:%s => %s:%s" % (timestamp,src_ip, src_port, dst_ip, dst_port)

# def prepareDumps():
#     if dump_pipeline.createDumps():
#         print("Successful creation of pipeline dumps...")
#     else:
#         print("Error in creation of pipeline dumps...")

def startup():
    # Check network flow csv file if it exists, if not create one.
    curdirname = os.getcwd() # current working directory
    # Generates a filename of the format 'YYYY-MM-DD_Flow.csv'
    global csvfilename
    csvfilename = "%s_Flow.csv" % (datetime.datetime.today().strftime('%Y-%m-%d'))
    isFileExist = os.path.exists(os.path.join(curdirname, r'CICFlowMeter-4.0/bin/data/daily', csvfilename))
    # If network flow csv file does not exist create new one
    if isFileExist == False:
        file = open(os.path.join(curdirname, r'CICFlowMeter-4.0/bin/data/daily', csvfilename), 'w')
        file.close()
    # Start CICFlowMeter
    command = "cd"
    Popen(['bash',os.path.join(curdirname,r"CICFlowMeter-4.0/bin/CICFlowMeter")], stdout=subprocess.PIPE)
    # sub1 = subprocess.Popen([command, "CICFlowMeter-4.0/bin"], stdout=subprocess.PIPE)
    # sub2 = subprocess.Popen("./CICFlowMeter", stdin=sub1.stdout, stdout=subprocess.PIPE)
    # dropped = []
    # sub2.communicate()

    # p = subprocess.run([r"/CICFlowMeter-4.0/bin/CICFlowMeter"])
# @app.route("/")
# def home():
#     return redirect(url_for("runIDS"))
if __name__ == "__main__":
    # app.run()
    startup()
    socketio.run(app)
    # runIDS(verbose=True)
    # prepareDumps()