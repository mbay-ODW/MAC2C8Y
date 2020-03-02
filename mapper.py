import jsonify
import csv
import pandas
import logging

logger = logging.getLogger('Mapper')
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger.debug('Logger for Mapper was initialised')
MACIDsdict = pandas.read_csv('MACID.csv',sep=',', header=0, names=['Name','MAC-Address'],dtype=str).to_dict(orient='records')
logger.info('Printing MAC ID that will be monitored %s',MACIDsdict)

def checkWhetherIDIsListed(ID):
    for dict_ in MACIDsdict:
        if dict_['MAC-Address'] == ID:
            return dict_.get('Name','No Name')
    return False
