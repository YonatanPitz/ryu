#!/bin/env python
import sys
import requests
import json
import time
import argparse
import socket

rest_url='http://localhost:8080/'

def add_delay_to_timestamp(timestamp, delay):
    return (timestamp + delay * 90000) % 0x100000000


def add_rtp_entry(dpid, begin_time, end_time, meta_action):
    data = {
        "dpid": dpid,
        "table_id": 252,
        "match":{
            "rtp_timestamp": "{}/{}".format(begin_time, end_time)
        },
        "actions":[
        {
            "type": "WRITE_METADATA",
            "metadata": meta_action,
            "metadata_mask": meta_action
        }
        ]
    }
    return requests.post(rest_url+'stats/flowentry/add', data=json.dumps(data))

def del_rtp_entry(dpid, begin_time, end_time):
    data = {
        "dpid": dpid,
        "table_id": 252,
        "match":{
            "rtp_timestamp": "{}/{}".format(begin_time, end_time)
        }
    }
    return requests.post(rest_url+'stats/flowentry/delete', data=json.dumps(data))

def add_fwd_entry(dpid, flow, meta, priority):
    match = flow["match"].copy()
    if meta != 0:
        match["metadata"] = "{}/{}".format(meta, 4095)
    data = {
        "dpid":     dpid,
        "table_id": 0,
        "priority": priority,
        "match":    match,
        "actions":  flow["actions"] 
    }
    data["match"] = match
    return requests.post(rest_url+'stats/flowentry/add', data=json.dumps(data))

def del_fwd_entry(dpid, flow, meta):
    match = flow["match"].copy()
    if meta != 0:
        match["metadata"] = "{}/{}".format(meta, 4095)
    data = {
        "dpid": dpid,
        "table_id": 0,
        "match": match
    }
    return requests.post(rest_url+'stats/flowentry/delete', data=json.dumps(data))

def get_flow_stats(dpid, flow, meta):
    match = flow["match"].copy()
    if meta != 0:
        match["metadata"] = "{}/{}".format(meta, 4095)
    data = {
        "table_id": 0,
        "match":    match,
    }
    r = requests.post(rest_url+'stats/flow/{}'.format(dpid), data=json.dumps(data))
    res = json.loads(r.text)[str(dpid)][0]
    return (res['packet_count'], res['byte_count'])

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Sets Shared Headroom configurations.')
    parser.add_argument('timestamp', metavar='TS', type=int,
                        help='RTP Timestamp to perform clean switching')
    parser.add_argument('--delay', metavar='DELAY', type=int, default=0,
                        help='Delay after given timestamp to perform switching')
    parser.add_argument('--file', metavar='FILE', type=str, default=None,
                        help='Path to configuartion file')
    parser.add_argument('--set_default', dest='default', action='store_const',
                        const=True, default=False,
                        help='Sets default rule to old port as given by config file')
    args = parser.parse_args()

    if args.file is not None:
        with open(args.file) as f:
            config = json.load(f)
    else:
        print("Configuration file path was not given")
        sys.exit()

    old_flow = config.get('before_switch')
    new_flow = config.get('after_switch')
    meta = 1

    begin_time = add_delay_to_timestamp(args.timestamp, args.delay)
    print(begin_time)
    begin_time = socket.htonl(begin_time)
    end_time = 0xffffffff

    r = requests.get(rest_url+'stats/switches')
    dpid = int(r.text[1:-1])

    if args.default:
        del_fwd_entry(dpid, new_flow, 0)
        del_fwd_entry(dpid, new_flow, meta)
        del_fwd_entry(dpid, old_flow, 0)
        del_fwd_entry(dpid, old_flow, meta)
        del_rtp_entry(dpid, begin_time, end_time)
        add_fwd_entry(dpid, old_flow, 0, 10)
        sys.exit()

    add_fwd_entry(dpid, new_flow, meta, 20)
    add_rtp_entry(dpid, begin_time, end_time, meta)
    pkt = 0
    while pkt == 0:
        pkt, byte = get_flow_stats(dpid, new_flow, meta)
        # print('{} packets. {} bytes'.format(pkt, byte))
        # time.sleep(1)
    time.sleep(1)
    print('Packets recieved. Switching default flow')

    del_fwd_entry(dpid, old_flow, 0)
    add_fwd_entry(dpid, new_flow, 0, 10)
    del_rtp_entry(dpid, begin_time, end_time)
    del_fwd_entry(dpid, new_flow, meta)

