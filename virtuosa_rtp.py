#!/bin/env python
import sys
import requests
import json
import time
import argparse
import os
import socket
from datetime import datetime, timedelta

rest_url='http://localhost:8080/'

def add_delay_to_timestamp(timestamp, delay):
    return int(timestamp + delay * 90000) % 0x100000000

def get_timestamp_with_delay(delay):
    time_us = int((time.time()+ delay)*1e6)
    return (time_us * 9 /100) % 0x100000000


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

def add_fwd_entry(dpid, flow, meta, actions=None):
    for existing_flow in flow["existing_flows"]:
        priority = existing_flow.get("priority", 0)
        match = existing_flow["match"].copy()
        if meta != 0:
            match["metadata"] = "{}/{}".format(meta, 4095)
            priority += 1
        if actions is None:
            actions = flow["new_actions"]
        data = {
            "dpid":     dpid,
            "table_id": 0,
            "priority": priority,
            "match":    match,
            "actions":  actions
        }
        print(data)
        requests.post(rest_url+'stats/flowentry/add', data=json.dumps(data))

def del_fwd_entry(dpid, flow, meta):
    for existing_flow in flow["existing_flows"]:
        match = existing_flow["match"].copy()
        if meta != 0:
            match["metadata"] = "{}/{}".format(meta, 4095)
        data = {
            "dpid": dpid,
            "table_id": 0,
            "match": match
        }
        print(data)
        requests.post(rest_url+'stats/flowentry/delete', data=json.dumps(data))

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

def get_flows(dpid, flow, meta):
    match = flow["match"].copy()
    if meta != 0:
        match["metadata"] = "{}/{}".format(meta, 4095)
    data = {
        "table_id": 0,
        "match":    match,
    }
    r = requests.post(rest_url+'stats/flow/{}'.format(dpid), data=json.dumps(data))
    return json.loads(r.text)[str(dpid)]

def get_groups(dpid, group_id=None):
    group_id_txt = '' if group_id is None else '/{}'.format(group_id)
    r = requests.get(rest_url+'stats/group/{}{}'.format(dpid, group_id_txt))
    return json.loads(r.text)[str(dpid)]

def add_group(dpid, group):
    data = group.copy()
    data["dpid"] = dpid
    r = requests.post(rest_url+'stats/groupentry/add', data=json.dumps(data))

def del_group(dpid, group):
    print(group)
    data = group.copy()
    data["dpid"] = dpid
    r = requests.post(rest_url+'stats/groupentry/delete', data=json.dumps(data))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Sets Shared Headroom configurations.')
    parser.add_argument('--timestamp', metavar='TS', type=int, default=None,
                        help='RTP Timestamp to perform clean switching')
    parser.add_argument('--delay', metavar='DELAY', type=float, default=0,
                        help='Delay after given timestamp to perform switching')
    parser.add_argument('--file', metavar='FILE', type=str, default=None,
                        help='Path to configuartion file')
    # parser.add_argument('--set_default', dest='default', action='store_const',
    #                     const=True, default=False,
    #                     help='Sets default rule to old port as given by config file')
    args = parser.parse_args()

    if args.file is not None:
        with open(os.path.join(args.file)) as f:
            config = json.load(f)
    else:
        print("Configuration file path was not given")
        sys.exit()

    if args.timestamp is not None:
       begin_time = add_delay_to_timestamp(args.timestamp, args.delay)
    else:
       begin_time = get_timestamp_with_delay(args.delay)
       print((datetime.now() + timedelta(seconds=args.delay)).strftime("%H:%M:%S"))
    print(begin_time)
    begin_time = socket.htonl(begin_time)
    end_time = 0xffffffff

    r = requests.get(rest_url+'stats/switches')
    dpid = int(r.text[1:-1])
    print (dpid)

    for group in config.get('groups'):
        if len(get_groups(dpid, group['group_id'])) != 0:
            print("Group exists. Doesn't override")
        else:
            add_group(dpid, group)
    meta = 1

    flows = config.get('flows')
    for flow in flows:
        flow["existing_flows"] = get_flows(dpid, flow, 0)
        # Yonatanp new - If doesn't have flows currently, create a new one
        if not flow["existing_flows"]:
            flow["existing_flows"].append({})
            flow["existing_flows"][0]["match"] = flow["match"].copy()
            add_fwd_entry(dpid, flow, 0, actions=flow["old_actions"])
        add_fwd_entry(dpid, flow, meta)
    add_rtp_entry(dpid, begin_time, end_time, meta)
    # print(flows)

    time.sleep(args.delay)
    print("cleanup")

    for flow in flows:
       del_fwd_entry(dpid, flow, 0)
       add_fwd_entry(dpid, flow, 0)

    del_rtp_entry(dpid, begin_time, end_time)

    for flow in flows:
        del_fwd_entry(dpid, flow, meta)
