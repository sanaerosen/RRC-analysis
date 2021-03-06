#!/usr/bin/python
import math

def mergeDict(new_attributes, attribute_dict, event, are_lists=False):
    for k, v in new_attributes.iteritems():
        if k not in attribute_dict[event]:
            attribute_dict[event][k] = []
        try:
            v = int(v)
        except:
            pass
        if not are_lists:
	        attribute_dict[event][k].append(v)
	else:
		attribute_dict[event][k].extend(v)

def meanValue(li):
    """author: Haokun """
    li = [x for x in li if x != None]
    if not li or len(li) == 0:
        return 0.0
    return sum(li)*1.0/len(li)

def listMeanValue(li):
    """author: Haokun """
    if not li:
        return 0.0
    return meanValue([meanValue(item) for item in li])

# Get the statistical distribution info
# @return 
#   [5%, 25%, 50%, 75%, 95%]
def quartileResult(li):
    """author: Haokun """
    li = [x for x in li if x != None]
    if not li:
        return [0]*5
    listLen = len(li)
    sorted_list = sorted(li)
    return [sorted_list[int(0.05*listLen)], sorted_list[int(0.25*listLen)], sorted_list[int(0.5*listLen)], \
            sorted_list[int(0.75*listLen)], sorted_list[int(0.95*listLen)]]

# calculate the standard deviation of the list
def stdevValue(li, mean = None):
    """author: Haokun """
    li = [x for x in li if x != None]
    if not li:
        return 0.0

    if not mean:
        mean = meanValue(li)

    diff_sum = 0.0
    for i in li:
        diff_sum += (i-mean)*(i-mean)
    return math.sqrt(diff_sum / len(li))

# Get both mean and standard dev
def meanStdevPair(li, upper_bound = None):
    """author: Haokun """
    li = [i for i in li if i != 0.0 and (not upper_bound or (upper_bound and i < upper_bound))]
    mean = meanValue(li)
    return (mean, stdevValue(li, mean))

# convert list to string with delimiters
def listToStr(li, DEL = "\t"):
    """author: Haokun """
    return DEL.join(str(li)[1:-1].split(", "))

