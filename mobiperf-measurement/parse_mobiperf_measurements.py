#/usr/bin/python

import json, glob, re, numpy

"""
Processes the data in gs://openmobiledata_public, in the Measurement database.
Extracts data relevant to rrc measurements and the effects of RRC state on 
DNS, TCP and HTTP lookups.  HTTP data is not entirely supported at this point.

To use:
    1. Put this script in the folder you are working in.
    2. Create a folder "data".
    3. Get the data from gs://openmobiledata_public, unzip it and put it in 
    the data folder.  Delete all zip files.
    4. Run.
    5. Go to the folder "graphs" and run gnuplot on all .p files.
    6. Your plots are all in that folder now.

TODO:
    Support varying the time parameters
    Support graphing by network technology (need to change the format of data
        provided by mobiperf serer)
    Graph the signal strength dependence of results
"""

##############################################################################
#                         CONFIG/UTILS                                       #
##############################################################################
TIMES = [0, 2, 4, 8, 12, 16, 22]
NUM_MEASUREMENTS = len(TIMES)
GAP = 2

def fix_filename(filename):
    """Given a string, replace all special characters by '_' and return it.
    
    Used for producing filenames that don't have difficult characters in them.

    """

    pattern = re.compile("[^\w]")
    return pattern.sub("_", filename)

def quartiles(l):
    """Given a list of numbers, return the first and third quartile.
    
    When not divisible by 4, returns the weighted average of the nearest 
    values. See https://en.wikipedia.org/wiki/Quartile#Method_3.

    Args:
        l: a list of numbers with 1 or more entries, which may be unsorted.

    Returns:
        A tuple (first quartile, third quartile).
    """

    l.sort()

    # deal with this case individually to avoid indexing errors
    if len(l) == 1:
        return (l[0], l[0])

    # If even, median will take care of it
    if len(l)%2 == 0:
        return (numpy.median(l[:len(l)/2]), numpy.median(l[len(l)/2:]))

    # For other cases, we weight values by 
    elif len(l)%4 == 1:
        start = len(l)/4
        smallval = (l[start-1]*0.25 + l[start] * 0.75)
        largeval = (l[start*3]*0.75 + l[start*3 + 1] * 0.25)
        return(smallval, largeval)
    else:
        start = len(l)/4
        smallval = (l[start]*0.75 + l[start+1] * 0.25)
        largeval = (l[start*3+1]*0.25 + l[start*3 + 2] * 0.75)
        return (smallval, largeval)

def test_quartile():
    """Used to make sure I got the quartile math right"""
    l = [1,2,3,4,5]
    print quartiles(l)
    l = [1,2,3,4,5,6]
    print quartiles(l)
    l = [1,2,3,4,5,6,7]
    print quartiles(l)
    l = [1,2,3,4,5,6,7,8]
    print quartiles(l)


def list_to_boxplot(l):
    """ Given a list of numbers convert to values suitable for a boxplot.
    
    Intended for use in generating data files for gnuplot.

    Args:
        l: a list of numbers with 1 or more entries, which may be unsorted.

    Returns:
        A string with the values: min, 1st quartile, median, 3rd quartile, max
        where each value is separated by a space.
    """
    minval = min(l)
    maxval = max(l)
    median = numpy.median(l)
    (quartile1, quartile3) = quartiles(l)
    return str(minval) + " " + str(quartile1) + " " + str(median) + " " \
            + str(quartile3) + " " + str(maxval)

##############################################################################
#                   Storing/parsing measurement data                         #
##############################################################################

class MeasurementData:
    """Extract the relevant items from the measurement data for analyzing the
    rrc test."""

    class DeviceProperties:
        """ Extracts the relevant information from the device_properties entry.

        Flattens nested items so that hte complete list of items is:
        os_version, rssi, carrier, model, manufacturer, latitude, longitude

        Also keeps track of the set of distinct carriers, manufacturerers and 
        models. In addition to being useful for its own sake, these values are
        used to assist in generating plots later.
        """
        distinct_carriers = set()
        distinct_manufacturers = set()
        distinct_models = set()
        distinct_models_by_carrier = {}

        def __init__(self, properties):

            device_info = properties["device_info"]
            location = properties["location"]

            self.os_version = properties["os_version"]
            self.rssi = properties["rssi"]
            self.carrier = properties["carrier"]
            self.model = device_info["model"]
            self.manufacturer = device_info["manufacturer"]
            self.latitude = location["latitude"]
            self.longitude = location["longitude"]

            self.distinct_carriers.add(self.carrier)
            self.distinct_manufacturers.add(self.manufacturer)
            self.distinct_models.add(self.model)

            if self.carrier not in self.distinct_models_by_carrier:
                self.distinct_models_by_carrier[self.carrier] = set()
            self.distinct_models_by_carrier[self.carrier].add(self.model)

        def print_stats(self):
            """Print statistics on all measurements: distinct carriers, models
            and manufacturers.
            
            Must process all measurements first."""

            print "Distinct carriers (count:", len(self.distinct_carriers), ")"
            for i in self.distinct_carriers:
                print "\t", i
            print "Distinct manufacturers (count:", len(self.distinct_manufacturers), ")"
            for i in self.distinct_manufacturers:
                print "\t", i
            print "Distinct models (count:", len(self.distinct_models), ")"
            for i in self.distinct_models:
                print "\t", i

    class Values:
        """ Stores the results of the rrc measurement tests.
        
        http_data, tcp_data and dns_data store the data in a list.
        Values are in milliseconds.  The inter-packet interval corresponding
        to the test is in self.times."""

        def __init__(self, data):
            self.http_data = self.parse_list(data["http"])
            self.tcp_data = self.parse_list(data["tcp"])
            self.dns_data = self.parse_list(data["dns"])
            self.times = self.parse_list(data["times"])

        def parse_list(self, line):
            """Convert a string representation of a list to the associated list.
            
            Args:
                line: A string formatted as '[1,2,3]' 

            Returns:
                The associated list, e.g. [1, 2, 3]
            """
            
            line = line[1:-1].split(",")
            return [int(x) for x in line]

    def __init__(self, data):

        self.task = data["task"]    
        self.timestamp = data["timestamp"]
        self.device_properties = self.DeviceProperties(data["device_properties"])
        self.values = self.Values(data["values"])
        print self.device_properties.carrier


##############################################################################
#                   Generating graphs                                        #
##############################################################################

def generate_gnuplot_datafile(data_to_graph, label, datatype):
    """ Given a set of measurement data, output as a gnuplottable data file.

    Note that measurement data is stored in a list, where the index of each 
    data point corresponds to an index in the timing test array.  All 
    measurement data is formatted like this.

    Produces a file in 'graphs/[label]_[datatype]_measurement.dat'

    Args:
        data_to_graph: A list of lists.  The outer list indices correspond to
            a timing index. The inner list can be of any length >0 and has
            a list of values to convert to a boxplot.

        label: A string to make up the first part of the file name. Will be
            escaped automatically. Generally of the form 'Carriername' or
            'Carriername_modeltype'. Needs to be consistent with what is 
            passed to the gnuplot scripts.
            
        data_type: A string labelling the measurement type.


    """
    label = fix_filename(label)
    f = open("graphs/" + label + "_" + datatype + "_measurement.dat", "w")
    for i in range(NUM_MEASUREMENTS):
        print >>f, TIMES[i], list_to_boxplot(data_to_graph[i])
    f.close()

def generate_gnuplot_script(data_to_graph, label, datatype, carrier = None):
    """Produces a gnuplot script to produce a boxplot from datafiles in 
    generate_gnuplot_datafile.

    TODO: move the labels so it's more like a histogram which is what it is

    Produces a plot in "./graphs/[datatype]_[label]_measurement.png", although
    the generated script still needs to be run externally.

    It plots elements from "./graphs/[item]_[label]_measurement.dat" or
    "./graphs/[carrier]_[item]_[label]_measurement.dat", where item is each
    item in data_to_graph.

    The size of each box is adjusted individually.

    Args:
        data_to_graph: A list of suffixes of filenames to graph (or something
            that can be converted to a list).  Each filename will be plotted
            individually. Boxes for the boxplots in each set of graphs will
            be offset from one another for easy comparison.

        label: A string to make up the first part of the file name. Will be
            escaped automatically. Generally of the form 'Carriername' or
            'Carriername_modeltype'. Needs to be consistent with what is 
            used to name measurement files.

        datatype: A string labelling the measurement type.

        carrier: If we are dividing the data up by carrier, need to put the 
            carrier name here.

    """

    label = fix_filename(label)
    datatype = fix_filename(datatype)
    f = open("graphs/" + datatype + "_" + label  + "_measurement.p","w")
    print >>f, "set term png"
    print >>f, "set output \"" + datatype + "_" + label + "_measurement.png\""
    print >>f, "set xrange[0:" + str(max(TIMES) + GAP) + "]"

    # calculate size of each boxplot
    boxwidth = (GAP * 0.75)/len(data_to_graph)
    print >>f, "set boxwidth", boxwidth
    print >>f, "set key top left"
    print >>f, "set ylabel \"Time to complete (ms)\""
    print >>f, "set xlabel \"Inter-packet time (ms)\""
    names = list(data_to_graph)
    for i in range(len(names)):

        # for the first element you type "plot", rest are comma-separated
        if i == 0:
            print >>f, "plot ",
        else:
            print >>f, ", ",

        if carrier != None:
            name = fix_filename(carrier + "_" +names[i])
        else:
            name = fix_filename(names[i])

        # Note lack of newline
        print >>f, "\"./" + name + "_" + datatype + "_measurement.dat\" using " +\
                "($1 + " + str(boxwidth*i) + \
                "):3:2:6:5 with candlesticks t \"" + name + \
                "\" whiskerbars, \"\" using ($1 + " + str(boxwidth*i) + \
                "):4:4:4:4 with candlesticks lt -1 notitle",
    print >>f

    f.close()

def make_graphs(datalist):
    """Produce the graphs of performance for different carriers and devices.
    
    Does not do RRC inference data.

    Args:
        datalist: list of MeasurementData objects to process.
    """

    carriers = datalist[0].device_properties.distinct_carriers
    d_carriers_tcp = {}
    d_carriers_dns= {}
    d_carriers_http = {}
    for i in carriers:
        d_carriers_tcp[i] = [[] for j in range(NUM_MEASUREMENTS)]
        d_carriers_dns[i] = [[] for j in range(NUM_MEASUREMENTS)]
        d_carriers_http[i] = [[] for j in range(NUM_MEASUREMENTS)]

    models = datalist[0].device_properties.distinct_models_by_carrier
    d_models_tcp = {}
    d_models_dns= {}
    d_models_http = {}
    for carrier in models.keys():
        d_models_tcp[carrier] = {}
        d_models_dns[carrier] = {}
        d_models_http[carrier] = {}
        for model in models[carrier]:
            d_models_tcp[carrier][model] = [[] for k in range(NUM_MEASUREMENTS)]
            d_models_dns[carrier][model] = [[] for k in range(NUM_MEASUREMENTS)]
            d_models_http[carrier][model] = [[] for k in range(NUM_MEASUREMENTS)]

    # create gnuplot scripts
    # First, scripts for carriers
    generate_gnuplot_script(carriers, "carrier", "http")
    generate_gnuplot_script(carriers, "carrier", "dns")
    generate_gnuplot_script(carriers, "carrier", "tcp")
    # Next, scripts for each carrier/model combo
    for carrier in models.keys():
        generate_gnuplot_script(models[carrier], "model_" + carrier, "tcp", carrier)
        generate_gnuplot_script(models[carrier], "model_" + carrier, "dns", carrier)
        generate_gnuplot_script(models[carrier], "model_" + carrier, "http", carrier)

    # copy entries from the data list into dicts to print
    for entry in datalist:
        carrier = entry.device_properties.carrier
        model = entry.device_properties.model
        for i in range(NUM_MEASUREMENTS):
            if entry.values.tcp_data[i] != 0:
                d_carriers_tcp[carrier][i].append(entry.values.tcp_data[i])
                d_models_tcp[carrier][model][i].append(entry.values.tcp_data[i])
            if entry.values.dns_data[i] != 0:
                d_carriers_dns[carrier][i].append(entry.values.dns_data[i])
                d_models_dns[carrier][model][i].append(entry.values.dns_data[i])
            if entry.values.tcp_data[i] != 0:
                d_carriers_http[carrier][i].append(entry.values.http_data[i])
                d_models_http[carrier][model][i].append(entry.values.http_data[i])

    for k, v in d_carriers_tcp.iteritems():
        generate_gnuplot_datafile(v, k, "tcp")
    for k, v in d_carriers_dns.iteritems():
        generate_gnuplot_datafile(v, k, "dns")
    for k, v in d_carriers_http.iteritems():
        generate_gnuplot_datafile(v, k, "http")

    for carrier in datalist[0].device_properties.distinct_carriers:
        for k, v in d_models_tcp[carrier].iteritems():
            generate_gnuplot_datafile(v, carrier + "_" + k, "tcp")
        for k, v in d_models_dns[carrier].iteritems():
            generate_gnuplot_datafile(v, carrier + "_" + k, "dns")
        for k, v in d_models_http[carrier].iteritems():
            generate_gnuplot_datafile(v, carrier + "_" + k, "http")


##############################################################################
#                   Main code                                                #
##############################################################################

def parse_measurement(folder, datalist):
    """Given a folder of data, parse the measurement file in the folder.
    
    The Measurement class does the bulk of the work here.
    
    Args:
        folder: The name of the data folder to open.  Should be those 
        downloaded and unzipped with gsutil.

        datalist: List to store the results, as MeasurementData items.
    """

    f = open(folder + "/Measurement")
    data = json.load(f)

    for item in data:
        if item["type"] != "rrc":
            continue 
        if item["success"] != True:
            continue 

        datalist.append(MeasurementData(item))



datalist = []
directories = glob.glob("data/S-*")
for d in directories:
    parse_measurement(d, datalist)

datalist[0].device_properties.print_stats()

make_graphs(datalist)
