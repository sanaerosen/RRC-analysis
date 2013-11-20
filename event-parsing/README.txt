Full documentation to come later...

./process_any.py eventfile.txt packetfile.txt

The event file is the file where you filter out only the events and
dump it to text.  The packet file is the pcap file converted to text
with tshark, and is optional.

The code is pretty messy right now and you may want to adjust what is
outputted, but it will generate statistics for you on what events
occur, when, and how often, based on where you are in the RRC state
machine, as well as (implicitly) detect the RRC state machine and its
intervals itself.

It should work for any phone and any network technology, but that's not 
guaranteed.


