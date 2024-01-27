# Shidhi Mohammad Bin Arif
# V00911512

import sys
import headers

PROTOCOL_MAP = {1: 'ICMP', 17: 'UDP'}

def parseCommandLine():
    """
    Parses command line arguments and returns the input file name.
    """
    if len(sys.argv) != 2:
        print('Incorrect usage. Please use the following formats:')
        print('  python3 p3Final.py <sample_trace_file.cap>')
        sys.exit(1)

    return sys.argv[1]

def readGlobalHeader(file):
    """
    Reads the global header from the file and returns it.
    """
    return headers.GlobalHeader(file.read(24))

def processPackets(file):
    """
    Processes packet data from the file.
    """
    protocolUsed = {}
    sourcePacket = []
    destinationPacket = []
    pcapStartTime = None
    packetCounter = 0
    identityMap = {}

    while True:
        packetCounter += 1

        inputStream = file.read(16)

        if inputStream == b'':
            break

        packet = headers.Packet()
        packet.set_header(inputStream)
        packet.set_number(packetCounter)

        incl_len = packet.header.incl_len

        if pcapStartTime is None:
            seconds = packet.header.ts_sec
            microseconds = packet.header.ts_usec
            pcapStartTime = round(seconds + microseconds * 0.000001, 6)
        
        packet.set_data(file.read(incl_len))

        packet.set_ipv4()
        if packet.ipv4.protocol == 1:
            packet.set_icmp()
            destinationPacket.append(packet)
            protocolUsed[1] = 'ICMP'
        elif packet.ipv4.protocol == 17:
            packet.set_udp()
            sourcePacket.append(packet)
            if not 33434 <= packet.udp.dst_port <= 33529:
                continue
            protocolUsed[17] = 'UDP'  
        if packet.ipv4.protocol not in PROTOCOL_MAP:
            continue
    
    #For Windows
    if any(p.icmp.type_num == 8 for p in destinationPacket):

        icmp_all = destinationPacket
        sourcePacket = []
        destinationPacket = []
        
        for p in icmp_all:
            if p.icmp.type_num == 8:
                sourcePacket.append(p)
            if p.icmp.type_num == 11 or p.icmp.type_num == 0:
                destinationPacket.append(p)

        intermediate = []
        intermediatePackets = []
        rttMap = {}
        srcIndex = 0
        while srcIndex < len(sourcePacket):
            p1 = sourcePacket[srcIndex]
            dstIndex = 0

            while dstIndex < len(destinationPacket):
                p2 = destinationPacket[dstIndex]

                if p1.icmp.sequence == p2.icmp.sequence:
                    if p2.ipv4.src_ip not in intermediate:
                        intermediate.append(p2.ipv4.src_ip)
                        intermediatePackets.append(p2)
                        rttMap[p2.ipv4.src_ip] = []

                    p1.set_timestamp(pcapStartTime)
                    p2.set_timestamp(pcapStartTime)
                    rtt = p2.timestamp - p1.timestamp
                    rttMap[p2.ipv4.src_ip].append(rtt)
                dstIndex += 1
            srcIndex += 1


    #For Linux
    else:
        intermediate = []
        intermediatePackets = []
        rttMap = {}
        srcIndex = 0
        while srcIndex < len(sourcePacket):
            dstIndex = 0
            while dstIndex < len(destinationPacket):
                p1 = sourcePacket[srcIndex]
                p2 = destinationPacket[dstIndex]

                if p1.udp.src_port == p2.icmp.src_port:
                    if p2.ipv4.src_ip not in intermediate:
                        intermediate.append(p2.ipv4.src_ip)
                        intermediatePackets.append(p2)
                        rttMap[p2.ipv4.src_ip] = []

                    p1.set_timestamp(pcapStartTime)
                    p2.set_timestamp(pcapStartTime)
                    rttMap[p2.ipv4.src_ip].append(p2.timestamp - p1.timestamp)
                dstIndex += 1
            srcIndex += 1

    for packet in sourcePacket:
        if packet.ipv4.identification not in identityMap:
            identityMap[packet.ipv4.identification] = []

        identityMap[packet.ipv4.identification].append(packet)
    
    fragCounter = sum(len(packets) > 1 for packets in identityMap.values())

    return protocolUsed, sourcePacket, intermediate, rttMap, identityMap, fragCounter


def formatOutput(protocolUsed, sourcePacket, intermediate, rttMap, identityMap, fragCounter):
    """
    Formats and prints the output based on processed data.
    """
    printSrcDstAddresses(sourcePacket)
    printIntermediateAddresses(intermediate)
    printProtocolValues(protocolUsed)
    printFragmentationDetails(identityMap, fragCounter)
    printRttStatistics(sourcePacket, intermediate, rttMap)

def printSrcDstAddresses(sourcePacket):
    if sourcePacket:
        print('The IP address of the source node:', sourcePacket[0].ipv4.src_ip)
        print('The IP address of ultimate destination node:', sourcePacket[0].ipv4.dst_ip)
    else:
        print('No source packets found.')

def printIntermediateAddresses(intermediate):
    print('The IP addresses of the intermediate destination nodes:')
    for i, routerIP in enumerate(intermediate[:-1]):
        print(f'\trouter {i+1}: {routerIP}')

def printProtocolValues(protocolUsed):
    print('\nThe values in the protocol field of IP headers:')
    for protocol in sorted(protocolUsed):
        print(f'\t{protocol}: {protocolUsed[protocol]}')
    print()
    print()

def printFragmentationDetails(identityMap, fragCounter):
    if fragCounter == 0:
        print('The number of fragments created from the original datagram is:', fragCounter)
        print('The offset of the last fragment is:', fragCounter, '\n')
    else:
        for identity, packets in identityMap.items():
            if len(packets) > 1:
                print(f'The number of fragments created from the original datagram {identity} is:', len(packets))
                offset = max(packet.ipv4.fragment_offset for packet in packets)
                print('The offset of the last fragment is:', offset, '\n')

def printRttStatistics(sourcePacket, intermediate, rttMap):
    if sourcePacket:
        sourceIP = sourcePacket[0].ipv4.src_ip
        for routerIP in intermediate:
            if routerIP in rttMap:
                averageRTT = round(sum(rttMap[routerIP]) / len(rttMap[routerIP]), 6)
                stanadardDeviationRTT = round((sum((x - averageRTT)**2 for x in rttMap[routerIP]) / len(rttMap[routerIP]))**0.5, 6)
                print(f'The avg RTT between {sourceIP} and {routerIP} is: {averageRTT} ms, the s.d. is: {stanadardDeviationRTT} ms')

def main():
    file = parseCommandLine()

    with open(file, 'rb') as f:
        readGlobalHeader(f)
        protocolUsed, sourcePacket, intermediate, rttMap, identityMap, fragCounter = processPackets(f)
        formatOutput(protocolUsed, sourcePacket, intermediate, rttMap, identityMap, fragCounter)
    
if __name__ == "__main__":
    main()