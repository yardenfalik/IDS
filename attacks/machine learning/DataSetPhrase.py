import utils

NUMBER_OF_DATASETS = 6

def Phrase():
    phrasedFileName = "data.txt"
    dataSetNames = ["dhcpStarvetion.pcapng", "dhcpSpoofing.pcapng", "portScan.pcapng", "tcpSynFlood.pcapng", "HTTPFlood.pcapng", "HTTPFloodStart.pcapng"]

    dict = []

    for dataSetName in dataSetNames:
        dict.append(utils.phraseDataset(dataSetName))

    f = open(phrasedFileName, "w")
    f.write(str(dict))
    f.close()
    
    return phrasedFileName